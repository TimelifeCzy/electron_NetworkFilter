/*
	@ Wfp - User: Base Filter Engine
*/

#include "WfpBaseBefAssist.h"
#include "WinSock2.h"

#include <stdlib.h>
#include "conio.h"
#include "winioctl.h"
#include "../inc/ioctl.h"
#include "../inc/LoopBuffer.h"

#include <ip2string.h>

#define INITGUID
#include <guiddef.h>
#include "mntrguid.h"

#define MONITOR_FLOW_ESTABLISHED_CALLOUT_DESCRIPTION L"Monitor Sample - Flow Established Callout"
#define MONITOR_FLOW_ESTABLISHED_CALLOUT_NAME L"Flow Established Callout"

#define MONITOR_STREAM_CALLOUT_DESCRIPTION L"Monitor Sample - Stream Callout"
#define MONITOR_STREAM_CALLOUT_NAME L"Stream Callout"

#define MONITOR_DataGram_CALLOUT_DESCRIPTION L"Monitor Sample - DataGram Callout"
#define MONITOR_DataGram_CALLOUT_NAME L"DataGram Callout"

#define	MONITOR_IOCTL_ENABLE_MONITOR  CTL_CODE(FILE_DEVICE_NETWORK, 0x1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	MONITOR_IOCTL_DISABLE_MONITOR CTL_CODE(FILE_DEVICE_NETWORK, 0x2, METHOD_BUFFERED, FILE_ANY_ACCESS)


/// ArgControl
enum WFPSAMPLER_FLOW_CONTROL_
{
	FLOW_CONTROL_NORMAL = 0,
	FLOW_CONTROL_HELP = 1,
	FLOW_CONTROL_CLEAN = 2,
};

typedef enum DD_PROXY_FLOW_TYPE_
{
	DD_PROXY_FLOW_ORIGINAL,
	DD_PROXY_FLOW_PROXY
} DD_PROXY_FLOW_TYPE;

DWORD
WfpMonitorAppAddFilters(
	_In_    HANDLE*         engineHandle,
	_In_    FWP_BYTE_BLOB* applicationPath,
	_In_	const UINT8* remoteAddr,
	_In_	USHORT remotePort,
	_In_	const UINT8* NewAddr,
	_In_	USHORT NewPort
	)
{
	/*
		proxy:

	*/


	if (!remoteAddr && !remotePort && !NewAddr && !NewPort) {
		printf("remoteaddr and remotePort false, Please chekcout values\n");
		return -1;
	}


	DWORD result = NO_ERROR;
	FWPM_SUBLAYER TcpSubLayer, UdpSubLayer;
	FWPM_FILTER Tcpfilter, Udpfilter;
	FWPM_FILTER_CONDITION TcpSublayerfilterConditions[3] = { 0, }, UdpSublayerfilterConditions[3] = { 0, }; // We only need two for this call.

	/*
		TCP Monitrol SubLayer
	*/
	RtlZeroMemory(&TcpSubLayer, sizeof(FWPM_SUBLAYER));
	TcpSubLayer.subLayerKey = MONITOR_SAMPLE_SUBLAYER;
	TcpSubLayer.displayData.name = L"Tcp SubLayer";
	TcpSubLayer.displayData.description = L"Tcp Stream and Proxy";
	TcpSubLayer.flags = 0;
	TcpSubLayer.weight = FWP_EMPTY;

	/*
		UDP Monitorl SubLayer
	*/
	RtlSecureZeroMemory(&UdpSubLayer, sizeof(FWPM_SUBLAYER));
	UdpSubLayer.subLayerKey = MONITOR_SAMPLE_UDP_SUBLAYER;
	UdpSubLayer.displayData.name = L"Udp SubLayer";
	UdpSubLayer.displayData.description = L"Udp Stream and Proxy";
	UdpSubLayer.flags = 0;
	UdpSubLayer.weight = FWP_EMPTY;

	printf("Starting Transaction\n");

	do
	{
		printf("HlprFwpmSubLayerAdd engineHandle = 0x%p\n", *engineHandle);
		result = HlprFwpmSubLayerAdd(engineHandle, &TcpSubLayer);
		if (NO_ERROR != result)
			break;

		result = HlprFwpmSubLayerAdd(engineHandle, &UdpSubLayer);
		if (NO_ERROR != result)
			break;

		/*
			TCP add callout & add Filter
			Tcp Established:
				FWPM_CONDITION_IP_PROTOCOL
		*/
		RtlZeroMemory(TcpSublayerfilterConditions, sizeof(TcpSublayerfilterConditions));
		TcpSublayerfilterConditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		TcpSublayerfilterConditions[0].matchType = FWP_MATCH_EQUAL;	// 是否等于条件值
		TcpSublayerfilterConditions[0].conditionValue.type = FWP_UINT8;
		TcpSublayerfilterConditions[0].conditionValue.uint8 = IPPROTO_TCP;	// TCP

		/*
				Add Filter Established
		*/
		RtlZeroMemory(&Tcpfilter, sizeof(FWPM_FILTER));
		Tcpfilter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
		Tcpfilter.displayData.name = L"Flow established filter.";
		Tcpfilter.displayData.description = L"Sets up flow for traffic that we are interested in.";
		Tcpfilter.action.type = FWP_ACTION_CALLOUT_TERMINATING; // FWP_ACTION_CALLOUT_INSPECTION
		Tcpfilter.action.calloutKey = TCP_FLOW_ESTABLISHED_CALLOUT_V4;
		Tcpfilter.filterCondition = TcpSublayerfilterConditions;
		Tcpfilter.subLayerKey = MONITOR_SAMPLE_SUBLAYER;
		Tcpfilter.weight.type = FWP_EMPTY; // auto-weight.
		Tcpfilter.numFilterConditions = 1;

		printf("HlprFwpmFilterAdd engineHandle = 0x%p\n", *engineHandle);
		result = HlprFwpmFilterAdd(engineHandle, &Tcpfilter);
		if (NO_ERROR != result)
			break;

		/*
				Add Filter TCP Stream
		*/
		RtlZeroMemory(&Tcpfilter, sizeof(FWPM_FILTER));
		Tcpfilter.layerKey = FWPM_LAYER_STREAM_V4;
		Tcpfilter.action.type = FWP_ACTION_CALLOUT_INSPECTION; // We're only doing inspection.
		Tcpfilter.action.calloutKey = TCP_STREAM_CALLOUT_V4;
		Tcpfilter.subLayerKey = MONITOR_SAMPLE_SUBLAYER;
		Tcpfilter.weight.type = FWP_EMPTY; // auto-weight.
		Tcpfilter.numFilterConditions = 0;
		Tcpfilter.filterCondition = NULL;
		Tcpfilter.displayData.name = L"Stream Layer Filter.";
		Tcpfilter.displayData.description = L"Monitors TCP traffic.";
		result = HlprFwpmFilterAdd(engineHandle, &Tcpfilter);
		if (NO_ERROR != result)
			break;

		/*
			Udp Established: FWP_DIRECTION_OUTBOUND | FWP_DRIECTION_INBOUND
				FWPM_CONDITION_IP_REMOTE_ADDRESS
				FWPM_CONDITION_IP_REMOTE_PORT
				FWPM_CONDITION_DIRECTION
		*/
		RtlZeroMemory(&Udpfilter, sizeof(FWPM_FILTER));
		Udpfilter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
		Udpfilter.displayData.name = L"Udp Flow Entablished filter.(Original Flow)";
		Udpfilter.displayData.description = L"Udp Sets up flow for traffic that we are interested in.";
		Udpfilter.action.type = FWP_ACTION_CALLOUT_TERMINATING; // FWP_ACTION_CALLOUT_INSPECTION
		Udpfilter.action.calloutKey = UDP_FLOW_ESTABLISHED_CALLOUT_V4;
		Udpfilter.filterCondition = UdpSublayerfilterConditions;
		Udpfilter.subLayerKey = MONITOR_SAMPLE_UDP_SUBLAYER;
		Udpfilter.weight.type = FWP_EMPTY; // auto-weight.
		Udpfilter.numFilterConditions = 3;
		Udpfilter.rawContext = DD_PROXY_FLOW_ORIGINAL;

		RtlZeroMemory(&UdpSublayerfilterConditions, sizeof(UdpSublayerfilterConditions));
		UdpSublayerfilterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		UdpSublayerfilterConditions[0].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[0].conditionValue.type = FWP_UINT32;
		UdpSublayerfilterConditions[0].conditionValue.uint32 =
			*(UINT32*)remoteAddr;

		UdpSublayerfilterConditions[1].fieldKey = FWPM_CONDITION_DIRECTION;
		UdpSublayerfilterConditions[1].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[1].conditionValue.type = FWP_UINT32;
		UdpSublayerfilterConditions[1].conditionValue.uint32 = FWP_DIRECTION_OUTBOUND;

		UdpSublayerfilterConditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		UdpSublayerfilterConditions[2].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[2].conditionValue.type = FWP_UINT16;
		UdpSublayerfilterConditions[2].conditionValue.uint16 = remotePort;

		result = HlprFwpmFilterAdd(engineHandle, &Udpfilter);
		if (NO_ERROR != result)
			break;

		RtlZeroMemory(&Udpfilter, sizeof(FWPM_FILTER));
		Udpfilter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
		Udpfilter.displayData.name = L"Udp Flow Entablished filter.(Proxy Flow)";
		Udpfilter.displayData.description = L"Udp Sets up flow for traffic that we are interested in.";
		Udpfilter.action.type = FWP_ACTION_CALLOUT_TERMINATING; // FWP_ACTION_CALLOUT_INSPECTION
		Udpfilter.action.calloutKey = UDP_FLOW_ESTABLISHED_CALLOUT_V4;
		Udpfilter.filterCondition = UdpSublayerfilterConditions;
		Udpfilter.subLayerKey = MONITOR_SAMPLE_UDP_SUBLAYER;
		Udpfilter.weight.type = FWP_EMPTY; // auto-weight.
		Udpfilter.numFilterConditions = 3;
		Udpfilter.rawContext = DD_PROXY_FLOW_PROXY;

		RtlZeroMemory(&UdpSublayerfilterConditions, sizeof(UdpSublayerfilterConditions));
		UdpSublayerfilterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		UdpSublayerfilterConditions[0].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[0].conditionValue.type = FWP_UINT32;
		UdpSublayerfilterConditions[0].conditionValue.uint32 =
			*(UINT32*)NewAddr;

		UdpSublayerfilterConditions[1].fieldKey = FWPM_CONDITION_DIRECTION;
		UdpSublayerfilterConditions[1].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[1].conditionValue.type = FWP_UINT32;
		UdpSublayerfilterConditions[1].conditionValue.uint32 = FWP_DIRECTION_OUTBOUND;		// FWP_DIRECTION_INBOUND

		UdpSublayerfilterConditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		UdpSublayerfilterConditions[2].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[2].conditionValue.type = FWP_UINT16;
		UdpSublayerfilterConditions[2].conditionValue.uint16 = NewPort;

		result = HlprFwpmFilterAdd(engineHandle, &Udpfilter);
		if (NO_ERROR != result)
			break;

		/*
			Udp DataGram:
				FWP_DIRECTION_OUTBOUND
				FWP_DIRECTION_INBOUND
		*/
		RtlZeroMemory(&Udpfilter, sizeof(FWPM_FILTER));
		Udpfilter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
		Udpfilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
		Udpfilter.action.calloutKey = UDP_DATAGRAM_CALLOUT_V4;
		Udpfilter.subLayerKey = MONITOR_SAMPLE_UDP_SUBLAYER;
		Udpfilter.weight.type = FWP_EMPTY; // auto-weight.
		Udpfilter.numFilterConditions = 3;

		RtlZeroMemory(&UdpSublayerfilterConditions, sizeof(UdpSublayerfilterConditions));
		UdpSublayerfilterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS; //condition_direction
		UdpSublayerfilterConditions[0].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[0].conditionValue.type = FWP_UINT32;
		UdpSublayerfilterConditions[0].conditionValue.uint32 = *(UINT32*)remoteAddr;

		UdpSublayerfilterConditions[1].fieldKey = FWPM_CONDITION_DIRECTION; //condition_direction
		UdpSublayerfilterConditions[1].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[1].conditionValue.type = FWP_UINT32;
		UdpSublayerfilterConditions[1].conditionValue.uint32 = FWP_DIRECTION_OUTBOUND;	// 出栈方向

		UdpSublayerfilterConditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		UdpSublayerfilterConditions[2].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[2].conditionValue.type = FWP_UINT16;
		UdpSublayerfilterConditions[2].conditionValue.uint16 = remotePort;
		Udpfilter.filterCondition = UdpSublayerfilterConditions;
		Udpfilter.displayData.name = L"Datagram OUTBOUND Layer Filter.";
		Udpfilter.displayData.description = L"OUTBOUND UDP/ICMP traffic.";
		result = HlprFwpmFilterAdd(engineHandle, &Udpfilter);
		if (NO_ERROR != result)
			break;


		RtlZeroMemory(&UdpSublayerfilterConditions, sizeof(UdpSublayerfilterConditions));
		UdpSublayerfilterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		UdpSublayerfilterConditions[0].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[0].conditionValue.type = FWP_UINT32;
		UdpSublayerfilterConditions[0].conditionValue.uint32 = *(UINT32*)NewAddr;
		UdpSublayerfilterConditions[1].fieldKey = FWPM_CONDITION_DIRECTION;
		UdpSublayerfilterConditions[1].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[1].conditionValue.type = FWP_UINT32;
		UdpSublayerfilterConditions[1].conditionValue.uint32 = FWP_DIRECTION_INBOUND;
		UdpSublayerfilterConditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		UdpSublayerfilterConditions[2].matchType = FWP_MATCH_EQUAL;
		UdpSublayerfilterConditions[2].conditionValue.type = FWP_UINT16;
		UdpSublayerfilterConditions[2].conditionValue.uint16 = NewPort;

		Udpfilter.filterCondition = UdpSublayerfilterConditions;
		Udpfilter.displayData.name = L"Datagram INBOUND Layer Filter.";
		Udpfilter.displayData.description = L"INBOUND UDP/ICMP traffic.";

		result = HlprFwpmFilterAdd(engineHandle, &Udpfilter);
		if (NO_ERROR != result)
			break;

		printf("Successfully added Stream filter\n");

		result = HlprFwpmTransactionCommit(engineHandle);
		if (NO_ERROR == result)
		{
			printf("Successfully Committed Transaction\n");
		}
		else
			printf("Failuer Committed Transaction\n");
		return result;

	} while (false);

	result = HlprFwpmTransactionAbort(engineHandle);
	if (NO_ERROR == result)
	{
		printf("Successfully Aborted Transaction\n");
	}
	return result;
}

DWORD 
WfpMonitorOpenMonitorDevice(
	_Out_ HANDLE* monitorDevice)
{
	ASSERT(monitorDevice);
	/// Open Wfp KM - Driver 
	*monitorDevice = CreateFileW(MONITOR_DOS_NAME,
								 GENERIC_READ | GENERIC_WRITE,
								 FILE_SHARE_READ | FILE_SHARE_WRITE,
								 NULL,
								 OPEN_EXISTING,
								 0,
								 NULL);
	if (*monitorDevice == INVALID_HANDLE_VALUE)
	{
		return GetLastError();
	}

	return NO_ERROR;
}

/*
	@ Send Control Code to Driver
*/
DWORD
MonitorAppEnableMonitoring(
	_In_    HANDLE            monitorDevice,
	_In_    MONITOR_SETTINGS* monitorSettings)
{
	DWORD bytesReturned;

	if (!DeviceIoControl(monitorDevice,
		MONITOR_IOCTL_ENABLE_MONITOR,
		monitorSettings,
		sizeof(MONITOR_SETTINGS),
		NULL,
		0,
		&bytesReturned,
		NULL))
	{
		return GetLastError();
	}

	return NO_ERROR;
}

/*
	@ Recv Kernel Data
*/
ULONG_PTR AcquireMappedLoopBuffer()
{
	ULONG RetBytes = 0;
	ULONG64 index = 0;
	ULONG buf = 0;
	ULONG x[2] = { 256,sizeof(ULONG) };
	ULONG_PTR ret = 0;

	// send control code

	CIRCULARBUFFER* circular_buffer_mapped = (CIRCULARBUFFER*)ret;

	__try {
		for (int i = 0; i < 3; i++) {
			RetBytes = (ULONG)OpenLoopBufferRead(circular_buffer_mapped, &buf, 1, index, &index);
			// Output Data
		}
	}
	__except (1) {}
	return ret;
}

/*
	临时地址 - 端口
*/
UINT16   configInspectDestPort = 1401;
UINT8*   configInspectDestAddrV4 = NULL;

UINT16   configNewDestPort = 1401;
UINT8*   configNewDestAddrV4 = NULL;

typedef ULONG (WINAPI* FnRtlIpv4StringToAddressW)(
	PCWSTR  S,
	BOOLEAN Strict,
	LPCWSTR *Terminator,
	in_addr *Addr
);
FnRtlIpv4StringToAddressW MyIpv4StringToAddressW;


int
WfpSkyNetMonitoring()
{
	UINT32				result = 0;
	HANDLE				engineHandle = NULL;
	HANDLE				monitorDevice = NULL;
	MONITOR_SETTINGS   monitorSettings;
	// FWP_BYTE_BLOB*		applicationId = NULL;
	FWPM_SESSION     session;
	RtlZeroMemory(&session, sizeof(FWPM_SESSION));
	session.displayData.name = L"Socket5 Tcp/Udp";
	session.displayData.description = L"For Adding callouts";
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	do
	{
		result = HlprFwpmEngineOpen(&engineHandle, &session);
		if (NO_ERROR != result)
			break;

		result = HlprFwpmTransactionBegin(&engineHandle, 0);
		if (NO_ERROR != result)
			break;

		//result = WfpMonitorOpenMonitorDevice(&monitorDevice);
		//if (NO_ERROR != result)
		//	break;

		// wfp add filter
		LPCWSTR terminator;

		IN_ADDR  destAddrStorageV4, newDestAddrStorageV4;

		HMODULE NtModu = GetModuleHandleW(L"Ntdll.dll");

		MyIpv4StringToAddressW = (FnRtlIpv4StringToAddressW)GetProcAddress(NtModu, "RtlIpv4StringToAddressW");

		// 目标ip
		int status = MyIpv4StringToAddressW(
			(PCWSTR)L"172.20.10.11",
			TRUE,
			&terminator,
			&destAddrStorageV4
		);

		if (status == 0)
		{
			destAddrStorageV4.S_un.S_addr =
				_byteswap_ulong(destAddrStorageV4.S_un.S_addr);
			configInspectDestAddrV4 = &destAddrStorageV4.S_un.S_un_b.s_b1;
		}


		// New-Ip configNewDestAddrV4
		status = MyIpv4StringToAddressW(
			(PCWSTR)L"192.168.112.128",
			TRUE,
			&terminator,
			&newDestAddrStorageV4
		);

		if (status == 0)
		{
			newDestAddrStorageV4.S_un.S_addr =
				_byteswap_ulong(newDestAddrStorageV4.S_un.S_addr);
			configNewDestAddrV4 = &newDestAddrStorageV4.S_un.S_un_b.s_b1;
		}

		result = WfpMonitorAppAddFilters(
			&engineHandle, 
			NULL, 
			configInspectDestAddrV4, 
			configInspectDestPort,
			configNewDestAddrV4,
			configNewDestPort);
		if (NO_ERROR != result)
			break;

		printf("Successfully added Filters through the Filtering Engine\n");

		printf("Enabling monitoring through the Monitor Sample Device\n");

		system("pause");

		monitorSettings.monitorOperation = monitorTraffic;

		result = MonitorAppEnableMonitoring(
			monitorDevice,
			&monitorSettings);

		if (NO_ERROR != result)
			break;

		printf("Successfully enabled monitoring.\n");

		printf("Events will be traced through WMI. Please press any key to exit and cleanup filters.\n");

#pragma prefast(push)
#pragma prefast(disable:6031, "by design the return value of _getch() is ignored here")
		_getch();
#pragma prefast(pop)

	} while (false);

	if (NO_ERROR != result)
	{
		printf("Monitor.\tError 0x%x occurred during execution\n", result);
	}

	if (monitorDevice)
	{
		printf("monitorDevice Uninsstall \n");
		CloseHandle(monitorDevice);
	}

	if (engineHandle)
	{
		printf("FwpmEngineClose Uninsstall \n");
		result = FwpmEngineClose(engineHandle);
		engineHandle = NULL;
	}
	return result;
}

int 
WfpInitServiceWorkRun()
{
	HANDLE engineHandle = NULL;
	FWPM_CALLOUT callout;
	FWPM_DISPLAY_DATA displayData;
	UINT32 result = 0;

	FWPM_SESSION session;
	RtlZeroMemory(&session, sizeof(FWPM_SESSION));
	session.displayData.name = L"Socket5 Tcp/Udp";
	session.displayData.description = L"For Adding callouts";

	/*
		@ Add CallOut
		@ 添加CallOut
	*/
	do
	{
		// OpenEngine
		result = HlprFwpmEngineOpen(&engineHandle, &session);
		if (NO_ERROR != result)
		{
			printf("Error: HlprFwpmEngineOpen = %d\r\n", result);
			return -1;
		}

		// TransactionBegin
		result = HlprFwpmTransactionBegin(&engineHandle);
		if (NO_ERROR != result)
		{
			printf("Error: HlprFwpmTransactionBegin = %d\r\n", result);
			return -1;
		}

		RtlZeroMemory(&callout, sizeof(FWPM_CALLOUT));
		RtlZeroMemory(&displayData, sizeof(FWPM_DISPLAY_DATA));
		displayData.description = MONITOR_FLOW_ESTABLISHED_CALLOUT_DESCRIPTION;
		displayData.name = MONITOR_FLOW_ESTABLISHED_CALLOUT_NAME;

		/*
			TCP - Established
		*/
		callout.calloutKey = TCP_FLOW_ESTABLISHED_CALLOUT_V4;
		callout.displayData = displayData;
		callout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
		callout.flags = FWPM_CALLOUT_FLAG_PERSISTENT;

		result = HlprFwpmCalloutAdd(&engineHandle, &callout);
		if (NO_ERROR != result)
		{
			printf("Error: HlprFwpmCalloutAdd = %d\r\n", result);
			break;
		}

		/*
			UDP - Established
		*/
		RtlZeroMemory(&callout, sizeof(FWPM_CALLOUT));
		RtlZeroMemory(&displayData, sizeof(FWPM_DISPLAY_DATA));
		displayData.description = L"Udp - Flow Established Callout proxy";
		displayData.name = L"Udp - Flow Established Callout";;

		callout.calloutKey = UDP_FLOW_ESTABLISHED_CALLOUT_V4;
		callout.displayData = displayData;
		callout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
		callout.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
		result = HlprFwpmCalloutAdd(&engineHandle, &callout);
		if (NO_ERROR != result)
		{
			printf("Error: HlprFwpmCalloutAdd = %d\r\n", result);
			break;
		}

	
		/*
			TCP FWPM_LAYER_STREAM_V4
		*/
		RtlZeroMemory(&callout, sizeof(FWPM_CALLOUT));
		displayData.description = MONITOR_STREAM_CALLOUT_DESCRIPTION;
		displayData.name = MONITOR_STREAM_CALLOUT_NAME;

		callout.calloutKey = TCP_STREAM_CALLOUT_V4;
		callout.displayData = displayData;
		callout.applicableLayer = FWPM_LAYER_STREAM_V4;
		callout.flags = FWPM_CALLOUT_FLAG_PERSISTENT;

		// Success! return NO_ERROR
		result = HlprFwpmCalloutAdd(&engineHandle, &callout);
		if (NO_ERROR != result)
		{
			printf("Error: HlprFwpmCalloutAdd = %d\r\n", result);
			break;
		}

		/*
			UDP - UDP_DATAGRAM_CALLOUT_V4
		*/
		RtlZeroMemory(&callout, sizeof(FWPM_CALLOUT));
		displayData.description = MONITOR_DataGram_CALLOUT_DESCRIPTION;
		displayData.name = MONITOR_DataGram_CALLOUT_NAME;

		callout.calloutKey = UDP_DATAGRAM_CALLOUT_V4;
		callout.displayData = displayData;
		callout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;
		// callout.flags = FWPM_CALLOUT_FLAG_PERSISTENT;

		result = HlprFwpmCalloutAdd(&engineHandle, &callout);
		if (NO_ERROR != result)
		{
			printf("Error: HlprFwpmCalloutAdd = %d\r\n", result);
			break;
		}


		result = HlprFwpmTransactionCommit(&engineHandle);
		if (NO_ERROR == result)
		{
			printf("Successfully Committed Transaction\r\n\r\n");
			break;
		}

		goto cleanup;

	} while (false);

	result = HlprFwpmTransactionAbort(&engineHandle);
	if (NO_ERROR == result)
	{
		printf("Successfully Aborted Transaction.\n");
	}

cleanup:
	if (engineHandle)
	{
		FwpmEngineClose(engineHandle);
		engineHandle = NULL;
	}

	return result;
}

int __cdecl wmain(
	_In_ const int argumentCount,
	_In_reads_(argumentCount) PCWSTR pArguments[]
)
{
	ASSERT(argumentCount);
	ASSERT(pArguments);

	UINT32 status = NO_ERROR;

	///
	// Server && Init CallOut
	// Add Callout
	///
	status = WfpInitServiceWorkRun();

	///
	// Set Wfp - User & AppDoMon
	// Add SubLayer and Add Filters
	///
	status = WfpSkyNetMonitoring();

	/// Argument Assist
	//if (argumentCount > 1)
	//{
	//	PCWSTR*                 ppCommandLineParameterStrings = (PCWSTR*)&(pArguments[1]);
	//	UINT32                  stringCount = argumentCount - 1;
	//	
	//	switch (stringCount)
	//	{
	//	case FLOW_CONTROL_NORMAL:
	//	{
	//		/// Init Wfp
	//		status = WfpInitServiceWorkRun();
	//		if (!status)
	//			return -1;

	//		/// Set Wfp - User & AppDoMon
	//		status = WfpSkyNetMonitoring();
	//		if (!status)
	//			return -1;
	//	}
	//	break;
	//	default:
	//		break;
	//	}
	//}

	return status;
}
