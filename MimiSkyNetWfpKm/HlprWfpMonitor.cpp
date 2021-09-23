#include <ntddk.h>
#include <ntstrsafe.h>
#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#include <fwpsk.h>
#include <ntdef.h>
#pragma warning(pop)

#include "../inc/ioctl.h"
#include "intsafe.h"

#include "HlprWfpApi.h"
#include "HlprNotifyMsg.h"
#include "HlprWfpMonitor.h"
#include "HlprDriverAlpc.h"

#define INITGUID
#include <guiddef.h>
#include "mntrguid.h"

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <ndis.h>

extern HANDLE gInjectionHandle;

UINT16   configNewDestPort = 1401;
UINT8*   configNewDestAddrV4 = NULL;
UINT8*   configNewDestAddrV6 = NULL;

UINT16   configInspectDestPort = 1401;
UINT8*   configInspectDestAddrV4 = NULL;
UINT8*   configInspectDestAddrV6 = NULL;

IN_ADDR  destAddrStorageV4, newDestAddrStorageV4;
IN6_ADDR destAddrStorageV6, newDestAddrStorageV6;

LIST_ENTRY gFlowList;
KSPIN_LOCK gFlowListLock;

BOOLEAN gDriverUnloading = FALSE;
HANDLE gThreadHandle = NULL;

LIST_ENTRY gPacketQueue;
KSPIN_LOCK gPacketQueueLock;
KEVENT gPacketQueueEvent;

extern "C"
{
	LIST_ENTRY flowContextList;
	KSPIN_LOCK flowContextListLock;
	UINT32 flowEstablishedId = 0, UdpflowEstablishedId = 0;
	UINT32 streamId = 0;
	UINT32 DataGramId = 0;
	UINT32 monitoringEnabled = 0;

	// realm and ip
	ULONG blockipaddrArry[10] = { 0xb465310b,0, };

	typedef struct UDP_HEADER_ {
		UINT16 srcPort;
		UINT16 destPort;
		UINT16 length;
		UINT16 checksum;
	} UDP_HEADER;


#define TAG_NAME_CALLOUT 'CnoM'

#if(NTDDI_VERSION >= NTDDI_WIN7)

	KSTART_ROUTINE DDProxyWorker;

	void
		DDProxyWorker(
			IN PVOID StartContext
		);


	NTSTATUS TcpCoFlowEstablishedCalloutV4(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Inout_opt_ void* packet,
		_In_opt_ const void* classifyContext,
		_In_ const FWPS_FILTER* filter,
		_In_ UINT64 flowContext,
		_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

	NTSTATUS TcpCoStreamCalloutV4(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Inout_opt_ void* packet,
		_In_opt_ const void* classifyContext,
		_In_ const FWPS_FILTER* filter,
		_In_ UINT64 flowContext,
		_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

	NTSTATUS UdpFlowEstablishedClassify(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Inout_opt_ void* layerData,
		_In_opt_ const void* classifyContext,
		_In_ const FWPS_FILTER* filter,
		_In_ UINT64 flowContext,
		_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

	NTSTATUS UdpCoDataGramCalloutV4(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Inout_opt_ void* packet,
		_In_opt_ const void* classifyContext,
		_In_ const FWPS_FILTER* filter,
		_In_ UINT64 flowContext,
		_Inout_ FWPS_CLASSIFY_OUT* classifyOut);



#else

	NTSTATUS UdpFlowEstablishedClassify(
		IN const FWPS_INCOMING_VALUES0* inFixedValues,
		IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
		IN OUT void* layerData,
		IN const FWPS_FILTER0* filter,
		IN UINT64 flowContext,
		OUT FWPS_CLASSIFY_OUT0* classifyOut);

	NTSTATUS TcpCoFlowEstablishedCalloutV4(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Inout_opt_ void* packet,
		_In_ const FWPS_FILTER* filter,
		_In_ UINT64 flowContext,
		_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

	NTSTATUS TcpCoStreamCalloutV4(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Inout_opt_ void* packet,
		_In_ const FWPS_FILTER* filter,
		_In_ UINT64 flowContext,
		_Inout_ FWPS_CLASSIFY_OUT* classifyOut);

	NTSTATUS UdpCoDataGramCalloutV4(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Inout_opt_ void* packet,
		_In_ const FWPS_FILTER* filter,
		_In_ UINT64 flowContext,
		_Inout_ FWPS_CLASSIFY_OUT* classifyOut)


#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

	NTSTATUS CoStreamNotifyV4(
		_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
		_In_ const GUID* filterKey,
		_Inout_ const FWPS_FILTER* filter);

	NTSTATUS CoFlowEstablishedNotifyV4(
		_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
		_In_ const GUID* filterKey,
		_Inout_ const FWPS_FILTER* filter);

	void TcpCoStreamFlowDeletion(
		_In_ UINT16 layerId,
		_In_ UINT32 calloutId,
		_In_ UINT64 flowContext);

	void MonitorCoDataGramFlowDeletion(
		_In_ UINT16 layerId,
		_In_ UINT32 calloutId,
		_In_ UINT64 flowContext);

	UINT64
		MonitorCoCreateFlowContext(
			_In_ const FWPS_INCOMING_VALUES* inFixedValues,
			_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
			_Out_ UINT64* flowHandle);

	NTSTATUS
		MonitorCoAllocFlowContext(
			_In_ SIZE_T processPathSize,
			_Out_ FLOW_DATA** flowContextOut
		);

	NTSTATUS
		MonitorCoInsertFlowContext(
			_Inout_ FLOW_DATA* flowContext);
	
}

void DDProxyInjectComplete(
	IN void* context,
	IN OUT NET_BUFFER_LIST* netBufferList,
	IN BOOLEAN dispatchLevel
)
{
	DD_PROXY_PENDED_PACKET* packet = (DD_PROXY_PENDED_PACKET*)context;
	UNREFERENCED_PARAMETER(dispatchLevel);

	// 关闭buffer_list
	FwpsFreeCloneNetBufferList0(netBufferList, 0);

	// DDProxyFreePendedPacket(packet);
}


NTSTATUS
DDProxyCloneModifyReinjectOutbound(
	IN DD_PROXY_PENDED_PACKET* packet
)
{
	NTSTATUS status = STATUS_SUCCESS;

	NET_BUFFER_LIST* clonedNetBufferList = NULL;
	FWPS_TRANSPORT_SEND_PARAMS0 sendArgs = { 0 };
	UDP_HEADER* udpHeader;

	status = FwpsAllocateCloneNetBufferList0(
		packet->netBufferList, //原始包
		NULL,
		NULL,
		0,
		&clonedNetBufferList
	);

	// 如果是UDP 且 远程端口不等0 - 改端口
	if ((packet->belongingFlow->protocol == IPPROTO_UDP) &&
		(packet->belongingFlow->toRemotePort != 0)) {
		NET_BUFFER* netBuffer;

		for (netBuffer = NET_BUFFER_LIST_FIRST_NB(clonedNetBufferList);
			netBuffer != NULL;
			netBuffer = NET_BUFFER_NEXT_NB(netBuffer))
		{
			udpHeader = (UDP_HEADER*)NdisGetDataBuffer(
				netBuffer,
				sizeof(UDP_HEADER),
				NULL,
				sizeof(UINT16),
				0
			 );

			ASSERT(udpHeader != NULL);

			// 修改udp代理端口
			udpHeader->destPort = packet->belongingFlow->toRemotePort;
			udpHeader->checksum = 0;
		}
	}

	// 无论对包修改或者不修改-都需要重发
	// 1. 需要发送的ip地址，上面已经修改过了端口
	// 2. id
	// 3. 控制数据
	// 4. 控制数据大小
	sendArgs.remoteAddress =
		(packet->belongingFlow->toRemoteAddr ? packet->belongingFlow->toRemoteAddr
			: (UINT8*)&packet->remoteAddr);
	sendArgs.remoteScopeId = packet->remoteScopeId;
	sendArgs.controlData = packet->controlData;
	sendArgs.controlDataLength = packet->controlDataLength;

	status = FwpsInjectTransportSendAsync0(
		gInjectionHandle,
		NULL,
		packet->endpointHandle,
		0,
		&sendArgs,
		packet->belongingFlow->addressFamily,
		packet->compartmentId,
		clonedNetBufferList,
		DDProxyInjectComplete,	// 被注入到网络堆栈以后调用回调
		packet
	);
	
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	clonedNetBufferList = NULL;

Exit:
	if (clonedNetBufferList != NULL)
	{
		FwpsFreeCloneNetBufferList0(clonedNetBufferList, 0);
	}

	return status;
}

NTSTATUS
DDProxyCloneModifyReinjectInbound(
	DD_PROXY_PENDED_PACKET* packet
)
{
	NTSTATUS status = STATUS_SUCCESS;

	NET_BUFFER_LIST* clonedNetBufferList = NULL;
	NET_BUFFER* netBuffer;
	UDP_HEADER* udpHeader;
	ULONG nblOffset;

	netBuffer = NET_BUFFER_LIST_FIRST_NB(packet->netBufferList);
	nblOffset = NET_BUFFER_DATA_OFFSET(netBuffer);

	// 如果偏移不相等
	if (nblOffset != packet->nblOffset)
	{
		ASSERT(packet->nblOffset - nblOffset == packet->transportHeaderSize);
		packet->transportHeaderSize = 0;
	}



	NdisRetreatNetBufferDataStart((PNET_BUFFER)netBuffer, packet->ipHeaderSize + packet->transportHeaderSize,
		0,
		NULL);

	status = FwpsAllocateCloneNetBufferList0(
		packet->netBufferList,
		NULL,
		NULL,
		0,
		&clonedNetBufferList
	);

	NdisAdvanceNetBufferDataStart(
		netBuffer,
		packet->ipHeaderSize + packet->transportHeaderSize,
		0,
		NULL
	);

	//
	if ((packet->belongingFlow->protocol == IPPROTO_UDP) &&
		(packet->belongingFlow->toRemotePort != 0))
	{
		NdisAdvanceNetBufferDataStart(
			netBuffer,
			packet->ipHeaderSize,
			FALSE,
			NULL
		);

		udpHeader = (UDP_HEADER*)NdisGetDataBuffer(
			netBuffer,
			sizeof(UDP_HEADER),
			NULL,
			sizeof(UINT16),
			0
		);
		ASSERT(udpHeader != NULL);
		udpHeader->srcPort = //bug bug bug!!!!!!!,change the destPort to srcPort
			packet->belongingFlow->toRemotePort;

		udpHeader->checksum = 0;

		NdisRetreatNetBufferDataStart(
			netBuffer,
			packet->ipHeaderSize,
			0,
			NULL
		);

	}


	if (packet->belongingFlow->toRemoteAddr != NULL) {
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
		status = FwpsConstructIpHeaderForTransportPacket0(
			clonedNetBufferList,
			packet->ipHeaderSize,
			packet->belongingFlow->addressFamily,
			packet->belongingFlow->toRemoteAddr,
			// This is our new source address --
			// or the destination address of the
			// original outbound traffic.
			(UINT8*)&packet->belongingFlow->localAddr,
			// This is the destination address of
			// the clone -- or the source of the
			// original outbound traffic.
			(IPPROTO)packet->belongingFlow->protocol,
			0,
			NULL,
			0,
			0,
			NULL,
			0,
			0
		);

#else
		ASSERT(FALSE);
		status = STATUS_NOT_IMPLEMENTED;
#endif
	}
	status = FwpsInjectTransportReceiveAsync0(
		gInjectionHandle,
		NULL,
		NULL,
		0,
		packet->belongingFlow->addressFamily,
		packet->compartmentId,
		packet->interfaceIndex,
		packet->subInterfaceIndex,
		clonedNetBufferList,
		DDProxyInjectComplete,
		packet
	);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	clonedNetBufferList = NULL; // ownership transferred to the 
								// completion function.

Exit:

	if (clonedNetBufferList != NULL)
	{
		FwpsFreeCloneNetBufferList0(clonedNetBufferList, 0);
	}

	return status;
}


void
DDProxyWorker(
	IN PVOID StartContext
)
{
	DD_PROXY_PENDED_PACKET* packet;
	LIST_ENTRY* listEntry;
	KLOCK_QUEUE_HANDLE packetQueueLockHandle;

	UNREFERENCED_PARAMETER(StartContext);

	// 处理包事件
	for (;;) {
		KeWaitForSingleObject(&gPacketQueueEvent, Executive, KernelMode, FALSE, NULL);

		if (gDriverUnloading) {
			break;
		}

		ASSERT(!IsListEmpty(&gPacketQueue));

		KeAcquireInStackQueuedSpinLock(&gPacketQueueLock, &packetQueueLockHandle);

		// 移除链表
		listEntry = RemoveHeadList(&gPacketQueue);

		KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);

		packet = CONTAINING_RECORD(
			listEntry,
			DD_PROXY_PENDED_PACKET,
			listEntry
		);

		if (!packet->belongingFlow->deleted) {
			NTSTATUS status;

			if (packet->direction == FWP_DIRECTION_OUTBOUND) {

				status = DDProxyCloneModifyReinjectOutbound(packet);
			}
			else {
				status = DDProxyCloneModifyReinjectInbound(packet);
			}
		}

		if (packet != NULL) {
			// 释放
		}

		KeAcquireInStackQueuedSpinLock(&gPacketQueueLock, &packetQueueLockHandle);

		if (IsListEmpty(&gPacketQueue) && !gDriverUnloading) {

			KeClearEvent(&gPacketQueueEvent);
		}

		KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);

	}

	ASSERT(gDriverUnloading);

	KeAcquireInStackQueuedSpinLock(
		&gPacketQueueLock,
		&packetQueueLockHandle
	);

	while (!IsListEmpty(&gPacketQueue))
	{
		listEntry = RemoveHeadList(&gPacketQueue);

		packet = CONTAINING_RECORD(
			listEntry,
			DD_PROXY_PENDED_PACKET,
			listEntry
		);

	}

	KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

void
MonitorCoDisableMonitoring(void)
{
	KLOCK_QUEUE_HANDLE lockHandle;

	// DoTraceMessage(TRACE_STATE_CHANGE, "Disabling monitoring.\r\n");

	KeAcquireInStackQueuedSpinLock(&flowContextListLock, &lockHandle);

	monitoringEnabled = 0;

	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

NTSTATUS
MonitorCoUnregisterCallout(
	_In_ const GUID* calloutKey
)
{
	NTSTATUS status;

	status = FwpsCalloutUnregisterByKey(calloutKey);

	return status;
}

NTSTATUS
MonitorCoUnregisterCallouts(void)
{
	NTSTATUS status;

	status = MonitorCoUnregisterCallout(&TCP_FLOW_ESTABLISHED_CALLOUT_V4);

	if (NT_SUCCESS(status))
	{
		status = MonitorCoUnregisterCallout(&TCP_STREAM_CALLOUT_V4);
		status = MonitorCoUnregisterCallout(&UDP_DATAGRAM_CALLOUT_V4);
	}

	return status;
}

void 
MonitorCoUninitialize(void)
{
	LIST_ENTRY list;
	KLOCK_QUEUE_HANDLE lockHandle;

	// Make sure we don't associate any more contexts to flows.
	MonitorCoDisableMonitoring();

	InitializeListHead(&list);

	KeAcquireInStackQueuedSpinLock(&flowContextListLock, &lockHandle);

	while (!IsListEmpty(&flowContextList))
	{
		FLOW_DATA* flowContext;
		LIST_ENTRY* entry;

		entry = RemoveHeadList(&flowContextList);

		flowContext = CONTAINING_RECORD(entry, FLOW_DATA, listEntry);
		flowContext->deleting = TRUE; // We don't want our flow deletion function
									  // to try to remove this from the list.

		InsertHeadList(&list, entry);
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	while (!IsListEmpty(&list))
	{
		FLOW_DATA* flowContext;
		LIST_ENTRY* entry;
		NTSTATUS status;

		entry = RemoveHeadList(&list);

		flowContext = CONTAINING_RECORD(entry, FLOW_DATA, listEntry);

		status = FwpsFlowRemoveContext(flowContext->flowHandle,
			FWPS_LAYER_STREAM_V4,
			streamId);

		status = FwpsFlowRemoveContext(flowContext->flowHandle,
			FWPS_LAYER_DATAGRAM_DATA_V4,
			DataGramId);
		NT_ASSERT(NT_SUCCESS(status));
		_Analysis_assume_(NT_SUCCESS(status));
	}

	MonitorCoUnregisterCallouts();
}

NTSTATUS 
WfpMonitorCoInitialize(
	_Inout_ DEVICE_OBJECT* deviceObject)
/*
	@ Init flowContextList && flowContextListLock List
	  -- HlprFwpsCalloutRegister
*/
{
	// Init 注入包列表
	NTSTATUS status = STATUS_SUCCESS;
	status = FwpsInjectionHandleCreate0(
		AF_UNSPEC,
		FWPS_INJECTION_TYPE_TRANSPORT,	// transport层注入
		&gInjectionHandle
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	InitializeListHead(&gFlowList);
	KeInitializeSpinLock(&gFlowListLock);

	InitializeListHead(&gPacketQueue);
	KeInitializeSpinLock(&gPacketQueueLock);
	KeInitializeEvent(
		&gPacketQueueEvent,
		NotificationEvent,
		FALSE
	);

	// 初始化目标IP及重定向IP
	// 目标ip
	LPCWSTR terminator;

	status = RtlIpv4StringToAddressW(
		(PCWSTR)L"172.20.10.11",
		TRUE,
		&terminator,
		&destAddrStorageV4
	);

	if (NT_SUCCESS(status))
	{
		destAddrStorageV4.S_un.S_addr =
			RtlUlongByteSwap(destAddrStorageV4.S_un.S_addr);
		configInspectDestAddrV4 = &destAddrStorageV4.S_un.S_un_b.s_b1;
	}

	status = RtlIpv4StringToAddressW(
		(PCWSTR)L"192.168.112.128",
		TRUE,
		&terminator,
		&newDestAddrStorageV4
	);

	if (NT_SUCCESS(status))
	{
		newDestAddrStorageV4.S_un.S_addr =
			RtlUlongByteSwap(newDestAddrStorageV4.S_un.S_addr);
		configNewDestAddrV4 = &newDestAddrStorageV4.S_un.S_un_b.s_b1;
	}

	if (!configNewDestAddrV4 && !configInspectDestAddrV4) {
		return status;
	}

	InitializeListHead(&flowContextList);
	KeInitializeSpinLock(&flowContextListLock);
	KdPrint(("FwpsCalloutRegister TcpCoFlowEstablishedCalloutV4 Entry.\r\n"));
	status = HlprFwpsCalloutRegister(deviceObject,
									 (FWPS_CALLOUT_CLASSIFY_FN)TcpCoFlowEstablishedCalloutV4,
									 (FWPS_CALLOUT_NOTIFY_FN)CoFlowEstablishedNotifyV4,
									 NULL, // We don't need a flow delete function at this layer.
									 &TCP_FLOW_ESTABLISHED_CALLOUT_V4,// &TCP_FLOW_ESTABLISHED_CALLOUT_V4,
									 0, // No flags.
									 &flowEstablishedId);

	status = HlprFwpsCalloutRegister(deviceObject,
									(FWPS_CALLOUT_CLASSIFY_FN)UdpFlowEstablishedClassify,
									(FWPS_CALLOUT_NOTIFY_FN)CoFlowEstablishedNotifyV4,
									NULL,
									&UDP_FLOW_ESTABLISHED_CALLOUT_V4,
									0, // No flags.
									&UdpflowEstablishedId);

	
	if (NT_SUCCESS(status))
	{
		KdPrint(("FwpsCalloutRegister TcpCoStreamCalloutV4 Entry.\r\n"));
		status = HlprFwpsCalloutRegister(deviceObject,
										(FWPS_CALLOUT_CLASSIFY_FN)TcpCoStreamCalloutV4,
										(FWPS_CALLOUT_NOTIFY_FN)CoStreamNotifyV4,
										(FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN)TcpCoStreamFlowDeletion,
										&TCP_STREAM_CALLOUT_V4,
										FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW,
										&streamId);

		KdPrint(("FwpsCalloutRegister UdpCoDATAGRAMCalloutV4 Entry.\r\n"));
		status = HlprFwpsCalloutRegister(deviceObject,
			(FWPS_CALLOUT_CLASSIFY_FN)UdpCoDataGramCalloutV4,
			(FWPS_CALLOUT_NOTIFY_FN)CoStreamNotifyV4,
			(FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN)MonitorCoDataGramFlowDeletion,
			&UDP_DATAGRAM_CALLOUT_V4,
			FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW,
			&DataGramId);
	}

	PsCreateSystemThread(
		&gThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		DDProxyWorker,
		NULL
	);


	return status;
}

/*
	@ ALE v4 handle
*/
NTSTATUS 
CoFlowEstablishedNotifyV4(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter)
{
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	switch (notifyType)
	{
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		//DoTraceMessage(TRACE_LAYER_NOTIFY,
		//	"Filter Added to Flow Established layer.\r\n");

		break;
	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
		//DoTraceMessage(TRACE_LAYER_NOTIFY,
		//	"Filter Deleted from Flow Established layer.\r\n");
		break;
	}

	return STATUS_SUCCESS;
}

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS 
TcpCoFlowEstablishedCalloutV4(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* packet,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
#else
NTSTATUS 
TcpCoFlowEstablishedCalloutV4(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* packet,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut);
#endif
{
	NTSTATUS status = STATUS_SUCCESS;
	UINT64   flowHandle;
	UINT64   flowContextLocal;

	UNREFERENCED_PARAMETER(packet);
#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(flowContext);
	do 
	{
		// Enable Monitor
		if (monitoringEnabled)
		{
			flowContextLocal = MonitorCoCreateFlowContext(inFixedValues, inMetaValues, &flowHandle);
			
			if (!flowContextLocal)
			{
				classifyOut->actionType = FWP_ACTION_CONTINUE;
				break;
			}
			
			status = FwpsFlowAssociateContext(flowHandle,
				FWPS_LAYER_STREAM_V4,
				streamId,
				flowContextLocal); 

			if (!NT_SUCCESS(status))
			{
				classifyOut->actionType = FWP_ACTION_CONTINUE;
				break;
			}
		}

		// Set Pack Action
		classifyOut->actionType = FWP_ACTION_PERMIT;

		if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
		{
			classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		}

	} while (false);

	return status;
}

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS 
UdpFlowEstablishedClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
#else
NTSTATUS 
UdpFlowEstablishedClassify(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const FWPS_FILTER0* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT0* classifyOut
)
#endif
{
	NTSTATUS status = STATUS_SUCCESS;

	BOOLEAN locked = FALSE;

	KLOCK_QUEUE_HANDLE flowListLockHandle;

	DD_PROXY_FLOW_CONTEXT* flowContextLocal = NULL;

	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(layerData);


	flowContextLocal = (DD_PROXY_FLOW_CONTEXT*)ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(DD_PROXY_FLOW_CONTEXT),
		DD_PROXY_FLOW_CONTEXT_POOL_TAG
	);

	if (flowContextLocal == NULL)
	{
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	RtlZeroMemory(flowContextLocal, sizeof(DD_PROXY_FLOW_CONTEXT));

	flowContextLocal->refCount = 1;
	flowContextLocal->flowType = (DD_PROXY_FLOW_TYPE)(filter->context);	// 判断是目标-代理
	flowContextLocal->addressFamily =
		(inFixedValues->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4) ?
		AF_INET : AF_INET6;
	ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
		FWPS_METADATA_FIELD_FLOW_HANDLE));
	flowContextLocal->flowId = inMetaValues->flowHandle;

	//
	// Note that since the consumer of the flow context is the datagram-data
	// layer classifyFn, layerId and calloutId are set to those of DD and not
	// flow-established.
	//
	flowContextLocal->layerId =
		(flowContextLocal->addressFamily == AF_INET) ?
		FWPS_LAYER_DATAGRAM_DATA_V4 : FWPS_LAYER_DATAGRAM_DATA_V6;
	flowContextLocal->calloutId =
		(flowContextLocal->addressFamily == AF_INET) ?
		DataGramId : 0;

	if (flowContextLocal->addressFamily == AF_INET)
	{
		flowContextLocal->ipv4LocalAddr =
			RtlUlongByteSwap(
				inFixedValues->incomingValue\
				[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32
			);
		flowContextLocal->protocol =
			inFixedValues->incomingValue\
			[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
	}
	else
	{
		RtlCopyMemory(
			(UINT8*)&flowContextLocal->localAddr,
			inFixedValues->incomingValue\
			[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16,
			sizeof(FWP_BYTE_ARRAY16)
		);
		flowContextLocal->protocol =
			inFixedValues->incomingValue\
			[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;
	}

	// 表示Outbound - 替换成代理的ip:port
	if (flowContextLocal->flowType == DD_PROXY_FLOW_ORIGINAL)
	{
		flowContextLocal->toRemoteAddr =
			(flowContextLocal->addressFamily == AF_INET) ?
			configNewDestAddrV4 : configNewDestAddrV6;
		// host-order -> network-order conversion for port.
		flowContextLocal->toRemotePort = RtlUshortByteSwap(configNewDestPort);
	}
	else
	{
		ASSERT(flowContextLocal->flowType == DD_PROXY_FLOW_PROXY);
		flowContextLocal->toRemoteAddr =
			(flowContextLocal->addressFamily == AF_INET) ?
			configInspectDestAddrV4 : configInspectDestAddrV6;
		// host-order -> network-order conversion for port.
		flowContextLocal->toRemotePort = RtlUshortByteSwap(configInspectDestPort);
	}
	// 如果端口不为空 且 v4
	if ((flowContextLocal->toRemoteAddr != NULL) &&
		(flowContextLocal->addressFamily == AF_INET))
	{
		// host-order -> network-order conversion for Ipv4 address.
		// 转换成网络序列
		flowContextLocal->ipv4NetworkOrderStorage =
			RtlUlongByteSwap(*(ULONG*)(flowContextLocal->toRemoteAddr));
		flowContextLocal->toRemoteAddr =
			(UINT8*)&flowContextLocal->ipv4NetworkOrderStorage;
	}

	KeAcquireInStackQueuedSpinLock(
		&gFlowListLock,
		&flowListLockHandle
	);

	locked = TRUE;

	if (!gDriverUnloading)
	{
		//
		// Associate DD_PROXY_FLOW_CONTEXT with the indicated flow-id to be 
		// accessible by the Datagram-Data classifyFn. (i.e. when a packet 
		// belongs to the same flow being classified at Datagram-Data layer,
		// DD_PROXY_FLOW_CONTEXT will be passed onto the classifyFn as the
		// "flowContext" parameter.
		//
		status = FwpsFlowAssociateContext0(
			flowContextLocal->flowId,
			flowContextLocal->layerId,
			flowContextLocal->calloutId,
			(UINT64)flowContextLocal
		);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}

		InsertHeadList(&gFlowList, &flowContextLocal->listEntry);
		flowContextLocal = NULL; // ownership transferred
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

Exit:

	if (locked)
	{
		KeReleaseInStackQueuedSpinLock(&flowListLockHandle);
	}

	if (flowContextLocal != NULL)
	{
		ExFreePoolWithTag(flowContextLocal, DD_PROXY_FLOW_CONTEXT_POOL_TAG);
	}

	if (!NT_SUCCESS(status))
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}

	return status;
}

NTSTATUS
MonitorCoInsertFlowContext(
	_Inout_ FLOW_DATA* flowContext)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	NTSTATUS status;


	KeAcquireInStackQueuedSpinLock(&flowContextListLock, &lockHandle);

	// Catch the case where we disabled monitoring after we had intended to
	// associate the context to the flow so that we don't bugcheck due to
	// our driver being unloaded and then receiving a call for a particular
	// flow or leak the memory because we unloaded without freeing it.
	if (monitoringEnabled)
	{
		// DoTraceMessage(TRACE_FLOW_ESTABLISHED, "Creating flow for traffic.\r\n");

		InsertTailList(&flowContextList, &flowContext->listEntry);
		status = STATUS_SUCCESS;
	}
	else
	{
		// DoTraceMessage(TRACE_FLOW_ESTABLISHED, "Unable to create flow, driver shutting down.\r\n");

		// Our driver is shutting down.
		status = STATUS_SHUTDOWN_IN_PROGRESS;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);
	return status;
}

UINT64
MonitorCoCreateFlowContext(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Out_ UINT64* flowHandle)
{
	FLOW_DATA*     flowContext = NULL;
	NTSTATUS       status;
	FWP_BYTE_BLOB* processPath;
	UINT32         index;

	*flowHandle = 0;

	if (!FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH))
	{
		status = STATUS_NOT_FOUND;
		goto cleanup;
	}

	processPath = inMetaValues->processPath;

	status = MonitorCoAllocFlowContext(processPath->size, &flowContext);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	//  Flow context is always created at the Flow established layer.

	// flowContext gets deleted in MonitorCoCleanupFlowContext 

	flowContext->deleting = FALSE;
	flowContext->flowHandle = inMetaValues->flowHandle;
	*flowHandle = flowContext->flowHandle;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS;
	flowContext->localAddressV4 = inFixedValues->incomingValue[index].value.uint32;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
	flowContext->localPort = inFixedValues->incomingValue[index].value.uint16;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
	flowContext->remoteAddressV4 = inFixedValues->incomingValue[index].value.uint32;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
	flowContext->remotePort = inFixedValues->incomingValue[index].value.uint16;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
	flowContext->ipProto = inFixedValues->incomingValue[index].value.uint16;

	// flowContext->processPath gets deleted in MonitorCoCleanupFlowContext 
	memcpy(flowContext->processPath, processPath->data, processPath->size);

	flowContext->processID = inMetaValues->processId;

	status = MonitorCoInsertFlowContext(flowContext);

cleanup:

	if (!NT_SUCCESS(status))
	{
		flowContext = NULL;
	}

	return (UINT64)(uintptr_t)flowContext;
}

NTSTATUS
MonitorCoAllocFlowContext(
	_In_ SIZE_T processPathSize,
	_Out_ FLOW_DATA** flowContextOut
)
{
	NTSTATUS status = STATUS_SUCCESS;
	FLOW_DATA* flowContext = NULL;

	*flowContextOut = NULL;

	flowContext = (FLOW_DATA*)ExAllocatePoolWithTag(NonPagedPool,
		sizeof(FLOW_DATA),
		TAG_NAME_CALLOUT);

	if (!flowContext)
	{
		status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	RtlZeroMemory(flowContext,
		sizeof(FLOW_DATA));


	flowContext->processPath = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool,
		processPathSize,
		TAG_NAME_CALLOUT);
	if (!flowContext->processPath)
	{
		status = STATUS_NO_MEMORY;
		goto cleanup;

	}

	*flowContextOut = flowContext;

cleanup:
	if (!NT_SUCCESS(status))
	{
		if (flowContext)
		{
			if (flowContext->processPath)
			{
				ExFreePoolWithTag(flowContext->processPath, TAG_NAME_CALLOUT);
			}
			ExFreePoolWithTag(flowContext, TAG_NAME_CALLOUT);
		}
	}

	return status;
}

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS UdpCoDataGramCalloutV4(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* packet,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)

#else
NTSTATUS UdpCoDataGramCalloutV4(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* packet,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)
#endif
{
	FLOW_DATA* flowData;
	FWPS_STREAM_CALLOUT_IO_PACKET* streamPacket;
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN inbound;
	UINT64 uDataLeng = 0;
	FWPS_PACKET_INJECTION_STATE packetState;
	KLOCK_QUEUE_HANDLE packetQueueLockHandle;
	BOOLEAN signalWorkerThread;
	DD_PROXY_PENDED_PACKET* packet_porxy = NULL;
	DD_PROXY_FLOW_CONTEXT* flowContextLocal = (DD_PROXY_FLOW_CONTEXT*)(DWORD_PTR)flowContext;

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(filter);

	_Analysis_assume_(packet != NULL);
	
	// 是否有权限修改
	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
		goto Exit;
	}

	// 如果注入的包将跳过 
	packetState = FwpsQueryPacketInjectionState0(gInjectionHandle, (NET_BUFFER_LIST*)packet, NULL);
	if ((packetState == FWPS_PACKET_INJECTED_BY_SELF) ||
		(packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF))
	{
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto Exit;
	}

	#pragma warning( suppress : 28197 )
	packet_porxy = (DD_PROXY_PENDED_PACKET*)ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(DD_PROXY_PENDED_PACKET),
		DD_PROXY_PENDED_PACKET_POOL_TAG
	);
	if (packet_porxy == NULL)
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		goto Exit;
	}

	RtlZeroMemory(packet_porxy, sizeof(DD_PROXY_PENDED_PACKET));

	ASSERT(flowContextLocal != NULL);

	packet_porxy->belongingFlow = flowContextLocal;
	ASSERT(packet_porxy->belongingFlow->refCount > 0);
	InterlockedIncrement(&packet_porxy->belongingFlow->refCount);

	// ipv4 & ipv6
	if (flowContextLocal->addressFamily == AF_INET) {
		ASSERT(inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4);
		packet_porxy->direction = (FWP_DIRECTION)inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32;
	}
	else
	{
		ASSERT(inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6);
		packet_porxy->direction = (FWP_DIRECTION)inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].value.uint32;
	}
	packet_porxy->netBufferList = (NET_BUFFER_LIST*)packet;

	FwpsReferenceNetBufferList0(packet_porxy->netBufferList, TRUE);

	ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
		FWPS_METADATA_FIELD_COMPARTMENT_ID));
	packet_porxy->compartmentId = (COMPARTMENT_ID)inMetaValues->compartmentId;

	// 获取方向
	if (packet_porxy->direction == FWP_DIRECTION_OUTBOUND) {
		ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE));
		packet_porxy->endpointHandle = inMetaValues->transportEndpointHandle;
		if (flowContextLocal->addressFamily == AF_INET) {
			packet_porxy->ipv4RemoteAddr =
				RtlUlongByteSwap( /* host-order -> network-order conversion */
					inFixedValues->incomingValue\
					[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32
				);
		}
		else {
			RtlCopyMemory(
				(UINT8*)&packet_porxy->remoteAddr,
				inFixedValues->incomingValue\
				[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS].value.byteArray16,
				sizeof(FWP_BYTE_ARRAY16)
			);
		}
		packet_porxy->remoteScopeId = inMetaValues->remoteScopeId;
		if (FWPS_IS_METADATA_FIELD_PRESENT(
			inMetaValues,
			FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA))
		{
			ASSERT(inMetaValues->controlDataLength > 0);
			// packet->controlData gets deleted in DDProxyFreePendedPacket
#pragma warning( suppress : 28197 )
			packet_porxy->controlData = (WSACMSGHDR*)ExAllocatePoolWithTag(
				NonPagedPool,
				inMetaValues->controlDataLength,
				DD_PROXY_CONTROL_DATA_POOL_TAG
			);
			if (packet_porxy->controlData == NULL)
			{
				classifyOut->actionType = FWP_ACTION_BLOCK;
				classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
				goto Exit;
			}
			RtlCopyMemory(
				packet_porxy->controlData,
				inMetaValues->controlData,
				inMetaValues->controlDataLength
			);
			packet_porxy->controlDataLength = inMetaValues->controlDataLength;

		}
	}
	else {
		ASSERT(packet_porxy->direction == FWP_DIRECTION_INBOUND);

		if (flowContextLocal->addressFamily == AF_INET)
		{
			ASSERT(inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4);
			packet_porxy->interfaceIndex =
				inFixedValues->incomingValue\
				[FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX].value.uint32;
			packet_porxy->subInterfaceIndex =
				inFixedValues->incomingValue\
				[FWPS_FIELD_DATAGRAM_DATA_V4_SUB_INTERFACE_INDEX].value.uint32;
		}
		else
		{
			ASSERT(inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6);
			packet_porxy->interfaceIndex =
				inFixedValues->incomingValue\
				[FWPS_FIELD_DATAGRAM_DATA_V6_INTERFACE_INDEX].value.uint32;
			packet_porxy->subInterfaceIndex =
				inFixedValues->incomingValue\
				[FWPS_FIELD_DATAGRAM_DATA_V6_SUB_INTERFACE_INDEX].value.uint32;
		}

		ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
			inMetaValues,
			FWPS_METADATA_FIELD_IP_HEADER_SIZE));
		ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
			inMetaValues,
			FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE));
		packet_porxy->ipHeaderSize = inMetaValues->ipHeaderSize;
		packet_porxy->transportHeaderSize = inMetaValues->transportHeaderSize;

		packet_porxy->nblOffset =
			NET_BUFFER_DATA_OFFSET(NET_BUFFER_LIST_FIRST_NB(packet_porxy->netBufferList));

	}

	KeAcquireInStackQueuedSpinLock(&gPacketQueueLock, &packetQueueLockHandle);

	// 包进行引用，包动作block，包克隆 - 数据修改
	// 重新注入-解引用 
	if (!gDriverUnloading) {
		signalWorkerThread = IsListEmpty(&gPacketQueue);
		InsertTailList(&gPacketQueue, &packet_porxy->listEntry);
		packet_porxy = NULL;

		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
	}
	else {
		signalWorkerThread = FALSE;
		classifyOut->actionType = FWP_ACTION_PERMIT;
	}


	// 如果有注入线程，需要执行
	if (signalWorkerThread)
	{
		// 激活注入包处理
		KeSetEvent(
			&gPacketQueueEvent,
			0,
			FALSE
		);
	}


	KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
Exit:
	if (packet != NULL)
	{
		//DDProxyFreePendedPacket(packet);
	}

	return STATUS_SUCCESS;
}

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS TcpCoStreamCalloutV4(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* packet,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)

#else
NTSTATUS TcpCoStreamCalloutV4(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* packet,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut)

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
{
	FLOW_DATA* flowData;
	FWPS_STREAM_CALLOUT_IO_PACKET* streamPacket;
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN inbound;
	UINT64 uDataLeng = 0;

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	_Analysis_assume_(packet != NULL);

	if (!monitoringEnabled)
	{
		goto cleanup;
	}

	streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET*)packet;
	if (streamPacket->streamData != NULL &&
		streamPacket->streamData->dataLength != 0)
	{
		flowData = *(FLOW_DATA**)(UINT64*)&flowContext;

		inbound = (BOOLEAN)((streamPacket->streamData->flags & FWPS_STREAM_FLAG_RECEIVE) == FWPS_STREAM_FLAG_RECEIVE);

		DbgPrint("Tcp --> ProcessId : %d\t Protor: %d\t localAddressV4: 0x%x:%d\t remoteAddressV4: 0x%x:%d\r\n", flowData->processID, flowData->ipProto, flowData->localAddressV4, flowData->localPort, flowData->remoteAddressV4, flowData->remotePort);



		// BUG : If the synchronization will be stuck 
		//IPPACKHEAD* ippk = (IPPACKHEAD*)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPPACKHEAD), 'TAG');
		//if (ippk)
		//{
		//	RtlSecureZeroMemory(ippk, sizeof(IPPACKHEAD));
		//	ippk->univermsg.ControlId = ALPC_IPPACK_HEADER;
		//	ippk->pid = flowData->processID;
		//	ippk->protocol = flowData->ipProto;
		//	ippk->localaddr = flowData->localAddressV4;
		//	ippk->localport = flowData->localPort;
		//	ippk->remoteaddr = flowData->remoteAddressV4;
		//	ippk->remoteport = flowData->remotePort;
		//	AlpcSendIpHeadStructMsg(ippk);
		//	if (ippk)
		//		ExFreePoolWithTag(ippk, 'TAG');
		//}

		// buffer push IpHeadMsg_List
		if (&g_IpHeadList)
		{
			IPHEADLIST* ippk = (IPHEADLIST*)ExAllocatePoolWithTag(NonPagedPool, sizeof(IPHEADLIST), 'TAG');
			RtlSecureZeroMemory(ippk, sizeof(IPHEADLIST));
			ippk->ipheadbuf.univermsg.ControlId = ALPC_IPPACK_HEADER;
			ippk->ipheadbuf.pid = flowData->processID;
			ippk->ipheadbuf.protocol = flowData->ipProto;
			ippk->ipheadbuf.localaddr = flowData->localAddressV4;
			ippk->ipheadbuf.localport = flowData->localPort;
			ippk->ipheadbuf.remoteaddr = flowData->remoteAddressV4;
			ippk->ipheadbuf.remoteport = flowData->remotePort;
			InsertTailList(&g_IpHeadList, &ippk->ListEntry);
		}

		// test FWP_ACTION_BLOCK 
		//if (flowData->remoteAddressV4 == blockipaddrArry[0])
		//{
		//	classifyOut->actionType = FWP_ACTION_BLOCK;
		//	return status;
		//}

		//do
		//{
		//	// Data
		//	if (streamPacket->streamData)
		//	{
		//		SIZE_T streamLength = streamPacket->streamData->dataLength;
		//		if (!streamLength)
		//			break;
		//	}

		//} while (false);

		//// http pack Anay
		//status = MonitorNfNotifyMessage(streamPacket->streamData,
		//	inbound,
		//	flowData->localPort,
		//	flowData->remotePort);
	}

cleanup:

	classifyOut->actionType = FWP_ACTION_CONTINUE;

	return status;
}

NTSTATUS CoStreamNotifyV4(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}

void
MonitorCoCleanupFlowContext(
	_In_ __drv_freesMem(Mem) FLOW_DATA* flowContext
)
/*
Routine Description

	Called to cleanup a flow context on flow deletion.  ProcessPath is passed
	as a second parameter so Prefast can see that it's being freed here.

*/
{
	if (flowContext->processPath)
	{
		ExFreePoolWithTag(flowContext->processPath, TAG_NAME_CALLOUT);
	}
	ExFreePoolWithTag(flowContext, TAG_NAME_CALLOUT);
}

void TcpCoStreamFlowDeletion(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	FLOW_DATA* flowData;
	HRESULT result;
	ULONG_PTR flowPtr;

	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);

	result = ULongLongToULongPtr(flowContext, &flowPtr);
	ASSERT(result == S_OK);
	_Analysis_assume_(result == S_OK);


	flowData = ((FLOW_DATA*)flowPtr);

	//
	// If we're already being deleted from the list then we mustn't try to 
	// remove ourselves here.
	//
	KeAcquireInStackQueuedSpinLock(&flowContextListLock, &lockHandle);

	if (!flowData->deleting)
	{
		RemoveEntryList(&flowData->listEntry);
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	MonitorCoCleanupFlowContext(flowData);
}


void MonitorCoDataGramFlowDeletion(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	FLOW_DATA* flowData;
	HRESULT result;
	ULONG_PTR flowPtr;

	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);
}