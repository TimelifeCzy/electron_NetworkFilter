/*
	@ Kernel : KM Filtering Engine
*/
#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>

#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include "../inc/ioctl.h"
#include "../inc/LoopBuffer.h"

#include "HlprWfpMonitor.h"
#include "HlprDrivercontrol.h"
#include "HlprNotifyMsg.h"
#include "HlprDriverAlpc.h"

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(MsnMntrInit,(e7db16bb, 41be, 4c05, b73e, 5feca06f8207),  \
        WPP_DEFINE_BIT(TRACE_INIT)               \
        WPP_DEFINE_BIT(TRACE_SHUTDOWN) )

// #include "MimiSkyNetWfpKM.tmh"
#include "init.tmh"

DEVICE_OBJECT* gWdmDevice;
HANDLE gInjectionHandle;

LIST_ENTRY	g_IpHeadList;

extern "C"
/*
	@ .cpp handle && function :
		-- DriverEntry: Driver Entry
		-- WfpMonitorEvtDeviceAdd : xxxx
		-- MonitorEvtDriverUnload : Unload WfpMon
*/
{
	NTSTATUS
		DriverEntry(
			_In_ DRIVER_OBJECT* driverObject,
			_In_ UNICODE_STRING* registryPath
		);

	NTSTATUS
		WfpMonitorEvtDeviceAdd(
			_In_ PWDFDEVICE_INIT pInit
		);

	void
		WfpMonitorEvtDriverUnload(
			_In_ WDFDRIVER Driver
		);

	NTSTATUS
		WfpMonitorNfInitialize(
			_In_ DEVICE_OBJECT* deviceObject);

	NTSTATUS 
		CreateProcessInfoForMapBuffer();
}

#define DELAY_ONE_MICRSECOND (-10)
#define DELAY_ONE_MILLISECOND (1000 * DELAY_ONE_MICRSECOND)

VOID MySleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	RtlSecureZeroMemory(&my_interval, sizeof(LARGE_INTEGER));
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

void AlpcMsgTest()
{
	//  test msg to server show ui
	DIRVER_MSG_TEST univermsg = { 0, };
	univermsg.univermsg.ControlId = ALPC_DRIVER_MSG_TEST;
	
	UNICODE_STRING test_buf;
	RtlInitUnicodeString(&test_buf, L"tesbuffer");
	while (true)
	{
		RtlMoveMemory(univermsg.MsgData, L"tesbuffer", 10);
		// test_buf.Buffer = test_buf.Buffer;
		MySleep(5000);
		TestSendMsg(&univermsg);
	}
}

VOID AlpcDispatchSendIpHeadMsg(
	_In_ PVOID StartContext
)
{
	while (true)
	{
		while (!IsListEmpty(&g_IpHeadList))
		{
			// KdBreakPoint();
			LIST_ENTRY *pEntry = RemoveHeadList(&g_IpHeadList);
			IPHEADLIST* pData = CONTAINING_RECORD(pEntry, IPHEADLIST, ListEntry);
			if (pData)
				AlpcSendIpHeadStructMsg(&pData->ipheadbuf);
			if (pData)
				ExFreePoolWithTag(pData, 'TAG');
		}

		// queue wait 1ms
		MySleep(100);
	}
}

NTSTATUS 
DriverEntry(
	_In_ DRIVER_OBJECT* driverObject,
	_In_ UNICODE_STRING* registryPath
)
/*
	Main dirver entry point 
*/
{
	NTSTATUS status = 0;
	WDF_DRIVER_CONFIG config;
	WDFDRIVER driver;
	PWDFDEVICE_INIT pInit = NULL;
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	WPP_INIT_TRACING(driverObject, registryPath);
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = WfpMonitorEvtDriverUnload;

	do
	{
		// Init Alpc
		// InitAlpcAddrs();
		// AlpcDriverStart();

		// Init IpHeadMonList
		InitializeListHead(&g_IpHeadList);
		// Start SendAlpc Thread
		HANDLE Msghandle;
		PsCreateSystemThread(
			&Msghandle,
			THREAD_ALL_ACCESS,
			NULL,
			NtCurrentProcess(),
			NULL,
			(PKSTART_ROUTINE)AlpcDispatchSendIpHeadMsg,
			NULL);

		status = WdfDriverCreate(driverObject, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
		if (!NT_SUCCESS(status))
			break;

		pInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
		if (!pInit)
			break;

		// wfp entry
		WfpMonitorEvtDeviceAdd(pInit);

	} while (false);

	return status;
}

NTSTATUS
WfpMonitorEvtDeviceAdd(
	_In_ PWDFDEVICE_INIT pInit
)
{
	NTSTATUS status;
	WDFDEVICE device;
	DECLARE_CONST_UNICODE_STRING(ntDeviceName, MONITOR_DEVICE_NAME);
	DECLARE_CONST_UNICODE_STRING(symbolicName, MONITOR_SYMBOLIC_NAME);

	WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);

	// register injectionhandle
	FwpsInjectionHandleCreate(
		AF_UNSPEC,
		FWPS_INJECTION_TYPE_TRANSPORT,
		&gInjectionHandle
	);

	//  &ntDeviceName &ntDeviceName
	status = WdfDeviceInitAssignName(pInit, &ntDeviceName);
	
	do 
	{
		status = WdfDeviceCreate(&pInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
		if (!NT_SUCCESS(status))
			break;

		// &symbolicName
		status = WdfDeviceCreateSymbolicLink(device, &symbolicName);
		if (!NT_SUCCESS(status))
			break;

		// Create Buffer Cach
		// CreateProcessInfoForMapBuffer();

		HlprCtlDriverInit(&device);
		if (!NT_SUCCESS(status))
			break;

		gWdmDevice = WdfDeviceWdmGetDeviceObject(device);

		/*
			Fwps Callout
		*/
		status = WfpMonitorCoInitialize(gWdmDevice);
		if (!NT_SUCCESS(status))
			break;

		status = WfpMonitorNfInitialize(gWdmDevice);
		if (!NT_SUCCESS(status))
			break;

		WdfControlFinishInitializing(device);

	} while (false);

	if (pInit)
	{
		WdfDeviceInitFree(pInit);
	}

	return status;
}

NTSTATUS
WfpMonitorNfInitialize(
	_In_ DEVICE_OBJECT* deviceObject)
{
	UNREFERENCED_PARAMETER(deviceObject);
	return STATUS_SUCCESS;
}

void
WfpMonitorEvtDriverUnload(
	_In_ WDFDRIVER Driver
)
{
	DRIVER_OBJECT* driverObject;
	MonitorCoUninitialize();
	MonitorNfUninitialize();
	KdPrint(("%s", L"MimiSkyNet Device Unload."));
	driverObject = WdfDriverWdmGetDriverObject(Driver);
	WPP_CLEANUP(driverObject);
}

NTSTATUS
CreateProcessInfoForMapBuffer()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	return 0;
}

