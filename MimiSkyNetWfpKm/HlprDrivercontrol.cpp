#include <ntddk.h>
#include <wdf.h>

#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include "../inc/ioctl.h"
#include "HlprWfpMonitor.h"
#include "HlprDrivercontrol.h"

extern "C"
{
	extern KSPIN_LOCK flowContextListLock;
	extern UINT32 monitoringEnabled;

	EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL MonitorEvtDeviceControl;

	NTSTATUS MonitorCoEnableMonitoring(
		_In_  MONITOR_SETTINGS* monitorSettings)
	{
		KLOCK_QUEUE_HANDLE lockHandle;

		if (!monitorSettings)
		{
			return STATUS_INVALID_PARAMETER;
		}
		KdPrint(("Enabling monitoring.\r\n"));
		KeAcquireInStackQueuedSpinLock(&flowContextListLock, &lockHandle);
		monitoringEnabled = 1;
		KeReleaseInStackQueuedSpinLock(&lockHandle);
		return STATUS_SUCCESS;
	}

	NTSTATUS
		HlprCtlDriverInit(
			_In_ WDFDEVICE* pDevice
		)
		/*
		   // Initializes the request queue for our driver.  This is how
		   // DeviceIoControl requests are sent to KMDF drivers.
		*/
	{
		NTSTATUS status;
		WDF_IO_QUEUE_CONFIG queueConfig;

		KdPrint(("MonitorSample Control Initialization in progress.\r\n"));
		WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
			&queueConfig,
			WdfIoQueueDispatchSequential
		);

		queueConfig.EvtIoDeviceControl = MonitorEvtDeviceControl;

		status = WdfIoQueueCreate(
			*pDevice,
			&queueConfig,
			WDF_NO_OBJECT_ATTRIBUTES,
			NULL
		);

		return status;
	}

	VOID
		MonitorEvtDeviceControl(
			_In_ WDFQUEUE Queue,
			_In_ WDFREQUEST Request,
			_In_ size_t OutputBufferLength,
			_In_ size_t InputBufferLength,
			_In_ ULONG IoControlCode
		)
	{
		NTSTATUS status = STATUS_SUCCESS;

		UNREFERENCED_PARAMETER(Queue);
		UNREFERENCED_PARAMETER(OutputBufferLength);

		KdPrint(("MonitorSample Dispatch Device Control : 0x%x\r\n", IoControlCode));

		switch (IoControlCode)
		{
			case MONITOR_IOCTL_ENABLE_MONITOR:
			{
				WDFMEMORY pMemory;
				void* pBuffer;

				if (InputBufferLength < sizeof(MONITOR_SETTINGS))
				{
					status = STATUS_INVALID_PARAMETER;
				}
				else
				{
					status = WdfRequestRetrieveInputMemory(Request, &pMemory);
					if (NT_SUCCESS(status))
					{
						pBuffer = WdfMemoryGetBuffer(pMemory, NULL);
						status = MonitorCoEnableMonitoring((MONITOR_SETTINGS*)pBuffer);
					}
				}
				break;
			}

			case MONITOR_IOCTL_DISABLE_MONITOR:
			{
				status = STATUS_SUCCESS;
				// MonitorCoDisableMonitoring();
				break;
			}

			default:
			{
				status = STATUS_INVALID_PARAMETER;
			}
		}

		WdfRequestComplete(Request, status);
	}
}

