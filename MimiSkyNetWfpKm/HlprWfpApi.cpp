#include <ntddk.h>
#include <ntstrsafe.h>

#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include "HlprWfpApi.h"

extern "C"
{
	NTSTATUS
		HlprFwpsCalloutRegister(_Inout_ void* deviceObject,
			_In_ FWPS_CALLOUT_CLASSIFY_FN ClassifyFunction,
			_In_ FWPS_CALLOUT_NOTIFY_FN NotifyFunction,
			_In_opt_ FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN FlowDeleteFunction,
			_In_ const GUID* calloutKey,
			_In_ UINT32 flags,
			_Out_ UINT32* calloutId)
		/*
			@ Add Network Filter Callback
		*/
		{
			ASSERT(ClassifyFunction);
			ASSERT(NotifyFunction);

			FWPS_CALLOUT sCallout;
			NTSTATUS status = STATUS_SUCCESS;

			memset(&sCallout, 0, sizeof(FWPS_CALLOUT));

			sCallout.calloutKey = *calloutKey;
			sCallout.flags = flags;
			sCallout.classifyFn = ClassifyFunction;
			sCallout.notifyFn = NotifyFunction;
			sCallout.flowDeleteFn = FlowDeleteFunction;

			status = FwpsCalloutRegister(deviceObject, &sCallout, calloutId);

			return status;
		}
}
