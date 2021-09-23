#pragma once


extern "C"
{
	/*
		@ FwpsCalloutRegister
			-- FWPS_CALLOUT_CLASSIFY_FN
			-- FWPS_CALLOUT_NOTIFY_FN
			-- FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN
	*/
	NTSTATUS
		HlprFwpsCalloutRegister(
			_Inout_ void* deviceObject,
			_In_ FWPS_CALLOUT_CLASSIFY_FN ClassifyFunction,
			_In_ FWPS_CALLOUT_NOTIFY_FN NotifyFunction,
			_In_opt_ FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN FlowDeleteFunction,
			_In_ const GUID* calloutKey,
			_In_ UINT32 flags,
			_Out_ UINT32* calloutId);
}

