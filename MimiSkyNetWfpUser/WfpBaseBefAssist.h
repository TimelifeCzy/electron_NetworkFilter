/*
	Wfp Base Function
		--
		--
		--
*/
#pragma once
#include "windows.h"
#include "fwpmu.h"
#include <stdio.h>
#include <mstcpip.h>

extern "C"
{
	/*
		wfp Base
	*/
	_At_(*pEngineHandle, _Pre_ _Null_)
		_When_(return != NO_ERROR, _At_(*pEngineHandle, _Post_ _Null_))
		_When_(return == NO_ERROR, _At_(*pEngineHandle, _Post_ _Notnull_))
		_Success_(return == NO_ERROR)
		UINT32 HlprFwpmEngineOpen(_Out_ HANDLE* pEngineHandle,
			FWPM_SESSION* wfpsession,
			_In_ const UINT32 sessionFlags = 0);

	/*
		@ Transaction
	*/
	_Success_(return == NO_ERROR)
		UINT32 HlprFwpmTransactionBegin(_In_ HANDLE* engineHandle,
			_In_ UINT32 flags = 0);

	_Success_(return == NO_ERROR)
		UINT32 HlprFwpmTransactionCommit(_In_ HANDLE* engineHandle);

	_Success_(return == NO_ERROR)
		UINT32 HlprFwpmTransactionAbort(_In_ HANDLE* engineHandle);

	_Success_(return == NO_ERROR)
		UINT32 HlprFwpmCalloutAdd(_In_ const HANDLE* engineHandle,
			_Inout_ FWPM_CALLOUT* pCallout);

	/*
		@ SubLayer
	*/
	_Success_(return == NO_ERROR)
		UINT32 HlprFwpmSubLayerDeleteByKey(_In_ const HANDLE* engineHandle,
			_In_ const GUID* pSubLayerKey);

	_Success_(return == NO_ERROR)
		UINT32 HlprFwpmSubLayerAdd(_In_ HANDLE* engineHandle,
			_In_ FWPM_SUBLAYER* subLayer);

	_Success_(return == NO_ERROR)
		UINT32 HlprFwpmSubLayerDelete(_In_opt_ HANDLE* pEngineHandle,
			_In_ const GUID* pSubLayerKey);


	/*
		@ Filter
	*/
	_Success_(return == NO_ERROR)
		UINT32 HlprFwpmFilterAdd(_In_ const HANDLE* engineHandle,
			_Inout_ FWPM_FILTER* pFilter);
};