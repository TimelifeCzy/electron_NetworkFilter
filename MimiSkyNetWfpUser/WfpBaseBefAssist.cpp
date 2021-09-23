#include "WfpBaseBefAssist.h"

_At_(*pEngineHandle, _Pre_ _Null_)
_When_(return != NO_ERROR, _At_(*pEngineHandle, _Post_ _Null_))
_When_(return == NO_ERROR, _At_(*pEngineHandle, _Post_ _Notnull_))
_Success_(return == NO_ERROR)
UINT32 HlprFwpmEngineOpen(_Out_ HANDLE* pEngineHandle,
	FWPM_SESSION* wfpsession,
	_In_ const UINT32 sessionFlags) /* FWPM_SESSION_FLAG_NONDYNAMIC */
{
	ASSERT(pEngineHandle);
	ASSERT(wfpsession);
	DWORD result;
	FWPM_DISPLAY_DATA displayData;

	result = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		wfpsession,
		pEngineHandle
	);

	printf("HlprFwpmEngineOpen pEngineHandle = 0x%p\n", *pEngineHandle);

	return result;
}

/*
	@ Transaction
*/
_Success_(return == NO_ERROR)
UINT32 HlprFwpmTransactionAbort(_In_ HANDLE* engineHandle)
{
	UINT32 status = NO_ERROR;
	ASSERT(*engineHandle);
	if (engineHandle)
	{
		status = FwpmTransactionAbort(*engineHandle);
		if (status != NO_ERROR)
			wprintf(L"HlprFwpmTransactionAbort() [status: %#x]",
				status);
	}
	else
	{
		status = ERROR_INVALID_PARAMETER;

		wprintf(L"HlprFwpmTransactionAbort() [status: %#x][engineHandle: %#p]",
			status,
			engineHandle);
	}

	return status;
}

_Success_(return == NO_ERROR)
UINT32 HlprFwpmTransactionBegin(_In_ HANDLE* engineHandle,
	_In_ UINT32 flags)        /* 0 */
{
	UINT32 status = NO_ERROR;

	if (engineHandle)
	{
		printf("FwpmTransactionBegin engineHandle = 0x%p\n", *engineHandle);
		status = FwpmTransactionBegin(*engineHandle,
			flags);
		if (status != NO_ERROR)
			wprintf(L"HlprFwpmTransactionBegin() [status: %#x]", status);
	}
	else
	{
		status = ERROR_INVALID_PARAMETER;

		wprintf(L"HlprFwpmTransactionBegin() [status: %#x][engineHandle: %#p]",
			status,
			*engineHandle);
	}

	return status;
}

_Success_(return == NO_ERROR)
UINT32 HlprFwpmTransactionCommit(_In_ HANDLE* engineHandle)
{
	UINT32 status = NO_ERROR;
	ASSERT(engineHandle);
	if (*engineHandle)
	{
		status = FwpmTransactionCommit(*engineHandle);
		if (status != NO_ERROR)
		{
			wprintf(L"HlprFwpmTransactionCommit() [status: %#x]",
				status);

			HlprFwpmTransactionAbort(engineHandle);
		}
	}
	else
	{
		status = ERROR_INVALID_PARAMETER;

		wprintf(L"HlprFwpmTransactionCommit() [status: %#x][engineHandle: %#p]",
			status,
			engineHandle);
	}

	return status;
}

_Success_(return == NO_ERROR)
UINT32 HlprFwpmCalloutAdd(_In_ const HANDLE* engineHandle,
	_Inout_ FWPM_CALLOUT* pCallout)
{
	UINT32 status = NO_ERROR;

	if (engineHandle &&
		pCallout)
	{
		printf("engineHandle = 0x%p\n", *engineHandle);
		status = FwpmCalloutAdd(*engineHandle,
			pCallout,
			NULL,
			NULL);
		if (status != NO_ERROR)
		{
			if (status == FWP_E_ALREADY_EXISTS)
			{
				wprintf(L"Callout Already Exists\r\n");

				status = NO_ERROR;
			}
			else
				wprintf(L"HlprFwpmCalloutAdd : FwpmCalloutAdd() [status: %#x]",
					status);
		}
	}
	else
	{
		status = ERROR_INVALID_PARAMETER;

		wprintf(L"HlprFwpmCalloutAdd() [status: %#x][engineHandle: %#p][pCallout: %#p]",
			status,
			engineHandle,
			pCallout);
	}

	return status;
}

/*
	@ SunLayer
*/
_Success_(return == NO_ERROR)
UINT32 HlprFwpmSubLayerAdd(_In_ HANDLE* engineHandle,
	_In_ FWPM_SUBLAYER* subLayer)             /* FWPM_SUBLAYER_FLAG_PERSISTENT */
{
	UINT32 status = NO_ERROR;
	ASSERT(subLayer);

	if (engineHandle)
	{
		status = FwpmSubLayerAdd(*engineHandle,
			subLayer,
			0);
		if (status != NO_ERROR)
		{
			if (status == FWP_E_ALREADY_EXISTS)
			{
				wprintf(L"SubLayer Already Exists");

				status = NO_ERROR;
			}
			else
				wprintf(L"HlprFwpmSubLayerAdd : FwpmSubLayerAdd() [status: %#x]",
					status);
		}
	}
	else
	{
		status = ERROR_INVALID_PARAMETER;

		wprintf(L"HlprFwpmSubLayerAdd() [status: %#x]",
			status);
	}

	return status;
}

/*
	@ Filter
*/
_Success_(return == NO_ERROR)
UINT32 HlprFwpmFilterAdd(_In_ const HANDLE* engineHandle,
	_Inout_ FWPM_FILTER* pFilter)
{
	ASSERT(engineHandle);
	ASSERT(pFilter);

	UINT32 status = NO_ERROR;

	status = FwpmFilterAdd(*engineHandle,
		pFilter,
		NULL,
		NULL);
	if (status != NO_ERROR)
		wprintf(L"HlprFwpmFilterAdd : FwpmFilterAdd() [status: %#x]",
			status);

	return status;
}