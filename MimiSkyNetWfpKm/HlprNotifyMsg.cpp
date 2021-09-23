#include <ntddk.h>

#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include "HlprNotifyMsg.h"

#define TAG_NAME_NOTIFY 'oNnM'

NTSTATUS
MonitorNfInitialize(
	_In_ DEVICE_OBJECT* deviceObject)
{
	UNREFERENCED_PARAMETER(deviceObject);

	return STATUS_SUCCESS;
}

NTSTATUS
MonitorNfUninitialize(void)
{
	return STATUS_SUCCESS;
}

__forceinline
void*
MonitorNfpFindCharacters(
	_In_reads_bytes_(streamLength) const char* stream,
	_In_ size_t streamLength,
	_In_reads_bytes_(subStreamLength) const char* subStream,
	_In_ size_t subStreamLength,
	_Out_ size_t* bytesLeft)
{
	size_t currentOffset = 0;
	void* subStreamPtr = NULL;

	*bytesLeft = streamLength;

	if (subStreamLength > streamLength)
	{
		return NULL;
	}

	while (currentOffset + subStreamLength <= streamLength)
	{
		if (0 == memcmp((void*)(stream + currentOffset), subStream, subStreamLength))
		{
			subStreamPtr = (void*)(char*)(stream + currentOffset);
			*bytesLeft = streamLength;
			*bytesLeft -= currentOffset;
			*bytesLeft -= subStreamLength;
			break;
		}
		currentOffset += subStreamLength;
	}

	return subStreamPtr;
}

NTSTATUS
MonitorNfParseMessageInbound(
	_In_reads_bytes_(streamLength) BYTE* stream,
	_In_ size_t streamLength,
	_In_ USHORT localPort,
	_In_ USHORT remotePort)
{
	UNREFERENCED_PARAMETER(stream);

	DbgPrint(
		"%Id bytes received. Local Port: %d Remote Port: %d.\r\n",
		streamLength,
		localPort,
		remotePort);
	return STATUS_SUCCESS;
}

NTSTATUS
MonitorNfParseMessageInboundHttpHeader(
	_In_reads_bytes_(streamLength) BYTE* stream,
	_In_ size_t streamLength,
	_In_ USHORT localPort,
	_In_ USHORT remotePort)
{
	BYTE* msgStart = NULL;
	size_t bytesLeft;
	NTSTATUS status = STATUS_INVALID_PARAMETER;

	// Walk past the HTTP header.
	msgStart = (BYTE*)MonitorNfpFindCharacters((char*)stream,
		streamLength,
		"\r\n\r\n",
		(ULONG)strlen("\r\n\r\n"),
		&bytesLeft);
	if (msgStart && (bytesLeft > 0))
	{
		size_t msgLength;

		msgStart += 4; // step past \r\n\r\n.

		msgLength = streamLength - (ULONG)(ULONG_PTR)(msgStart - stream);

		// Do the final inbound message processing.
		status = MonitorNfParseMessageInbound(msgStart,
			msgLength,
			localPort,
			remotePort);
	}

	return status;
}

NTSTATUS
MonitorNfParseMessageOutbound(
	_In_reads_bytes_(streamLength) BYTE* stream,
	_In_ size_t streamLength,
	_In_ USHORT localPort,
	_In_ USHORT remotePort)
{
	UNREFERENCED_PARAMETER(stream);

	DbgPrint("%Id bytes sent. Local Port: %d Remote Port: %d.\r\n",
		streamLength,
		localPort,
		remotePort);

	return STATUS_SUCCESS;
}

NTSTATUS
MonitorNfParseMessageOutboundHttpHeader(
	_In_reads_bytes_(streamLength) BYTE* stream,
	_In_ size_t streamLength,
	_In_ USHORT localPort,
	_In_ USHORT remotePort)
{
	BYTE* msgStart = NULL;
	size_t bytesLeft;
	NTSTATUS status = STATUS_SUCCESS;
	// Walk past the HTTP header.
	msgStart = (BYTE*)MonitorNfpFindCharacters((char*)stream,
		streamLength,
		"\r\n\r\n",
		(ULONG)strlen("\r\n\r\n"),
		&bytesLeft);
	if (msgStart && (bytesLeft > 0))
	{
		size_t msgLength;

		msgStart += 4; // step past \r\n\r\n.

		msgLength = streamLength - (ULONG)(ULONG_PTR)(msgStart - stream);
		status = MonitorNfParseMessageOutbound(msgStart,
			msgLength,
			localPort,
			remotePort);
	}

	return status;
}


NTSTATUS
MonitorNfParseStreamAndTraceMessage(
	_In_reads_bytes_(streamLength) BYTE* stream,
	_In_ size_t streamLength,
	_In_ BOOLEAN inbound,
	_In_ USHORT localPort,
	_In_ USHORT remotePort)
{
	NTSTATUS status;

	if (!inbound)
	{
		// Http Query
		if ((_strnicmp((const char*)stream, "POST", streamLength) == 0)
			|| (_strnicmp((const char*)stream, "GET", streamLength) == 0))
		{
			if ((MonitorNfParseMessageOutboundHttpHeader(stream,
				streamLength,
				localPort,
				remotePort)) != STATUS_SUCCESS)
				return STATUS_INSUFFICIENT_RESOURCES;
		}
		else
		{
			if ((MonitorNfParseMessageOutbound(stream,
				streamLength,
				localPort,
				remotePort) != STATUS_SUCCESS))
				return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	else
	{
		if (_strnicmp((const char*)stream, "HTTP", streamLength) == 0)
		{
			if ((MonitorNfParseMessageInboundHttpHeader(stream,
				streamLength,
				localPort,
				remotePort)) != STATUS_SUCCESS)
				return STATUS_INSUFFICIENT_RESOURCES;
		}
		else
		{
			if ((MonitorNfParseMessageInbound(stream,
				streamLength,
				localPort,
				remotePort)) != STATUS_SUCCESS)
				return STATUS_INSUFFICIENT_RESOURCES;
		}

		// SSL
		BYTE ssl_title[] = { 0x16, 0x03, 0x03 };
		if (*stream == ssl_title[0] &&
			*(stream + 1) == ssl_title[1] &&
			*(stream + 2) == ssl_title[2]
			)
		{
			DbgPrint("SSL Connect\r\n");
		}

		// Https

	}

	{
		status = STATUS_SUCCESS;
	}

	return status;
}

EX_SPIN_LOCK    gBlockIpLock, gBlockDataLock;

NTSTATUS MonitorNfNotifyMessage(
	_In_ const FWPS_STREAM_DATA* streamBuffer,
	_In_ BOOLEAN inbound,
	_In_ USHORT localPort,
	_In_ USHORT remotePort)
{
	NTSTATUS status = STATUS_SUCCESS;
	BYTE* stream = NULL;
	SIZE_T streamLength = streamBuffer->dataLength;
	SIZE_T bytesCopied = 0;

	if (streamLength == 0)
		return status;

	stream = (BYTE*)ExAllocatePoolWithTag(NonPagedPool,
										  streamLength,
										  TAG_NAME_NOTIFY);
	if (!stream)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(stream, streamLength);

	FwpsCopyStreamDataToBuffer(
		streamBuffer,
		stream,
		streamLength,
		&bytesCopied);

	NT_ASSERT(bytesCopied == streamLength);
	
	status = MonitorNfParseStreamAndTraceMessage(stream, streamLength, inbound, localPort, remotePort);

	ExFreePoolWithTag(stream, TAG_NAME_NOTIFY);

	return status;

}