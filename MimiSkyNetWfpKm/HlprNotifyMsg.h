#pragma once

extern "C"
{
#define TAG_NOTIFY 'yftN'

	NTSTATUS
		MonitorNfInitialize(
			_In_ DEVICE_OBJECT* deviceObject);

	NTSTATUS
		MonitorNfUninitialize(void);

	NTSTATUS MonitorNfNotifyMessage(
		_In_ const FWPS_STREAM_DATA* streamBuffer,
		_In_ BOOLEAN inbound,
		_In_ USHORT localPort,
		_In_ USHORT remotePort);

	typedef struct _BLACK_LIST_DATA {
		LIST_ENTRY	link;
		char data[255];
	}BLACK_LIST_DATA, *PBLACK_LIST_DATA;
}
