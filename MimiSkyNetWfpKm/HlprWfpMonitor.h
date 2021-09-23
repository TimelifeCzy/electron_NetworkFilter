#pragma once
#define DD_PROXY_FLOW_CONTEXT_POOL_TAG 'olfD'
#define DD_PROXY_PENDED_PACKET_POOL_TAG 'kppD'
#define DD_PROXY_CONTROL_DATA_POOL_TAG 'dcdD'

extern "C"
{
	typedef struct _FLOW_DATA
	{
		LIST_ENTRY  listEntry;
		UINT64      flowHandle;
		UINT64      flowContext;
		UINT64      calloutId;
		ULONG       localAddressV4;
		USHORT      localPort;
		USHORT      ipProto;
		ULONG       remoteAddressV4;
		USHORT      remotePort;
		WCHAR*      processPath;
		UINT64	   processID;
		BOOLEAN     deleting;
	} FLOW_DATA;

	NTSTATUS
		WfpMonitorCoInitialize(_Inout_ DEVICE_OBJECT* deviceObject);

	void MonitorCoUninitialize(void);

	typedef struct _BIND_DATA_TO_R3_
	{
		LIST_ENTRY  listEntry;
		WCHAR	   wProcessPath[1024];
		BYTE	   imageName[16 * 4];
		UINT64	   uProcessID;
		ULONG      uDataLength;
		USHORT     uRemotePort;
		USHORT     uLocalPort;
		BOOLEAN	   bIsSend;
	}BIND_DATA_TO_R3, *LPBIND_DATA_TO_R3;

	typedef enum DD_PROXY_FLOW_TYPE_
	{
		DD_PROXY_FLOW_ORIGINAL,
		DD_PROXY_FLOW_PROXY
	} DD_PROXY_FLOW_TYPE;


//
// DD_PROXY_FLOW_CONTEXT is the object type we used to stored information
// specific flow. This callout driver maintains two kind of flow contexts --
// the original flow and the flow being proxied to.
//

	typedef struct DD_PROXY_FLOW_CONTEXT_
	{
		LIST_ENTRY listEntry;

		BOOLEAN deleted;

		DD_PROXY_FLOW_TYPE flowType;
		ADDRESS_FAMILY addressFamily;

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
		union
		{
			FWP_BYTE_ARRAY16 localAddr;
			UINT32 ipv4LocalAddr;
		};
#pragma warning(pop)


		UINT8 protocol;

		UINT64 flowId;
		UINT16 layerId;
		UINT32 calloutId;

		UINT32 ipv4NetworkOrderStorage;

		//
		// For DD_PROXY_FLOW_ORIGINAL type, toRemote* is the new address/port
		// we are proxing to. For DD_PROXY_FLOW_PROXY type, it is the address/
		// port that we will need to revert to.
		//
		UINT8* toRemoteAddr;
		UINT16 toRemotePort;

		LONG refCount;
	} DD_PROXY_FLOW_CONTEXT;

	//
// DD_PROXY_PENDED_PACKET is the object type we used to store all information
// needed for out-of-band packet modification and re-injection. This type
// also points back to the flow context the packet belongs to.

	typedef struct DD_PROXY_PENDED_PACKET_
	{
		LIST_ENTRY listEntry;

		DD_PROXY_FLOW_CONTEXT* belongingFlow;
		FWP_DIRECTION  direction;

		//
		// Common fields for inbound and outbound traffic.
		//
		NET_BUFFER_LIST* netBufferList;
		COMPARTMENT_ID compartmentId;

		//
		// Data fields for outbound packet re-injection.
		//
		UINT64 endpointHandle;

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
		union
		{
			FWP_BYTE_ARRAY16 remoteAddr;
			UINT32 ipv4RemoteAddr;
		};
#pragma warning(pop)

		SCOPE_ID remoteScopeId;
		WSACMSGHDR* controlData;
		ULONG controlDataLength;

		//
		// Data fields for inbound packet re-injection.
		//
		ULONG nblOffset;
		UINT32 ipHeaderSize;
		UINT32 transportHeaderSize;
		IF_INDEX interfaceIndex;
		IF_INDEX subInterfaceIndex;
	} DD_PROXY_PENDED_PACKET;
}