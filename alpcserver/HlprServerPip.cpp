#include "HlprServerPip.h"
#include <Windows.h>
#include <iostream>

using namespace std;

HANDLE m_PipHandle;

#include <vector>

vector<HANDLE> g_PipClientList;

HlprServerPip::HlprServerPip()
{

}

HlprServerPip::~HlprServerPip()
{

}

int HlprServerPip::StartServerPip(
)
{
	m_PipHandle = CreateNamedPipeW(L"\\\\.\\Pipe\\uiport", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 1, 0, 0, 1000, NULL);
	if (m_PipHandle == INVALID_HANDLE_VALUE)
	{
		// Log
		cout << "[+]CreateNamedPipeW Error: %d\r\n" << GetLastError() << endl;
		return -1;
	}
	printf("[1+]Server restart, wait client connect PipServer!\r\n");

	// Wait UI-Connect 
	BOOL nRet = ConnectNamedPipe(m_PipHandle, NULL);
	if (!nRet)
		PipClose();
	printf("[2+]Client Connect Success~\r\n");
	return nRet;
}

int HlprServerPip::PipSendMsg(
	void* buf, 
	const int bufLen
)
{
	if (m_PipHandle)
	{
		DWORD wrtSize = 0;
		BOOL nRet = WriteFile(m_PipHandle, buf, bufLen, &wrtSize, NULL);
		if (!nRet)
			return -1;
		else
			return 0;
	}

	return -1;
}

void HlprServerPip::PipClose()
{
	if (m_PipHandle)
		CloseHandle(m_PipHandle);
	m_PipHandle = NULL;
}