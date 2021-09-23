// CveServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

#include "HlprServerPip.h"
#include "HlprServerAlpc.h"

HlprServerPip g_pipui;

// Master Thread No-Exit
void wait()
{
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

DWORD PipStartCallback(
	LPVOID lpThreadParameter
)
{
	if (!lpThreadParameter)
		return -1;
	HlprServerPip* Piphd = (HlprServerPip *)lpThreadParameter;
	Piphd->StartServerPip();
}

void PipServerCallback(
	wchar_t* PortName
)
{
	if (-1 == g_pipui.StartServerPip())
	{
		auto error = GetLastError();
		printf("[~]Error: %d\r\n", error);
	}

	IPPACKHANDER ip_Heartbeat;
	memset(&ip_Heartbeat, 0, sizeof(IPPACKHANDER));
	ip_Heartbeat.heartbeat = 997;

	// 心跳包检测
	while (true)
	{
		if (-1 == g_pipui.PipSendMsg(&ip_Heartbeat, sizeof(IPPACKHANDER)))
		{
			printf("[3+]Client Pip inactive!\r\n");
			// 关闭Pip，失败意味着客户端已经关闭匿名管道
			g_pipui.PipClose();

			// 重新开启匿名管道，等待客户端上线
			if (-1 == g_pipui.StartServerPip())
			{
				auto error = GetLastError();
				printf("[~]Error: %d\r\n", error);
			}
		}
		Sleep(1000);
	}	
}

int main()
/*
	Enable Thread wait Client Connect
	Driver: Recv Msg  Inject Process(dll)  <--> block
	Dll: Recv Monitor info  <--> block
*/
{
	getchar();

	HANDLE hDllPortHandle, hDriverPortHandle, hPip;
	WCHAR AlpcDriverPortName[] = L"\\RPC Control\\AlpcDriverPort";
	WCHAR AlpcMonitorPortName[] = L"\\RPC Control\\AlpcMonitorPort";
	// remote debug breakpointer
	InitEvent();

	// PipServer
	hPip = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&PipServerCallback, NULL, 0, NULL);
	// Driver ALPC Services Port 
	hDriverPortHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&AlpcPortStart, (LPVOID)AlpcDriverPortName, 0, NULL);
	// DLL Monitor ALPC Services Port
	hDllPortHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&AlpcPortStart, (LPVOID)AlpcMonitorPortName, 0, NULL);
	// wait();
	WaitForSingleObject(hDriverPortHandle, INFINITE);

	return 0;
}