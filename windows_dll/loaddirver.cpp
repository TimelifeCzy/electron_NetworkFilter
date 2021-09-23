#include <Windows.h>
#include "apiexport.h"
#include <stdio.h>

#define BUFSIZE 1024

int prDriverOpen()
{
	return 1;
}

int puLoadDriver(const char* drivername, const int nstatus)
{
	printf("load driver start");
	return 1;
}

int puUninstallDriver(const char* drivername)
{
	return 1;
}

int puGetDriverStatus(const char* drivername)
{
	return 1;
}

int puStopDriverStatus(const char* drivername)
{
	return 1;
}

int puControlCodeSend(const long long driverhandle, const int controlcode)
{
	return 1;
}

int puPipGetBuf(HANDLE PipServerPortHandle, PIPPACKHANDER PipBuffer)
{
	if (!PipServerPortHandle && !PipBuffer)
	{
		return -1;
	}

	DWORD dwRead = 0;
	DWORD dwAvail = 0;

	do
	{
		// PeekNamePipe用来预览一个管道中的数据，用来判断管道中是否为空
		if (!PeekNamedPipe((HANDLE)PipServerPortHandle, NULL, NULL, &dwRead, &dwAvail, NULL) || dwAvail <= 0)
		{
			continue;
		}
		if (ReadFile((HANDLE)PipServerPortHandle, PipBuffer, sizeof(IPPACKHANDER), &dwRead, NULL))
		{
			if (dwRead > 0)
				return 1;
			else
				return -2;
		}
	} while (TRUE);
}

HANDLE puPipInit(char* PipName)
{
	if (!PipName)
		return (HANDLE)-2;

	// Init Pip
	if (WaitNamedPipeA(PipName, NMPWAIT_WAIT_FOREVER) == false) {
		int error = GetLastError();
		return (HANDLE)-3;
	}

	HANDLE hPipe = CreateFileA(PipName, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (hPipe <= 0)
	{
		int error = GetLastError();
		return (HANDLE)-4;
	}
	else
		return hPipe;
}