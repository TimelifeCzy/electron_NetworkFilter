#pragma once
extern "C"
{
	typedef struct _IPPACKHADNER
	{
		// UNIVERMSG univermsg;	// ALL Port Analys MSG
		ULONG localaddr;
		long localport;
		ULONG remoteaddr;
		long remoteport;
		unsigned short protocol;
		int pid;
	}IPPACKHANDER, *PIPPACKHANDER;

	/*
		@ puLoadDriver: 加载驱动
		@ drivername: 驱动绝对路径
		@ dirverstatus: 驱动加载状态
	*/
	__declspec(dllexport) int puLoadDriver(const char* drivername, const int nstatus);
	/*
		@ puUninstallDriver: 卸载驱动
		@ drivername: 驱动绝对路径
	*/
	__declspec(dllexport) int puUninstallDriver(const char* drivername);
	/*
		@ pugetDriverStatus: 获取当前驱动状态
		@ drivername: 驱动绝对路径
	*/
	__declspec(dllexport) int puGetDriverStatus(const char* drivername);
	/*
		@ puStopDriverStatus: 停止驱动
		@ drivername: 驱动绝对路径
	*/
	__declspec(dllexport) int puStopDriverStatus(const char* drivername);
	/*
		@ puControlCodeSend: 发送控制码
		@ drivername: 驱动绝对路径
	*/
	__declspec(dllexport) int puControlCodeSend(const long long driverhandle, const int controlcode);

	__declspec(dllexport) int puPipGetBuf(HANDLE PipServerPortHandle, PIPPACKHANDER PipBuffer);

	__declspec(dllexport) HANDLE puPipInit(char* PipName);

}
