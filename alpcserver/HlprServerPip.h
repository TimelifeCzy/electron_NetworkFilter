#pragma once

class HlprServerPip
{
public:
	HlprServerPip();
	~HlprServerPip();

private:
	

public:
	int StartServerPip();
	int PipSendMsg(void* buf, const int bufLen);
	void PipClose();
};

