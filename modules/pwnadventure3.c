#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "shackle.h"
#include "pwnadventure3.h"

FILE *packetCapture = NULL;

CRITICAL_SECTION packetCaptureSection = {0};

extern "C" __declspec(dllexport) unsigned long __stdcall newSend(unsigned long socket, char *buf, unsigned long len, unsigned long flags);
extern "C" __declspec(dllexport) unsigned long __stdcall newRecv(unsigned long socket, char *buf, unsigned long len, unsigned long flags);


extern "C" __declspec(dllexport) unsigned long __stdcall test0();
extern "C" __declspec(dllexport) unsigned long __stdcall test2(UINT_PTR a, UINT_PTR b);

extern "C" unsigned long __stdcall test0()
{
	OutputDebugString("test0: called\n");
	return 0;
}

extern "C" unsigned long __stdcall test2(UINT_PTR a, UINT_PTR b)
{
	char mbuf[1024];
	sprintf(mbuf,"test2: called. %p %p\n",(void *)a,(void *)b);
	OutputDebugString(mbuf);
	if(a == 0x1234 && b == 0x5678)
	{
		OutputDebugString("test2: unlocked.\n");
	}
	return 0;
}

typedef DWORD (WINAPI * _send) (DWORD, char *, DWORD, DWORD);
_send oldSend = NULL;
_send oldRecv = NULL;


HANDLE hPipe;

struct cmdbuf
{
	DWORD type;
	DWORD size;
};

struct cmdbuf crit_cmdbuf;
DWORD bytesWritten;

unsigned long reuse_socket = 0;

// doesn't give me the same calling convention =)
extern "C" unsigned long __stdcall newSend(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	if(len > 5)
	{
		if(buf[0] == 0x24 && buf[1] == 0x62)
		{
			buf[18] = 0xFF;
			buf[19] = 0xFF;
			buf[20] = 0xFF;
			buf[21] = 0xFF;
		}
	}
	int i = oldSend(socket, buf, len, flags);
	if(reuse_socket == 0)
	{
		reuse_socket = socket;
	}
	EnterCriticalSection(&packetCaptureSection);
	/*
	fwrite(&len,1,sizeof(unsigned long ),packetCapture);
	fwrite(buf,1,len,packetCapture);
	*/
	crit_cmdbuf.type = 5555;
	crit_cmdbuf.size = len;
	WriteFile(hPipe,&crit_cmdbuf,sizeof(cmdbuf),&bytesWritten,NULL);
	WriteFile(hPipe,buf,len,&bytesWritten,NULL);
	LeaveCriticalSection(&packetCaptureSection);
	return i;
}

extern "C" unsigned long __stdcall newRecv(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	int i = oldRecv(socket, buf, len, flags);
	EnterCriticalSection(&packetCaptureSection);
	/*
	fwrite(&len,1,sizeof(unsigned long ),packetCapture);
	fwrite(buf,1,len,packetCapture);
	*/
	crit_cmdbuf.type = 3333;
	crit_cmdbuf.size = len;
	WriteFile(hPipe,&crit_cmdbuf,sizeof(cmdbuf),&bytesWritten,NULL);
	WriteFile(hPipe,buf,len,&bytesWritten,NULL);
	LeaveCriticalSection(&packetCaptureSection);
	return i;
}


extern "C" void __stdcall callback(ULONG_PTR addr)
{
	if(oldSend == NULL)
	{
		OutputDebugString("Filling oldSend\n");
		oldSend = (_send )addr;
	}
	else{
		OutputDebugString("Filling oldRecv\n");
		oldRecv = (_send )addr;
	}
	return;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
	if(fdwReason == DLL_PROCESS_ATTACH)
    {	
		// packetCapture = fopen("c:\\projects\\capture.cap","wb");
		hPipe = hPipe = CreateFile("\\\\.\\pipe\\ipcutil",GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
		InitializeCriticalSection(&packetCaptureSection);
		OutputDebugString("pwnadventure3.dll loaded!\n");
		return TRUE;
	}
}

/*
void initializeHooks()
{
	OutputDebugString("ok!");
	//HANDLE cp = GetCurrentProcess();
	//HANDLE p = GetModuleHandle("ws2_32.dll");
	//MODULEINFO modInfo;
	
	packetCapture = fopen("c:\\projects\\capture.cap","wb");
	InitializeCriticalSection(&packetCaptureSection);
	// GetModuleInformation(cp,(HMODULE )p,&modInfo,sizeof(modInfo));
	hook((UINT_PTR )GetProcAddress(LoadLibrary("ws2_32.dll"),"send"),(UINT_PTR ) newSend, (UINT_PTR
	*)&oldSend);
	hook((UINT_PTR )GetProcAddress(LoadLibrary("ws2_32.dll"),"recv"),(UINT_PTR ) newRecv, (UINT_PTR *)&oldRecv);
}
*/