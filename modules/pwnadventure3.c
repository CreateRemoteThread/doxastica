#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
extern "C"{
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}
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

extern "C" __declspec(dllexport) unsigned long __stdcall proxySend(unsigned long *buf, unsigned long len);

extern "C" __declspec(dllexport) UINT_PTR __stdcall getSaveAddr();
extern "C" __declspec(dllexport) void __stdcall lockLocation(int yesno);

unsigned long IClientWorld = 0;

extern "C" UINT_PTR __stdcall getSaveAddr()
{
	return (UINT_PTR )(&IClientWorld);
}

typedef DWORD (WINAPI * _send) (DWORD, char *, DWORD, DWORD);
_send oldSend = NULL;
_send oldRecv = NULL;

unsigned long lastSock = 0;

extern "C" unsigned long __stdcall proxySend(unsigned long *buf, unsigned long len)
{
	OutputDebugString("proxySend called...\n");
	if(lastSock != 0)
	{
		int i = oldSend(lastSock, (char *)buf, len, 0);
		return i;
	}
	return 0;
}

extern "C" unsigned long __stdcall test0()
{
	OutputDebugString("test0: called\n");
	return 0;
}

extern "C" unsigned long __stdcall test2(UINT_PTR a, UINT_PTR b)
{
	char mbuf[1024];
	__asm{
			int 3
		};
	sprintf(mbuf,"test2: called. %p %p\n",(void *)a,(void *)b);
	OutputDebugString(mbuf);
	if(a == 0x1234 && b == 0x5678)
	{
		
		OutputDebugString("test2: unlocked.\n");
	}
	return 0;
}

HANDLE hPipe;

struct cmdbuf
{
	DWORD type;
	DWORD size;
};

struct cmdbuf crit_cmdbuf;
DWORD bytesWritten;

unsigned long reuse_socket = 0;

int lockZ = 0;
typedef struct{
	float x;
	float y;
	float z;
}Vector3;

Vector3 playerloc;

extern "C" void __stdcall lockLocation(int yesno)
{
	lockZ = yesno;
	return;
}

// doesn't give me the same calling convention =)
extern "C" unsigned long __stdcall newSend(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	
	if(buf[0] == 0x2a)
	{
		lastSock = socket;
	}
	if(buf[0] == 0x6d && buf[1] == 0x76)
	{
		// 6d 76 d8 59 40 c6 57 cb 0c 47 b5 b2 b6 44 65 0e d4 ed 00 00 00 00
		// xx xx 11 11 11 11 22 22 22 22 33 33 33 33 44 44 44 44
		if(lockZ != 0)
		{
			buf[12] += a5;
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

extern "C" void __stdcall patchIPlayerObject()
{
	if(IClientWorld == 0)
	{
		return;
	}
	else
	{
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
