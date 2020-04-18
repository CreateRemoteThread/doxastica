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

#define FLAG_BEARS 1

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
			// buf[12] += 48;
			buf[12] = 1;
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

#define RECV_MK 0x6d6b
#define RECV_PS 0x7073

unsigned long RECV_STATE = 0;
unsigned long RECV_CTR = 0;

extern "C" unsigned long __stdcall newRecv(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	int i = oldRecv(socket,buf,len,flags);

	#ifndef FLAG_BEARS
	if(RECV_STATE == 0)
	{
		if(i == 2)
		{
			if(buf[0] == 'm' && buf[1] == 'k')
			{
				RECV_STATE = RECV_MK; // spawn items
				RECV_CTR = 9;
				OutputDebugString("RECV_MK\n");
			}
			else if(buf[0] == 'p' && buf[1] == 's')
			{
				RECV_STATE = RECV_PS; // position chang
				RECV_CTR = 4;
				OutputDebugString("RECV_PS\n");
			}
		}
	}
	else if(RECV_STATE == RECV_MK)
	{
		if(RECV_CTR == 5)
		{
			if(i != 4 && i != 9)
			{
				RECV_STATE = 0;
				RECV_CTR = 0;
				OutputDebugString("Not a bear, any bear... (RECV_MK, RECV_CTR 5, packet size)\n");
			}
			
			if(i == 4)
			{
				if(buf[0] == 'B' && buf[1] == 'e' && buf[2] == 'a' && buf[3] == 'r')
				{
					RECV_CTR -= 1;
				}
				else
				{
					
					RECV_STATE = 0;
					RECV_CTR = 0;
					OutputDebugString("Not a Bear (RECV_MK, RECV_CTR 5, data)\n");
				}
			}
			else if(i == 9)
			{
				if(memcmp("AngryBear",buf,9) == 0)
				{
					RECV_CTR -= 1;
				}
				else
				{
					RECV_STATE = 0;
					RECV_CTR = 0;
					OutputDebugString("Not an AngryBear (RECV_MK, RECV_CTR 5, data)\n");
				}
			}
			
		}
		else if(RECV_CTR == 4 || RECV_CTR == 3 || RECV_CTR == 2)
		{
			if(i == 4)
			{
				buf[0] = '\xFF';
				buf[1] = '\xFF';
				buf[2] = '\xFF';
				buf[3] = '\xFF';
				OutputDebugString("patching spawn loc\n");
				RECV_CTR -= 1;
			}
			else
			{
				RECV_CTR = 0;
			}
		}
		else
		{
			RECV_CTR -= 1;
		}
	}
	else if(RECV_STATE == RECV_PS)
	{
		if(RECV_CTR == 3 || RECV_CTR == 2 || RECV_CTR == 1)
		{
			if(i == 4)
			{
				buf[0] = '\x00';
				buf[1] = '\x00';
				buf[2] = '\x00';
				buf[3] = '\x00';
				OutputDebugString("patching move loc\n");
				RECV_CTR -= 1;
			}
			else
			{
				RECV_CTR = 0;
			}
			// RECV_CTR -= 1;
		}
		else
		{
			RECV_CTR -= 1;
			
		}
	}
	
	if(RECV_CTR == 0)
	{
		RECV_STATE = 0;
	}
	#endif
	
	finito:;
	EnterCriticalSection(&packetCaptureSection);
	crit_cmdbuf.type = 3333;
	crit_cmdbuf.size = len;
	WriteFile(hPipe,&crit_cmdbuf,sizeof(cmdbuf),&bytesWritten,NULL);
	WriteFile(hPipe,buf,len,&bytesWritten,NULL);
	LeaveCriticalSection(&packetCaptureSection);
	return len;
}

unsigned long lastSocket;
int readHead;
int packetSize;
char iobuf[50240];

extern "C" unsigned long __stdcall BACKUP_newRecv(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	if(lastSocket == 0)
	{
		lastSocket = socket;
	}
	if(lastSocket != socket)
	{
		if(readHead != packetSize)
		{
			OutputDebugString("orphan packet...\n");
			__asm{
				int 3
			}
		}
		else
		{
			lastSocket = socket;
		}
	}
	
	int i = 0;
	if(packetSize == readHead)
	{
		packetSize = oldRecv(socket,iobuf,50240,flags);
			
		readHead = 0;
		EnterCriticalSection(&packetCaptureSection);
		crit_cmdbuf.type = 3333;
		crit_cmdbuf.size = packetSize;
		WriteFile(hPipe,&crit_cmdbuf,sizeof(cmdbuf),&bytesWritten,NULL);
		WriteFile(hPipe,iobuf,packetSize,&bytesWritten,NULL);
		LeaveCriticalSection(&packetCaptureSection);
		
		if(packetSize <= len)
		{
			packetSize = 0;
			memcpy(buf,iobuf,packetSize);
			return packetSize;
		}
		else
		{	
			memcpy(buf,iobuf,len);
			readHead = len;
			return len;
		}
	}
	else
	{
		if(readHead + len <= packetSize)
		{
			for(i = 0;i < len;i++)
			{
				buf[i] = iobuf[readHead++];
			}
			return len;
		}
		else
		{
			for(i = 0;readHead + i < packetSize;i++)
			{
				buf[i] = iobuf[readHead++];
			}
			return i;
		}
	}
	
	
	return len;
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
