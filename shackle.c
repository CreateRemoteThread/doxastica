#include <stdio.h>
#include <windows.h>
#include "beaengine\beaengine.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdlib.h>

// switched to beaengine for 64-bit support

#ifdef ARCHI_64
	#define ARCHI 64
	#define PC_REG Rip
	#define REGISTER_LENGTH DWORD64
	#define FUNCTION_PATCHLEN 14
	#define FUNCTION_SHORTPATCH_HACK 5
	#define INTEL_MAXINSTRLEN 15
	#define FUNCTION_TAILLEN 14
#else
	#define ARCHI 32
	#define PC_REG Eip
	#define REGISTER_LENGTH DWORD
	#define FUNCTION_PATCHLEN 6
	#define FUNCTION_SHORTPATCH_HACK 5
	#define INTEL_MAXINSTRLEN 15
	#define FUNCTION_TAILLEN 7
#endif

#define MANUAL_FUNCTION_PRELUDE 1

int init = 0;

typedef DWORD (WINAPI * _MessageBoxA) (DWORD, LPCVOID, LPCVOID, DWORD);
typedef DWORD (WINAPI * _send) (DWORD, char *, DWORD, DWORD);
void hook(UINT_PTR addressFrom, UINT_PTR addressTo, UINT_PTR *saveAddress);
UINT_PTR searchForShortCave(UINT_PTR addressFrom,int minLength);
DWORD WINAPI IPCServerThread( LPVOID lpParam );
DWORD WINAPI IPCServerInstance(LPVOID lpvParam);
void processCommand(char *pchRequest, char *pchReply);

_MessageBoxA oldMessageBox = NULL;
_send oldSend = NULL;
_send oldRecv = NULL;

/*
// okay, what's the function prelude of newmessagebox?
u $ip
shackle64!newMessageBox+0xd [c:\projects\elegurawolfe\shackle.c @ 43]:
00000001`8000100d c60061          mov     byte ptr [rax],61h
00000001`80001010 ff1512360400    call    qword ptr [shackle64!oldMessageBox (00000001`80044628)]
00000001`80001016 33c0            xor     eax,eax
00000001`80001018 4883c428        add     rsp,28h
00000001`8000101c c3              ret

// where does oldMessageBox point? this should be our function prelude
// that we control
0:000> dq 00000001`80044628
00000001`80044628  00000000`00300000 00000000`00000000
00000001`80044638  00000000`00000000 00000000`00000001
00000001`80044648  00000000`00000000 00000000`00000000
00000001`80044658  00000000`00000000 00380c33`da800000
00000001`80044668  00000001`00000000 00000000`01ce5c50
00000001`80044678  00000000`00000000 00000000`01ce5c90
00000001`80044688  00000000`00000000 00000000`00000000
00000001`80044698  00000000`00000000 00000001`80044f70

// this should be our function prelude
// but it looks broken as shit. this SHOULD be:
u 00000000`00300000
00000000`00300000 4883ec38        sub     rsp,38h
00000000`00300004 4533db          xor     r11d,r11d
00000000`00300007 44391dea0d0200  cmp     dword ptr [00000000`00320df8],r11d [ this one fucks us because it's a relative ]
00000000`0030000e ff2500000000    jmp     qword ptr [00000000`00300014]
00000000`00300014 52              push    rdx                           [ SHOULD BE QWORD READ AS DATA ]
00000000`00300015 139177000000    adc     edx,dword ptr [rcx+77h]
00000000`0030001b 0000            add     byte ptr [rax],al
00000000`0030001d 0000            add     byte ptr [rax],al

untouched user32!MessageBoxA:
00000000`77911344 4883ec38        sub     rsp,38h
00000000`77911348 4533db          xor     r11d,r11d
00000000`7791134b 44391dea0d0200  cmp     dword ptr [USER32!gapfnScSendMessage+0x927c (00000000`7793213c)],r11d
*/


#define CL_ON_64BIT_IS_A_PIECE_OF_SHIT 1

lua_State *lua = NULL;

unsigned long WINAPI newMessageBox(unsigned long hwnd,char *msg,char *title,unsigned long flags)
{
	/*
	#ifdef CL_ON_64BIT_IS_A_PIECE_OF_SHIT
		char *p = (char *)0;
		p[0] = 'a';
	#endif
	*/
	oldMessageBox(hwnd,"NERDZ",title,flags);
	return 0;
}

unsigned long newSend(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	int i = oldSend(socket, buf, len, flags);
	OutputDebugString("send\n");
	return i;
}

unsigned long newRecv(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	int i = oldRecv(socket,buf,len,flags);
	OutputDebugString("recv\n");
	return i;
}

// dirty hack we use to enable short patching on 64-bit
// search from the addressFromto an address with "\XC3

UINT_PTR searchForShortCave(UINT_PTR addressFrom,int minLength)
{
	unsigned int maxSearchLen = 10000;
	unsigned int i = 0, n = 0;
	unsigned char *p = (unsigned char *)addressFrom;
	UINT_PTR foundAddress = 0;
	char *mbuf = (char *)malloc(1024);
	// memset(mbuf,0,1024);
	OutputDebugString("searching for short cave\n");
	for( i = 0; i < maxSearchLen;i++)
	{
		/*
		sprintf(mbuf,"[%02x]\00",(unsigned char )p[i]);
		if( i % 16 == 0)
		{
			OutputDebugString("\n");
		}
		*/
		OutputDebugString(mbuf);
		if ((unsigned char )p[i] == (unsigned char )'\xC3')
		{
			// OutputDebugString("\n ---- FOUND ---- \n");
			foundAddress = (UINT_PTR )(p + i + 1);
			for(n = 1;n < minLength;n++)
			{
				if ( (p[i+n] != (unsigned char )'\xCC' ) && (p[i+n] != (unsigned char )'\x00') && (p[i+n] != (unsigned char )'\x90') )
				{
					memset(mbuf,0,1024);
					sprintf(mbuf," exiting search for loop at %x, [%02x]\n" , (UINT_PTR )(p + i + n), (unsigned char )(p[i+n]));
					OutputDebugString(mbuf);
					foundAddress = 0;
				}
			}
			if(foundAddress)
			{
				// OutputDebugString("\n + FOUND \n");
				return (UINT_PTR )(p + i + 1);
			}
		}
	}
	return foundAddress;
}

void hook(UINT_PTR addressFrom, UINT_PTR addressTo, UINT_PTR *saveAddress)
{
	DWORD oldProtect = 0;
	int totalSize = 0;
	DISASM *d = (DISASM *)malloc(sizeof(DISASM));
	
	memset(d,0,sizeof(DISASM));
	d->Archi = ARCHI;
	d->EIP = (UIntPtr )addressFrom;
	totalSize += Disasm(d);

	int shortCutSize = 0;
	shortCutSize = totalSize;
	
	char *mbuf = (char *)VirtualAlloc(NULL,1024,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
	while(totalSize < FUNCTION_PATCHLEN)
	{
		d->EIP = (UIntPtr )(addressFrom + totalSize);
		totalSize += Disasm(d);
		if (shortCutSize < FUNCTION_SHORTPATCH_HACK)
		{
			shortCutSize = totalSize;
		}
	}

	//memset(mbuf,0,1024);
	//sprintf(mbuf," TRYING TO PATCH %x to %x, allocating total len of %d, closest cave %x (searching for cave size %d)\n", addressFrom,addressTo,totalSize, shortCaveAddr, shortCutSize);
	//OutputDebugString(mbuf);

	char *codeCave = (char *)VirtualAlloc(NULL,totalSize + FUNCTION_TAILLEN,MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD unused;
	VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_READWRITE,&oldProtect);

	// what the fuck was i smoking when i wrote this shit and left it in
	// let's virtualprotect right after i virtualprojtect
	// fucking a you imbecile
	// VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_READWRITE,&unused);\

	UINT_PTR shortCaveAddr = searchForShortCave(addressFrom,14);
	if (shortCaveAddr != 0)
	{
		totalSize = shortCutSize;
	}

	memset(codeCave,'\xCC',totalSize);
	memcpy(codeCave,(LPVOID )addressFrom,totalSize);

	#if ARCHI == 32
		codeCave[totalSize] = '\xE9';
		DWORD *cp = (DWORD *)((unsigned long )codeCave + totalSize + 1);
		cp[0] = (unsigned long )(addressFrom + totalSize - ((unsigned long )codeCave + totalSize + 5));
		saveAddress[0] = (unsigned long )codeCave;
		VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_EXECUTE_READ,&unused);
	#else
		codeCave[totalSize] = '\xFF';              // jmp [rip+0]
		codeCave[totalSize + 1] = '\x25';          // or if your name is nasm
		codeCave[totalSize + 2] = '\x00';          // jmp qword [rel $+0x0] then disasm / edit
		codeCave[totalSize + 3] = '\x00';
		codeCave[totalSize + 4] = '\x00';
		codeCave[totalSize + 5] = '\x00';
		UINT_PTR *cp = (UINT_PTR *)(codeCave + totalSize + 6);
		cp[0] = (UINT_PTR )(addressFrom + totalSize); // no need for shitlording with relative addr here
		saveAddress[0] = (UINT_PTR )codeCave;
		VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_EXECUTE_READ,&unused);
	#endif

	VirtualProtect((LPVOID )addressFrom,FUNCTION_PATCHLEN,PAGE_READWRITE,&oldProtect);
	memset((void *)addressFrom,'\xCC',totalSize);

	char *addressFromWrite = (char *)(addressFrom);

	#if ARCHI == 32
		addressFromWrite[0] = '\xE9';
		DWORD *p =  (DWORD *)((unsigned long ) addressFromWrite + 1 );
		p[0] = (DWORD )(addressTo - ((unsigned long ) addressFrom   + 5));
		VirtualProtect((LPVOID )addressFrom,7,oldProtect,&unused);
	#else
		// on 64-bit systems, search for a 14-byte cave we can jmp to within 0xFFFF
		// this way, we destroy only 5 bytes of the original prelude
		// greatly reducing our chances of fucking shit up.
		
		UINT_PTR *p = 0;

		if (shortCaveAddr != 0)
		{
			// stage 1 trampoline - E9 shortcaveaddr
			// assume this is executable for now, fix this later.
			addressFromWrite[0] = '\xE9';
			DWORD *p1 = (DWORD *)(addressFrom + 1);
			p1[0] = (DWORD )((UINT_PTR )shortCaveAddr - (UINT_PTR )addressFromWrite);
			p1[0] -= 5; // offset of current 5-byte instruction =)
			// stage 2 trampoline - JMP [RIP+0] DQ [absolute oldMessageBoxA]
			unsigned char *shortCaveAddrWrite = (unsigned char *)shortCaveAddr;
			VirtualProtect((LPVOID )shortCaveAddr,FUNCTION_PATCHLEN,PAGE_READWRITE,&unused);
			shortCaveAddrWrite[0] = '\xFF';
			shortCaveAddrWrite[1] = '\x25';
			shortCaveAddrWrite[2] = '\x00';
			shortCaveAddrWrite[3] = '\x00';
			shortCaveAddrWrite[4] = '\x00';
			shortCaveAddrWrite[5] = '\x00';
			p = (UINT_PTR *)(shortCaveAddr + 6);
			p[0] = (UINT_PTR )(addressTo);
			VirtualProtect((LPVOID )shortCaveAddr,FUNCTION_PATCHLEN,PAGE_EXECUTE_READ,&unused);
			VirtualProtect((LPVOID )addressFrom,FUNCTION_PATCHLEN,oldProtect,&unused);
		}
		else
		{
			addressFromWrite[0] = '\xFF';
			addressFromWrite[1] = '\x25';
			addressFromWrite[2] = '\x00';
			addressFromWrite[3] = '\x00';
			addressFromWrite[4] = '\x00';
			addressFromWrite[5] = '\x00';
			p = (UINT_PTR *)(addressFrom + 6);
			p[0] = (UINT_PTR )(addressTo);
			VirtualProtect((LPVOID )addressFrom,14,oldProtect,&unused);
		}
	#endif

	/*

	  hook structure:
	  hookFrom: E9 addressTo
	  addressTo: our function
	  codeCave is the new function
	*/

	memset(mbuf,0,1024);
	#if ARCHI == 32
	sprintf(mbuf,"* [32-BIT] [0x%x] HOOKED %02x %02x%02x%02x%02x (0x%x)\n",(UINT_PTR )addressFrom,
													(unsigned char )addressFromWrite[0],
													(unsigned char )addressFromWrite[1],
													(unsigned char )addressFromWrite[2],
													(unsigned char )addressFromWrite[3],
													(unsigned char )addressFromWrite[4],
													(UINT_PTR )addressTo);
	#else
	if(shortCaveAddr != 0)
	{
		sprintf(mbuf,"* [64-BIT] [0x%x] %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x (0x%x)\n",(UINT_PTR )addressFrom,
													(unsigned char )addressFromWrite[0],
													(unsigned char )addressFromWrite[1],
													(unsigned char )addressFromWrite[2],
													(unsigned char )addressFromWrite[3],
													(unsigned char )addressFromWrite[4],
													(unsigned char )addressFromWrite[5], // PATCH GOES HERE
													(unsigned char )addressFromWrite[6],
													(unsigned char )addressFromWrite[7],
													(unsigned char )addressFromWrite[8],
													(unsigned char )addressFromWrite[9],
													(unsigned char )addressFromWrite[10],
													(unsigned char )addressFromWrite[12],
													(unsigned char )addressFromWrite[13],
													(unsigned char )addressFromWrite[14],
													(UINT_PTR )addressTo);
	}
	else
	{
		sprintf(mbuf,"* [64-BIT] [0x%x] HOOKED-SHORTCAVE %02x %02x%02x%02x%02x (0x%x)\n",(UINT_PTR )addressFrom,
													(unsigned char )addressFromWrite[0],
													(unsigned char )addressFromWrite[1],
													(unsigned char )addressFromWrite[2],
													(unsigned char )addressFromWrite[3],
													(unsigned char )addressFromWrite[4],
													(UINT_PTR )shortCaveAddr);
	}
	#endif
	OutputDebugString(mbuf);

	VirtualFree(mbuf,0,MEM_RELEASE);

	return;
}


DWORD threadId = 0;

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH && init == 0)
      {
        init = 1;
		OutputDebugString(" - shackle dll loaded\n");
		CreateThread(NULL,0,IPCServerThread,NULL,0,&threadId);
		
		return TRUE;
      }
  return TRUE;
}

DWORD WINAPI IPCServerThread( LPVOID lpParam ) 
{
	char *mbuf = (char *)malloc(1024);
	char *pipeName = (char *)malloc(1024);
	// cuz im a hipster too
	for(;;)
	{
		BOOL   fConnected = FALSE; 
		DWORD  dwThreadId = 0; 
		HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL; 

		memset(pipeName,0,1024);
		sprintf(pipeName,"\\\\.\\pipe\\shackle-%d",GetCurrentProcessId());
		hPipe = CreateNamedPipe(pipeName,PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024,1024, 0 , NULL);
		if (hPipe == INVALID_HANDLE_VALUE)
		{
			memset(mbuf,0,1024);
			sprintf(mbuf," CreateNamedPipe failed, GLE = %d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}

		fConnected = ConnectNamedPipe(hPipe,NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		if (fConnected)
		{
			hThread = CreateThread( NULL, 0, IPCServerInstance, (LPVOID) hPipe, 0, &dwThreadId);
			if (hThread == NULL)
			{
				memset(mbuf,0,1024);
				sprintf(mbuf," CreateThread (listener instance) failed, GLE = %d\n",GetLastError());
				OutputDebugString(mbuf);
				break;
			}
			else
			{
				// don't need to track this.
				CloseHandle(hThread);
			}
		}
		else
		{
			CloseHandle(hPipe);
		}
	}
	free(pipeName);
	free(mbuf);
	return 0;
}

DWORD WINAPI IPCServerInstance(LPVOID lpvParam)
{
	char *pchRequest = (char *)malloc(1024);
	char *pchReply = (char *)malloc(1024);
	char *mbuf = (char *)malloc(1024);
	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;
	HANDLE hPipe = (HANDLE )lpvParam;

	OutputDebugString(" - IPC Server Instance created\n");

	while(1)
	{
		fSuccess = ReadFile(hPipe,pchRequest,1024,&cbBytesRead,NULL);
		if (!fSuccess || cbBytesRead == 0)
		{
			sprintf(mbuf," [ERR] read failed, gle=%d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}
		
		memset(pchReply,0,1024);
		processCommand(pchRequest,pchReply);
		cbReplyBytes = strlen(pchReply) + 1;

		fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
		if (!fSuccess || cbReplyBytes != cbWritten)
		{
			sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}
	}

	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	free(mbuf);
	free(pchRequest);
	free(pchReply);
	return 1;
}

/*
	just pass things to the lua engine :D
*/
void processCommand(char *pchRequest, char *pchReply)
{
	
	return;
}
