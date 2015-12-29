#include <stdio.h>
#include <windows.h>
#include "beaengine\beaengine.h"

// switched to beaengine for 64-bit support

#ifdef ARCHI_64
	#define ARCHI 64
	#define PC_REG Rip
	#define REGISTER_LENGTH DWORD64
#else
	#define ARCHI 32
	#define PC_REG Eip
	#define REGISTER_LENGTH DWORD
#endif

#define MANUAL_FUNCTION_PRELUDE 1

int init = 0;

typedef DWORD (WINAPI * _MessageBoxA) (DWORD, LPCVOID, LPCVOID, DWORD);
typedef DWORD (WINAPI * _send) (DWORD, char *, DWORD, DWORD);
void hook(char *addressFrom, char *addressTo, unsigned long *saveAddress);

_MessageBoxA oldMessageBox = NULL;
_send oldSend = NULL;
_send oldRecv = NULL;

unsigned long WINAPI newMessageBox(unsigned long hwnd,char *msg,char *title,unsigned long flags)
{
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

#define FUNCTION_PATCHLEN 6
#define INTEL_MAXINSTRLEN 15
#define FUNCTION_TAILLEN 7

// 32-bit into 32-bit, 64-bit into 64-bit.

void hook(char *addressFrom, char *addressTo, unsigned long *saveAddress)
{
	DWORD oldProtect = 0;
	int totalSize = 0;
	DISASM *d = (DISASM *)malloc(sizeof(DISASM));
	
	memset(d,0,sizeof(DISASM));
	d->Archi = ARCHI;
	d->EIP = (UIntPtr )addressFrom;
	totalSize += Disasm(d);

	while(totalSize < FUNCTION_PATCHLEN)
	{
		d->EIP = (UIntPtr )(addressFrom + totalSize);
		totalSize += Disasm(d);
	}
	
	char *mbuf = (char *)VirtualAlloc(NULL,1024,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
	char *codeCave = (char *)VirtualAlloc(NULL,totalSize + FUNCTION_TAILLEN,MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD unused;
	VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_READWRITE,&oldProtect);

	VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_READWRITE,&unused);
	memset(codeCave,'\xCC',totalSize);
	memcpy(codeCave,addressFrom,totalSize);
	codeCave[totalSize] = '\xE9';
	DWORD *cp = (DWORD *)((unsigned long )codeCave + totalSize + 1);
	cp[0] = (unsigned long )(addressFrom + totalSize - ((unsigned long )codeCave + totalSize + 5));
	saveAddress[0] = (unsigned long )codeCave;
	VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_EXECUTE_READ,&unused);

	VirtualProtect(addressFrom,7,PAGE_READWRITE,&oldProtect);
	memset(addressFrom,'\xCC',totalSize);

	addressFrom[0] = '\xE9';
	DWORD *p =  (DWORD *)((unsigned long ) addressFrom + 1 );
	p[0] = (DWORD )(addressTo - ((unsigned long ) addressFrom   + 5));
	VirtualProtect(addressFrom,7,oldProtect,&unused);

	/*

	  hook structure:
	  hookFrom: E9 addressTo
	  addressTo: our function
	  codeCave is the new function	  

	*/

	memset(mbuf,0,1024);
	sprintf(mbuf,"* [%08x] %02x %02x%02x%02x%02x (%08x)\n",(unsigned long )addressFrom,
													(unsigned char )addressFrom[0],
													(unsigned char )addressFrom[1],
													(unsigned char )addressFrom[2],
													(unsigned char )addressFrom[3],
													(unsigned char )addressFrom[4],
													(unsigned long )addressTo);
	OutputDebugString(mbuf);

	VirtualFree(mbuf,0,MEM_RELEASE);

	return;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH && init == 0)
      {
        init = 1;
		OutputDebugString("SUCCESS\n");
		hook((char *)(GetProcAddress(LoadLibrary("user32"),"MessageBoxA")),(char *)&newMessageBox,(unsigned long *)&oldMessageBox);
		return TRUE;
      }
  return TRUE;
}
