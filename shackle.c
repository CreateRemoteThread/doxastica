#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include "beaengine\beaengine.h"
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <signal.h>
#include <imagehlp.h>
#include <ctype.h>
#include <winnt.h>
#include "shackle.h"
#include "search.h"
#include "ptrscan.h"
#include "pcontrol.h"
#include "vtable.h"
#include "wincrypt.h"
#include "lua_socket.h"
#include "magicmirror.h"
#include "darksign.h"
#include "xedparse\src\XEDParse.h"

FILE _iob[] = {*stdin, *stdout, *stderr};

extern "C" FILE * __cdecl __iob_func(void)
{
    return _iob;
}

#define WIN32_LEAN_AND_MEAN

#define EOFMARK		"<eof>"
#define marklen		(sizeof(EOFMARK)/sizeof(char) - 1)

void printShortResults(HANDLE hPipe,lua_State *L,searchResult *m);

#define VERSTRING "[v0p2 anarchy's heart]"

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
typedef DWORD (WINAPI * _WSASend) (SOCKET, UINT_PTR, DWORD, UINT_PTR, DWORD, UINT_PTR, UINT_PTR);

/*
BOOL CryptEncrypt(
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen,
  DWORD      dwBufLen
);
*/
typedef DWORD (WINAPI * _CryptEncrypt) (HCRYPTKEY , HCRYPTHASH, BOOL,DWORD,BYTE *, DWORD *,DWORD);
typedef DWORD (WINAPI * _CryptDecrypt) (HCRYPTKEY , HCRYPTHASH, BOOL,DWORD,BYTE *, DWORD *,DWORD);

/*
BOOL RSAENH_CPDecrypt
 (
  HCRYPTPROV hProv,
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE*      pbData,
  DWORD*     pdwDataLen
 )
*/

/*
typedef int _PyRun_SimpleString (char *);

_PyRun_SimpleString real_PyRun_SimpleString = NULL;
*/
 
_MessageBoxA oldMessageBox = NULL;
_send oldSend = NULL;
_send oldRecv = NULL;
_CryptEncrypt oldCryptEncrypt = NULL;
_CryptDecrypt oldCryptDecrypt = NULL;
_WSASend oldWSASend = NULL;

char *globalHotkeyArray[256];
int globalSleepTime = 500;

CRITICAL_SECTION packetCaptureSection = {0};
FILE *packetCapture = NULL;

HANDLE hPacketCapture_ENCRYPT = NULL;
HANDLE hPacketCapture_DECRYPT = NULL;

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

#define LUA_MAXINPUT		512

int WINAPI newWSASend(SOCKET s, UINT_PTR lpBuffers, DWORD dwBufferCount, UINT_PTR lpBytesSent, DWORD dwFlags, UINT_PTR lpOverlapped, UINT_PTR lpCompletionRoutine)
{
	OutputDebugString("WSA Send Hook\n");
	return oldWSASend(s,lpBuffers,dwBufferCount,lpBytesSent,dwFlags,lpOverlapped,lpCompletionRoutine);
}

unsigned long WINAPI newMessageBox(unsigned long hwnd,char *msg,char *title,unsigned long flags)
{
	oldMessageBox(hwnd,msg,title,flags);
	return 0;
}

extern "C" __declspec(dllexport) unsigned long __stdcall newSend(unsigned long socket, char *buf, unsigned long len, unsigned long flags);
extern "C" __declspec(dllexport) unsigned long __stdcall newRecv(unsigned long socket, char *buf, unsigned long len, unsigned long flags);

// doesn't give me the same calling convention =)
extern "C" unsigned long __stdcall newSend(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	int i = oldSend(socket, buf, len, flags);
	EnterCriticalSection(&packetCaptureSection);
	fwrite(&len,1,sizeof(unsigned long ),packetCapture);
	fwrite(buf,1,len,packetCapture);
	LeaveCriticalSection(&packetCaptureSection);
	return i;
}

extern "C" unsigned long __stdcall newRecv(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	int i = oldRecv(socket, buf, len, flags);
	EnterCriticalSection(&packetCaptureSection);
	fwrite(&len,1,sizeof(unsigned long ),packetCapture);
	fwrite(buf,1,len,packetCapture);
	LeaveCriticalSection(&packetCaptureSection);
	return i;
}

int keyExported = 0;

#ifdef INCLUDE_NEWCRYPT
extern "C" __declspec(dllexport) BOOL __stdcall newCryptEncrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL final, DWORD flags, BYTE *buf, DWORD *buflen,DWORD dwBufLen);
extern "C" BOOL __stdcall newCryptEncrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL final, DWORD flags, BYTE *buf, DWORD *buflen,DWORD dwBufLen)
{
	DWORD fuckX;
	EnterCriticalSection(&packetCaptureSection);
	WriteFile(hPacketCapture_ENCRYPT,buflen,4,&fuckX,NULL); // now goes over named pipe
	WriteFile(hPacketCapture_ENCRYPT,buf,buflen[0],&fuckX,NULL);
	if(keyExported == 0)
	{
		keyExported = 1;
		
	}
	LeaveCriticalSection(&packetCaptureSection);
	
	BOOL b = oldCryptEncrypt(key,hash,final,flags,buf,buflen,dwBufLen);
	return b;
}

char *keyBlob;
DWORD keyBlobLen = 1024;

extern "C" __declspec(dllexport) BOOL __stdcall newCryptDecrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL final, DWORD flags, BYTE *buf, DWORD *buflen,DWORD dwBufLen);
extern "C" BOOL __stdcall newCryptDecrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL final, DWORD flags, BYTE *buf, DWORD *buflen,DWORD dwBufLen)
{
	DWORD fuckX;
	BOOL b = oldCryptDecrypt(key,hash,final,flags,buf,buflen,dwBufLen);
	EnterCriticalSection(&packetCaptureSection);
	WriteFile(hPacketCapture_DECRYPT,buflen,4,&fuckX,NULL); // now goes over named pipe
	WriteFile(hPacketCapture_DECRYPT,buf,buflen[0],&fuckX,NULL);
	LeaveCriticalSection(&packetCaptureSection);
	if(keyExported == 0)
	{
		HCRYPTPROV hProv = 0;
		HCRYPTKEY hExchangeKeyPair = 0;
		keyExported = 1;
		keyBlob = (char *)malloc(1024);
		
		/*
		0:000:x86> dd esp
		008ff0d0  67a4c46f 67c7fc08 00000000 67bf2554
		008ff0e0  00000001 f0000000 68043a30 67c7c4c8
		008ff0f0  00000000 00000028 77773779 07c19507
		008ff100  009e0000 00000028 008ff360 00000028
		008ff110  008ff368 00000150 777723b0 00000119
		008ff120  00000088 02b1e6c8 fffffeb0 00000009
		008ff130  fffffee7 009e04b8 00000ea0 06040002
		008ff140  00000000 a90400ad 009e0270 00000003
		0:000:x86> db 67bf2554
		67bf2554  4d 69 63 72 6f 73 6f 66-74 20 45 6e 68 61 6e 63  Microsoft Enhanc
		67bf2564  65 64 20 43 72 79 70 74-6f 67 72 61 70 68 69 63  ed Cryptographic
		67bf2574  20 50 72 6f 76 69 64 65-72 20 76 31 2e 30 00 00   Provider v1.0..
		67bf2584  00 00 00 00 00 00 00 00-73 23 69 3a 43 72 79 70  ........s#i:Cryp
		67bf2594  74 42 69 6e 61 72 79 54-6f 53 74 72 69 6e 67 00  tBinaryToString.
		67bf25a4  00 00 00 00 4e 69 69 00-73 69 3a 43 72 79 70 74  ....Nii.si:Crypt
		67bf25b4  53 74 72 69 6e 67 54 6f-42 69 6e 61 72 79 00 00  StringToBinary..
		67bf25c4  00 00 00 00 73 23 7c 69-00 00 00 00 43 72 79 70  ....s#|i....Cryp
		*/
		
		if(!CryptAcquireContext( &hProv, NULL, NULL, PROV_RSA_FULL, 0))
		{
			MessageBox(0,"Cannot acquire crypto context","fuck",MB_OK);
			return b;
		}
		
		CryptGetUserKey( hProv, AT_KEYEXCHANGE, &hExchangeKeyPair);
		
		if(CryptExportKey(key,0,7,0,(BYTE *)keyBlob,&keyBlobLen) != 0)
		{
			MessageBox(0,"GOT KEY!","GOT KEY!",MB_OK);

			HANDLE keyDump = CreateFile("c:\\projects\\KEYBLOB.bin",GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
			WriteFile(keyDump,keyBlob,keyBlobLen,&fuckX,NULL);
			CloseHandle(keyDump);
		}
		else
		{
			MessageBox(0,"NO KEY!","NO KEY!",MB_OK);
			return b;
		}
	}

	return b;
}
#endif

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
		// OutputDebugString(mbuf);
		if ((unsigned char )p[i] == (unsigned char )'\xC3')
		{
			
			foundAddress = (UINT_PTR )(p + i + 1);
			for(n = 1;n < minLength;n++)
			{
				if ( (p[i+n] != (unsigned char )'\xCC' ) && (p[i+n] != (unsigned char )'\x00') && (p[i+n] != (unsigned char )'\x90') )
				{
					/*
					memset(mbuf,0,1024);
					sprintf(mbuf," exiting search for loop at %x, [%02x]\n" , (UINT_PTR )(p + i + n), (unsigned char )(p[i+n]));
					OutputDebugString(mbuf);
					*/
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

void iathook(UINT_PTR addressFrom, UINT_PTR addressTo, UINT_PTR *saveAddress)
{
	HMODULE hMods[1024];
	DWORD cbNeeded = 0;
	MODULEINFO modInfo;

	char mbuf[1024];

	UINT_PTR lpBase = 0;

	HANDLE hProcess = GetCurrentProcess();

	EnumProcessModules( GetCurrentProcess(), hMods, sizeof(hMods),&cbNeeded);

	int i = 0;
	for (; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		char szModName[1024];
		if(GetModuleFileNameEx( hProcess,hMods[i],szModName,sizeof(szModName) / sizeof(char)) )
		{
			if(strstr(shortName(szModName),"exe") != NULL)
			{
				GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo));
				lpBase = (UINT_PTR )modInfo.lpBaseOfDll;
				break;
			}
		}
	}
	
	sprintf(mbuf," [IAT] found base at 0x%p\n",(void *)lpBase);
	OutputDebugString(mbuf);

	IMAGE_DOS_HEADER *imgDosHdr = (IMAGE_DOS_HEADER *)lpBase;
	IMAGE_NT_HEADERS *imgNtHdrs = (IMAGE_NT_HEADERS *)(lpBase + imgDosHdr->e_lfanew);

	if(imgDosHdr->e_magic != 0x5a4d)
	{
		OutputDebugString(" [IAT] e_magic fucked, abort, abort\n");
		return;
	}

	if(imgNtHdrs->Signature  != 0x4550)
	{
		OutputDebugString(" [IAT] imgNtHdrs->Signature fucked, abort, abort\n");
		return;
	}

	OutputDebugString(" [IAT] signature checks ok, trying to find import table...\n");

	IMAGE_DATA_DIRECTORY *pDataDir = ((IMAGE_DATA_DIRECTORY *)(imgNtHdrs->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT));
	IMAGE_IMPORT_DESCRIPTOR *pImportDir = (IMAGE_IMPORT_DESCRIPTOR *)(lpBase + pDataDir->VirtualAddress);

	OutputDebugString(" [IAT] got data dir + import dir\n");

	IMAGE_THUNK_DATA **nameChain = (IMAGE_THUNK_DATA **)(lpBase + pImportDir->Characteristics);
	UINT_PTR *funcChain = (UINT_PTR *)(lpBase + pImportDir->FirstThunk);

	sprintf(mbuf," [IAT] nameChain = %p, funcChain = %p\n",nameChain,funcChain);
	OutputDebugString(mbuf);

	// only works with loaded functions
	while(funcChain[i] != addressFrom && funcChain[i] != 0)
	{
		i++;
	}

	sprintf(mbuf," [IAT] got it - %p\n",&funcChain[i]);
	OutputDebugString(mbuf);

	saveAddress[0] = funcChain[i];

	DWORD oldProtect;
	VirtualProtect(&funcChain[i],sizeof(UINT_PTR),PAGE_READWRITE,&oldProtect);

	funcChain[i] = addressTo;

	VirtualProtect(&funcChain[i],sizeof(UINT_PTR),oldProtect,&oldProtect);

	sprintf(mbuf," [IAT] replaced IAT pointer to %p with %p\n",(void *)saveAddress[0],(void *)addressTo);
	OutputDebugString(mbuf);

	return;
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
		// codeCave[totalSize] = '\xE8'; // call, not jmp
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
	sprintf(mbuf,"* [32-BIT] [0x%p] HOOKED %02x %02x%02x%02x%02x (0x%p)\n",(void *)(UINT_PTR )addressFrom,
													(unsigned char )addressFromWrite[0],
													(unsigned char )addressFromWrite[1],
													(unsigned char )addressFromWrite[2],
													(unsigned char )addressFromWrite[3],
													(unsigned char )addressFromWrite[4],
													(void *)(UINT_PTR )addressTo);
	#else
	if(shortCaveAddr != 0)
	{
		sprintf(mbuf,"* [64-BIT] [0x%p] %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x (0x%p)\n",(void *)(UINT_PTR )addressFrom,
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
													(void *)(UINT_PTR )addressTo);
	}
	else
	{
		sprintf(mbuf,"* [64-BIT] [0x%p] HOOKED-SHORTCAVE %02x %02x%02x%02x%02x (0x%p)\n",(void *)(UINT_PTR )addressFrom,
													(unsigned char )addressFromWrite[0],
													(unsigned char )addressFromWrite[1],
													(unsigned char )addressFromWrite[2],
													(unsigned char )addressFromWrite[3],
													(unsigned char )addressFromWrite[4],
													(void *)(UINT_PTR )shortCaveAddr);
	}
	#endif
	OutputDebugString(mbuf);

	VirtualFree(mbuf,0,MEM_RELEASE);

	return;
}

DWORD threadId = 0;
DWORD threadId_hotkeys = 0;

int isMyTEBFucked(){
	MessageBox(0,"Teb test","hello2",MB_OK);
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
	if((fdwReason == DLL_PROCESS_ATTACH && init == 0) || fdwReason == DLL_MAGICMIRROR)
      {
        init = 1;
		SYSTEMTIME lt = {0};
		char *fnameBuf[1024];


		GetLocalTime(&lt);
		/*
		sprintf crashes here, but other things poop themsleves too.
		0:001> dd esp
		01b7e9ac  01b7e9cc 01c9b474 00000013 00000026
		01b7e9bc  000407e4 000c0000 00260013 02730024
		01b7e9cc  00003231 c35dd2ce 01b7eaec 00f51e98
		01b7e9dc  00000003 0100017c 764fc7c8 0000331c
		01b7e9ec  000000ec ef5abb88 00000002 01489f50
		01b7e9fc  ef5ab87c 01b7ea6c 77e493ea 01b7eaec
		01b7ea0c  01b7ea98 01b7ea48 01b7ea44 01b7ea34
		01b7ea1c  01b7ea3c 00000000 01b7eb5c 01b7ebd4
		*/
		char *p = (char *)malloc(1024);
		sprintf((char *)fnameBuf,"c:\\projects\\packetlog-%02d:%02d.log",lt.wHour,lt.wMinute);
		/*
				if(fdwReason == DLL_MAGICMIRROR)
		{
			__asm{
				int 3
			}
		}
		*/
		OutputDebugString(" - shackle dll loaded, deploying stealth\n");
		#ifdef THROWBRICKS
		MODULEINFO mi;
		GetModuleInformation(GetCurrentProcess(),hinstDLL,&mi,sizeof(mi));

		DWORD oldProtect = 0;

		IMAGE_DOS_HEADER *imgDosHdr = (IMAGE_DOS_HEADER *)mi.lpBaseOfDll;
		IMAGE_NT_HEADERS *imgNtHdrs = (IMAGE_NT_HEADERS *)(imgDosHdr + imgDosHdr->e_lfanew);
		OutputDebugString(" - throwing bricks at the window for a bit...\n");

		VirtualProtect(mi.lpBaseOfDll,1,PAGE_READWRITE,&oldProtect);
		imgDosHdr->e_magic = 0;
		imgDosHdr->e_lfanew = 0;
		VirtualProtect(mi.lpBaseOfDll,1,oldProtect,&oldProtect);

		VirtualProtect((LPVOID )(imgNtHdrs),1,PAGE_READWRITE,&oldProtect);
		imgNtHdrs->Signature = 0;
		VirtualProtect((LPVOID )(imgNtHdrs),1,oldProtect,&oldProtect);
		#endif

		OutputDebugString(" - creating server thread\n");
		
		HANDLE hThread = CreateThread(NULL,0,IPCServerThread,NULL,0,&threadId);
		return TRUE;
      }
  return TRUE;
}

DWORD WINAPI IPCServerThread( LPVOID lpParam ) 
{
	char *mbuf = (char *)malloc(1024);
	char *pipeName = (char *)malloc(1024);

	__registerThread(GetCurrentThreadId());

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

	__unregisterThread(GetCurrentThreadId());
	return 0;
}

#define lua_saveline(L,line)	{ (void)L; (void)line; }
#define lua_freeline(L,b)	{ (void)L; (void)b; }

static int incomplete (lua_State *L, int status) {
  if (status == LUA_ERRSYNTAX) {
    size_t lmsg;
    const char *msg = lua_tolstring(L, -1, &lmsg);
    if (lmsg >= marklen && strcmp(msg + lmsg - marklen, EOFMARK) == 0) {
      lua_pop(L, 1);
      return 1;
    }
  }
  return 0;  /* else... */
}

static int addreturn (lua_State *L) {
  const char *line = lua_tostring(L, -1);  /* original line */
  const char *retline = lua_pushfstring(L, "return %s;", line);
  int status = luaL_loadbuffer(L, retline, strlen(retline), "=stdin");
  if (status == LUA_OK) {
    lua_remove(L, -2);  /* remove modified line */
    if (line[0] != '\0')  /* non empty? */
      lua_saveline(L, line);  /* keep history */
  }
  else
    lua_pop(L, 2);  /* pop result from 'luaL_loadbuffer' and modified line */
  return status;
}

static int pushline (lua_State *L, int firstline, HANDLE hPipe, int *exitToLoop) {
  // what kind of crackhead programming is this shit
  char buffer[LUA_MAXINPUT];
  char *b = buffer;
  size_t l;
  char *prmt = "IGNORED-PUSHLINE";
  int readstatus = lua_readline(L, b, prmt, hPipe, exitToLoop);
  if (readstatus == 0)
    return 0;  /* no input (prompt will be popped by caller) */
  lua_pop(L, 1);  /* remove prompt */
  l = strlen(b);
  if (l > 0 && b[l-1] == '\n')  /* line ends with newline? */
    b[--l] = '\0';  /* remove it */
  if (firstline && b[0] == '=')  /* for compatibility with 5.2, ... */
    lua_pushfstring(L, "return %s", b + 1);  /* change '=' to 'return' */
  else
    lua_pushlstring(L, b, l);
  lua_freeline(L, b);
  return 1;
}

static int multiline (lua_State *L, HANDLE hPipe, int *exitToLoop) {
  for (;;) {  /* repeat until _s a complete statement */
    size_t len;
    const char *line = lua_tolstring(L, 1, &len);  /* get what it has */
    int status = luaL_loadbuffer(L, line, len, "=stdin");  /* try it */
    if (!incomplete(L, status) || !pushline(L, 0, hPipe, exitToLoop) || *exitToLoop == 1) {
	  OutputDebugString("+fucked+\n");
      lua_saveline(L, line);  /* keep history */
      return status;  /* cannot or should not try to add continuation line */
    }
    lua_pushliteral(L, "\n");  /* add newline... */
    lua_insert(L, -2);  /* ...between the two lines */
    lua_concat(L, 3);  /* join them */
  }
}

int lua_readline(lua_State *L, char *buf, char *prompt, HANDLE hPipe, int *exitIoLoop)
{
	char mbuf[1024];
	BOOL fSuccess = FALSE;
	DWORD cbBytesRead = 0;
	fSuccess = ReadFile(hPipe,buf,LUA_MAXINPUT,&cbBytesRead,NULL);
	if (!fSuccess || cbBytesRead == 0)
	{
		memset(mbuf,0,1024);
		sprintf(mbuf," [ERR] read failed, gle=%d\n",GetLastError());
		OutputDebugString(mbuf);
		*exitIoLoop = 1;
		return 0;
	}
	return 1;
}

static int msghandler (lua_State *L) {
  const char *msg = lua_tostring(L, 1);
  if (msg == NULL) {  /* is error object not a string? */
    if (luaL_callmeta(L, 1, "__tostring") &&  /* does it have a metamethod */
        lua_type(L, -1) == LUA_TSTRING)  /* that produces a string? */
      return 1;  /* that is the message */
    else
      msg = lua_pushfstring(L, "(error object is a %s value)",
                               luaL_typename(L, 1));
  }
  luaL_traceback(L, L, msg, 1);  /* append a standard traceback */
  return 1;  /* return the traceback */
}

static void lstop (lua_State *L, lua_Debug *ar) {
  (void)ar;  /* unused arg. */
  lua_sethook(L, NULL, 0, 0);  /* reset hook */
  luaL_error(L, "interrupted!");
}

lua_State *globalL = NULL;

static void laction (int i) {
  signal(i, SIG_DFL); /* if another SIGINT happens, terminate process */
  lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}

static int docall (lua_State *L, int narg, int nres) {
  int status;
  int base = lua_gettop(L) - narg;  /* function index */
  lua_pushcfunction(L, msghandler);  /* push message handler */
  lua_insert(L, base);  /* put it under function and args */
  globalL = L;  /* we need to mutex this shit */
  signal(SIGINT, laction);  /* set C-signal handler */
  status = lua_pcall(L, narg, nres, base);
  signal(SIGINT, SIG_DFL); /* reset C-signal handler */
  lua_remove(L, base);  /* remove message handler from the stack */
  return status;
}

static int loadline (lua_State *L, HANDLE hPipe, int *exitToLoop) {
  int status;
  lua_settop(L, 0);
  if (!pushline(L, 1, hPipe, exitToLoop))
    return -1;  /* no input */
  if ((status = addreturn(L)) != LUA_OK)  /* 'return ...' did not work? */
    status = multiline(L,hPipe,exitToLoop);  /* try as command, maybe with continuation lines */
  lua_remove(L, 1);  /* remove line from the stack */
  lua_assert(lua_gettop(L) == 1);
  return status;
}

static int cs_print(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
	DWORD cbWritten = 0;


	int n = lua_gettop(L);  /* number of arguments */
	int i;
	lua_getglobal(L, "tostring");
	for (i=1; i<=n; i++)
	{
		const char *s;
		size_t l;
		lua_pushvalue(L, -1);  /* function to be called */
		lua_pushvalue(L, i);   /* value to print */
		lua_call(L, 1, 1);
		s = lua_tolstring(L, -1, &l);  /* get result */
		if (s == NULL)
			return luaL_error(L, "'tostring' must return a string to 'print'");
		if (i>1)
			WriteFile(hPipe,"\t",1,&cbWritten,NULL);
		WriteFile(hPipe,s,l,&cbWritten,NULL);
		lua_pop(L, 1);  /* pop result */
    }
	lua_writeline();
	return 0;
}

static int cs_run(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	DWORD threadId_shellcodeLoader = 0;

	char mbuf[1024];

	if(lua_gettop(L) == 1)
	{
		if(lua_isnumber(L,1))
		{
			UINT_PTR runPtr = (UINT_PTR )lua_tointeger(L,1);
			sprintf(mbuf," [NFO] running at 0x%p\n",(void *)runPtr);
			outString(hPipe,mbuf);
			CreateThread(NULL,0,(LPTHREAD_START_ROUTINE )shellcodeLoader,(LPVOID )runPtr,0,&threadId_shellcodeLoader);
		}
		else
		{
			sprintf(mbuf," [ERR] 'run' first argument must be a pointer to executable code\n");
			outString(hPipe,mbuf);
		}
	}
	else
	{
		sprintf(mbuf," [ERR] 'run' needs 1 argument\n");
		outString(hPipe,mbuf);
	}
	return 0;
}

typedef int func(void);

DWORD WINAPI shellcodeLoader(LPVOID param)
{
	__registerThread(GetCurrentThreadId());

	func *f = (func *)param;
	f();

	__unregisterThread(GetCurrentThreadId());
	
	return 0;
}

static int cs_ALERT(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
	DWORD cbWritten = 0;

	size_t l;
	const char* str = lua_tolstring( L, -1 , &l);
    lua_pop(L, 1);

    WriteFile(hPipe,str,l,&cbWritten,NULL);
    return 0;
}

static int test_lua(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char *pchReply = "TEST_LUA\0";
	DWORD cbReplyBytes = 4;
	DWORD cbWritten = 0;
	char mbuf[1024];

	BOOL fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
	if (!fSuccess || cbReplyBytes != cbWritten)
	{
		sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
		OutputDebugString(mbuf);
	}

	fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
	if (!fSuccess || cbReplyBytes != cbWritten)
	{
		sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
		OutputDebugString(mbuf);
	}

	OutputDebugString(" + lua engine successfully recognizes test_lua(), good to go\n");
	// lua_pushinteger(L,123);
	return 0;
}

// cs_resolve(straddr) = addr
// cs_unresolve(addr) = straddr
// can be used for back and forward conversions

static int cs_unresolve(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	UINT_PTR address = 0;

	if (lua_gettop(L) == 1)
	{
		address = (UINT_PTR)lua_tointeger( L, -1 );
	}
	else
	{
		outString(hPipe," [ERR] malloc(size) requires 1 argument\n");
		return 0;
	}

	// walk through module list (this should be rare)
	char mbuf[1024];

	HMODULE hMods[1024];
	DWORD cbNeeded = 0;
	MODULEINFO modInfo;
	HANDLE hProcess = GetCurrentProcess();
	if( EnumProcessModules( hProcess, hMods, sizeof(hMods),&cbNeeded) )
	{
		int i = 0;
		for (; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char szModName[1024];
			GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo));
			if(GetModuleFileNameEx( hProcess,hMods[i],szModName,sizeof(szModName) / sizeof(char)) )
			{
				if ( GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo)) )
				{
					if(address == (UINT_PTR )modInfo.lpBaseOfDll)
					{
						lua_pushstring(L,shortName(szModName));
						return 1;
					}
					else if(address > (UINT_PTR )modInfo.lpBaseOfDll && address <= (UINT_PTR )((UINT_PTR )modInfo.lpBaseOfDll + modInfo.SizeOfImage))
					{
						sprintf(mbuf,"%s+0x%p",shortName(szModName),(void *)(address - (UINT_PTR )modInfo.lpBaseOfDll));
						lua_pushstring(L,mbuf);
						return 1;
					}
				}
			}
		}
	}
	else
	{
		return 0;
	}

	return 0;
}

// try to roll with 
static int cs_resolve(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	
	size_t l;
	char* address = (char *)lua_tolstring( L, -1 , &l);
    lua_pop(L, 1);

	char mbuf[1024];
	memset(mbuf,0,1024);

	sprintf(mbuf," [NFO] resolving '%s'\n",address);
	outString(hPipe,mbuf);

	char *baseDll = NULL;
	char *function = NULL;
	char *offset = NULL;
	
	int i = 0, maxlen = strlen(address);
	baseDll = address;

	for( ; i < maxlen; i++)
	{
		if(address[i] == '!')
		{
			address[i] = '\0';
			function = baseDll + i + 1;
		}
		else if(address[i] == '+')
		{
			address[i] = '\0';
			offset = baseDll + i + 1;
		}
	}

	if(baseDll == NULL)
	{
		outString(hPipe," [ERR] no base dll provided (wtf?)\n");
		return 0;
	}
	
	UINT_PTR base = 0;
	if(function  == NULL)
	{
		MODULEINFO *mi = (MODULEINFO *)malloc( sizeof(MODULEINFO) );
		memset(mi,0,sizeof(MODULEINFO));
		HMODULE hMod = GetModuleHandle(baseDll);
		if(hMod == NULL)
		{
			outString(hPipe," [ERR] could not get handle of module (make sure it's loaded)\n");
			free(mi);
			return 0;
		}
		GetModuleInformation(GetCurrentProcess(),hMod,mi,sizeof(MODULEINFO));
		base = (UINT_PTR )mi->lpBaseOfDll;
		free(mi);
		// return 1;
	}
	else
	{
		HMODULE hMod = GetModuleHandle(baseDll);
		if(hMod == NULL)
		{
			outString(hPipe," [ERR] could not get handle of module (make sure it's loaded)\n");
			return 0;
		}
		base = (UINT_PTR )GetProcAddress(hMod,function);
		if (base == NULL)
		{
			outString(hPipe," [ERR] could not resolve function\n");
			return 0;
		}
	}

	if(offset != NULL)
	{
		base += atol(offset);
	}

	lua_pushinteger(L,base);
	return 1;
}

void cs_error(lua_State *L, HANDLE hPipe)
{
	char mbuf[1024];
	sprintf(mbuf," %s\n",lua_tostring(L,-1));
	outString(hPipe,mbuf);
	return;
}

DWORD WINAPI IPCServerInstance(LPVOID lpvParam)
{
	char *pchRequest = (char *)malloc(1024);
	char *pchReply = (char *)malloc(1024);
	char *mbuf = (char *)malloc(1024);
	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;
	HANDLE hPipe = (HANDLE )lpvParam;

	__registerThread(GetCurrentThreadId());

	OutputDebugString(" - IPC Server Instance created\n");

	// moved here for thread-safety.
	lua_State *luaState = NULL;

	luaState = luaL_newstate();

	// different threads can't define different hotkeys on a host system
	// want to race-proof this, lower priority
	memset(globalHotkeyArray,0,sizeof( char * ) * 256);
	int unhookThisThread = 0;

	luaL_openlibs(luaState);
	// lua_register(luaState,"test_lua",test_lua);
	lua_register(luaState,"print",cs_print);
	lua_register(luaState,"hexdump",cs_hexdump);
	lua_register(luaState,"memcpy",cs_memcpy);
	lua_register(luaState,"memset",cs_memset);
	lua_register(luaState,"malloc",cs_malloc);
	lua_register(luaState,"free",cs_free);
	lua_register(luaState,"mprotect",cs_mprotect);
	lua_register(luaState,"memread",cs_memread);
	lua_register(luaState,"disasm",cs_disassemble);
	lua_register(luaState,"disassemble",cs_disassemble);
	lua_register(luaState,"asm_new",cs_asm_new);
	lua_register(luaState,"asm_add",cs_asm_add);
	lua_register(luaState,"asm_commit",cs_asm_commit);
	lua_register(luaState,"asm_free",cs_asm_free);
	lua_register(luaState,"resolve",cs_resolve);
	lua_register(luaState,"unresolve",cs_unresolve);
	lua_register(luaState,"search_filter",cs_search_filter);
	lua_register(luaState,"search_new",cs_search_new);
	lua_register(luaState,"search_free",cs_search_free);
	lua_register(luaState,"search_fetch",cs_search_fetch);
	lua_register(luaState,"search_vtable",cs_search_vtable);
	lua_register(luaState,"dump_all",cs_dump_everything_we_can);
	lua_register(luaState,"dump_module",cs_dump_module);
	lua_register(luaState,"ls_connect",cs_ls_connect);
	lua_register(luaState,"ls_closesocket",cs_ls_closesocket);
	lua_register(luaState,"ls_send",cs_ls_send);
	lua_register(luaState,"ls_recv",cs_ls_recv);
	lua_register(luaState,"eb",cs_eb);
	lua_register(luaState,"ew",cs_ew);
	lua_register(luaState,"ed",cs_ed);
	lua_register(luaState,"db",cs_db);
	lua_register(luaState,"dw",cs_dw);
	lua_register(luaState,"dd",cs_dd);
	lua_register(luaState,"magicmirror",cs_magicmirror);
	lua_register(luaState,"fetch_byte",cs_fetch_byte);
	lua_register(luaState,"fetch_word",cs_fetch_word);
	lua_register(luaState,"fetch_dword",cs_fetch_dword);
	lua_register(luaState,"bind",cs_bind);
	lua_register(luaState,"unbind",cs_unbind);
	// **DEPRECATED:m_who_writes_to** lua_register(luaState,"who_writes_to",cs_who_writes_to);
	// **DEPRECATED:m_finish_who_writes_to** lua_register(luaState,"finish_who_writes_to",cs_finish_who_writes_to);
	lua_register(luaState,"run",cs_run);
	lua_register(luaState,"msgbox",cs_msgbox);
	lua_register(luaState,"listthreads",cs_listthreads);
	lua_register(luaState,"stopthreads",cs_stopthreads);
	lua_register(luaState,"resumethreads",cs_resumethreads);

	LUAINIT_DARKSIGN;

	// lua_register(luaState,"m_who_writes_to",cs_m_who_writes_to);
	// lua_register(luaState,"m_who_reads_from",cs_m_who_reads_from);
	lua_register(luaState,"m_who_accesses",cs_m_who_accesses);
	lua_register(luaState,"m_finish_who_writes_to",cs_m_finish_who_writes_to);
	lua_register(luaState,"finish_m_who_writes_to",cs_m_finish_who_writes_to);
	lua_register(luaState,"m_finish",cs_m_finish_who_writes_to);

	// mprotect constants
	luaL_dostring(luaState,"PAGE_EXECUTE = 0x10");
	luaL_dostring(luaState,"PAGE_EXECUTE_READ = 0x20");
	luaL_dostring(luaState,"PAGE_EXECUTE_READWRITE = 0x40");
	luaL_dostring(luaState,"PAGE_EXECUTE_WRITECOPY = 0x80");
	luaL_dostring(luaState,"PAGE_NOACCESS = 0x1");
	luaL_dostring(luaState,"PAGE_READONLY = 0x2");
	luaL_dostring(luaState,"PAGE_READWRITE = 0x4");
	luaL_dostring(luaState,"PAGE_WRITECOPY = 0x8");
	luaL_dostring(luaState,"PAGE_TARGETS_INVALID = 0x40000000");
	luaL_dostring(luaState,"PAGE_TARGETS_NO_UPDATE = 0x40000000");
	luaL_dostring(luaState,"PAGE_GUARD = 0x100");
	luaL_dostring(luaState,"PAGE_NOCACHE = 0x200");
	luaL_dostring(luaState,"PAGE_WRITECOMBINE = 0x400");
	luaL_dostring(luaState,"SEARCH_DWORD = 4");
	luaL_dostring(luaState,"SEARCH_PATTERN = 8");
	luaL_dostring(luaState,"SEARCH_WORD = 2");
	luaL_dostring(luaState,"SEARCH_BYTE = 1");

	// msgbox constants
	luaL_dostring(luaState,"MB_ABORTRETRYIGNORE = 0x2");
	luaL_dostring(luaState,"MB_CANCELTRYCONTINUE = 0x6");
	luaL_dostring(luaState,"MB_HELP = 0x4000");
	luaL_dostring(luaState,"MB_OK = 0x0");
	luaL_dostring(luaState,"MB_OKCANCEL = 0x1");
	luaL_dostring(luaState,"MB_RETRYCANCEL = 0x5");
	luaL_dostring(luaState,"MB_YESNO = 0x4");
	luaL_dostring(luaState,"MB_YESNOCANCEL = 0x3");
	luaL_dostring(luaState,"MB_ICONEXCLAMATION = 0x30");
	luaL_dostring(luaState,"MB_ICONWARNING = 0x30");
	luaL_dostring(luaState,"MB_ICONINFORMATION = 0x40");
	luaL_dostring(luaState,"MB_ICON_ASTERISK= 0x40");
	luaL_dostring(luaState,"MB_ICONQUESTION = 0x20");
	luaL_dostring(luaState,"MB_ICONSTOP = 0x10");
	luaL_dostring(luaState,"MB_ICONERROR = 0x10");
	luaL_dostring(luaState,"MB_ICONHAND = 0x10");
	luaL_dostring(luaState,"MB_DEFBUTTON1 = 0x0");
	luaL_dostring(luaState,"MB_DEFBUTTON2 = 0x100");
	luaL_dostring(luaState,"MB_DEFBUTTON3 = 0x200");
	luaL_dostring(luaState,"MB_DEFBUTTON4 = 0x300");
	luaL_dostring(luaState,"MB_APPLMODAL = 0x0");
	luaL_dostring(luaState,"MB_SYSTEMMODAL = 0x1000");
	luaL_dostring(luaState,"MB_TASKMODAL = 0x2000");
	luaL_dostring(luaState,"MB_DEFAULT_DESKTOP_ONLY = 0x20000");
	luaL_dostring(luaState,"MB_RIGHT = 0x80000");
	luaL_dostring(luaState,"MB_RTLREADING = 0x100000");
	luaL_dostring(luaState,"MB_SETFOREGROUND = 0x10000");
	luaL_dostring(luaState,"MB_TOPMOST = 0x40000");
	luaL_dostring(luaState,"MB_SERVICE_NOTIFICATION = 0x200000");

	luaL_dostring(luaState,"IDABORT = 1");
	luaL_dostring(luaState,"IDCANCEL = 1");
	luaL_dostring(luaState,"IDCONTINUE = 11");
	luaL_dostring(luaState,"IDIGNORE = 5");
	luaL_dostring(luaState,"IDNO = 7");
	luaL_dostring(luaState,"IDOK = 1");
	luaL_dostring(luaState,"IDRETRY = 4");
	luaL_dostring(luaState,"IDTRYAGAIN = 10");
	luaL_dostring(luaState,"IDYES = 6");
	
	CreateThread(NULL,0,(LPTHREAD_START_ROUTINE )hotkeyThread,luaState,0,&threadId_hotkeys);

	int exitToLoop = 0;

	strcpy(pchReply,"NEXTCMDREADY\0");
	cbReplyBytes = strlen(pchReply) + 1;

	HANDLE hProcess = (HANDLE )GetCurrentProcess();
	DWORD pid = (DWORD )GetCurrentProcessId();

	lua_pushinteger(luaState,(UINT_PTR )hPipe);
	lua_setglobal(luaState,"__hpipe");

	lua_pushinteger(luaState,(UINT_PTR )hProcess);
	lua_setglobal(luaState,"__hprocess");

	lua_pushinteger(luaState,pid);
	lua_setglobal(luaState,"__pid");

	sprintf(mbuf," - __hpipe = %p | __hProcess = %p | __pid = %d -\n",hPipe,hProcess,pid);
	outString(hPipe,mbuf);

	// collect process modules for resolver
	HMODULE hMods[1024];
	DWORD cbNeeded = 0;
	MODULEINFO modInfo;
	if( EnumProcessModules( hProcess, hMods, sizeof(hMods),&cbNeeded) )
	{
		int i = 0;
		for (; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char szModName[1024];
			GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo));
			if(GetModuleFileNameEx( hProcess,hMods[i],szModName,sizeof(szModName) / sizeof(char)) )
			{
				if ( GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo)) )
				{
					sprintf(mbuf," + %s (0x%p, size:%x) (entry:0x%p)\n",shortName(szModName),hMods[i],modInfo.SizeOfImage,modInfo.EntryPoint);
					outString(hPipe,mbuf);
					sprintf(mbuf,"%s = {start=%p,size=%x}",shortName(szModName),hMods[i],modInfo.SizeOfImage);
					int bufptr = 0;
					for(;mbuf[bufptr] != '\0';bufptr++)
					{
						if(mbuf[bufptr] == '.')
						{
							mbuf[bufptr] = '_';
						}
					}
					luaL_dostring(luaState,mbuf);
				}
				else
				{
					sprintf(mbuf," + %s (no info available)\n",shortName(szModName));
					outString(hPipe,mbuf);
				}
			}
		}
	}
	else
	{
		// maybe get 'peek' to do initialization.
	}

	outString(hPipe,"\n");


	sprintf(mbuf," welcome to doxastica %s\n",VERSTRING);
	OutputDebugString(mbuf);

	sprintf(mbuf,"INITFINISHED\0");
	outString(hPipe,mbuf);

	while(1)
	{
		fSuccess = ReadFile(hPipe,pchRequest,1024,&cbBytesRead,NULL);
		if (!fSuccess || cbBytesRead == 0)
		{
			sprintf(mbuf," [ERR] read failed, gle=%d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}

		// flush.
		lua_settop(luaState, 0);

		/*

		// http://stackoverflow.com/questions/20454725/how-to-replace-lua-default-error-print

		if (luaL_loadbuffer(L,script.c_str(),script.Length(),AnsiString(Name).c_str()) == 0) {
		if (lua_pcall(L, 0, 0, 0))        // Run loaded Lua script
			cs_error(L, "Runtime error: "); // Print runtime error
		} else {
			cs_error(L, "Compiler error: ");  // Print compiler error
		}
		*/

		// OutputDebugString("OK, LUA stack flushed\n");
		
		if( luaL_loadbuffer(luaState,pchRequest,strlen(pchRequest),"IPCInput") == 0 )
		{
			if( lua_pcall(luaState,0,0,0) )
			{
				cs_error(luaState,hPipe);
			}
		}
		else
		{
			cs_error(luaState,hPipe);
		}
		
		// int status = luaL_dostring(luaState,pchRequest);

		fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
		if (!fSuccess || cbReplyBytes != cbWritten)
		{
			sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}

		OutputDebugString("OK, peek replied to...\n");

		// lua_settop(luaState, 0);
	}

	/*
	while ((status = loadline(luaState, hPipe, &exitToLoop)) != -1 && exitToLoop == 0) 
	{
		if (status == LUA_OK)
		{
			OutputDebugString("doing call\n");
			status = docall(luaState, 0, LUA_MULTRET);
		}
		if (status == LUA_OK)
		{
			memset(pchReply,0,1024);
			strcpy(pchReply,"123123");
			cbReplyBytes = strlen(pchReply) + 1;	
		}
		else
		{
			memset(pchReply,0,1024);
			strcpy(pchReply,"fqn wat 123123");
			cbReplyBytes = strlen(pchReply) + 1;
		}
		fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
		if (!fSuccess || cbReplyBytes != cbWritten)
		{
			sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}
	}
	*/

	lua_settop(luaState, 0);  /* clear stack */
	lua_writeline();
	lua_close(luaState);

	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	free(mbuf);
	free(pchRequest);
	free(pchReply);

	__unregisterThread(GetCurrentThreadId());

	return 1;
}

/*

lua API (invoke via peek)
=========================

- void hexdump(addr offset, int size)
- void disassemble(addr offset, int instructionLength)
- str cs_assemble(addr offset, str input)
- void memcpy(addr offset, string data, int size)
- void memset(addr offset, char data, int size)
- (status, oldprotect) = mprotect(addr offset, size, int protectionconstant) // really virtualprotect, but sure.
- addr resolve(str resolvestring)
- addr malloc(size)
- void free(addr)

*/

static int cs_malloc(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
	char mbuf[1024];

	int size = 0;

	if (lua_gettop(L) == 1)
	{
		size = lua_tointeger(L,1);
	}
	else
	{
		outString(hPipe," [ERR] malloc(size) requires 1 argument\n");
		return 0;
	}

	UINT_PTR returnvalue = (UINT_PTR )malloc(size);
	memset((void *)returnvalue,0,size);

	sprintf(mbuf," [NFO] allocated %d bytes at 0x%p\n",size,(void *)returnvalue);
	outString(hPipe,mbuf);

	lua_pushinteger(L,returnvalue);
	return 1;
}

static int cs_free(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
	char mbuf[1024];

	char *ptr = NULL;

	if (lua_gettop(L) == 1)
	{
		ptr = (char *)lua_tointeger(L,1);
	}
	else
	{
		outString(hPipe," [ERR] free(ptr) requires 1 argument\n");
		return 0;
	}

	free(ptr);
	return 0;
}

static int cs_mprotect(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char *addrTo = NULL;
	int protectconstant = 0;
	int size = 0;

	if (lua_gettop(L) == 3)
	{
		addrTo = (char *)(UINT_PTR )lua_tointeger(L,1);
		size = lua_tointeger(L,2);
		protectconstant = lua_tointeger(L,3);
	}
	else
	{
		outString(hPipe," [ERR] memprotect(dest,size,protect_constant) requires 3 arguments\n");
		return 0;
	}

	DWORD oldProtect = 0;
	int returnstatus = 0;

	returnstatus = VirtualProtect(addrTo,size,protectconstant,&oldProtect);
	if(returnstatus == 0)
	{
		returnstatus = GetLastError();
	}

	lua_pushinteger(L,oldProtect);
	lua_pushinteger(L,returnstatus);

	return 2;
}

static int cs_memset(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char *addrTo = NULL;
	char byteToSet = '\0';
	int size = 0;

	size_t msize = 0;

	if (lua_gettop(L) == 3)
	{
		addrTo = (char *)(UINT_PTR )lua_tointeger(L,1);
		if(lua_isstring(L,2))
		{
			byteToSet = (char ) ((char *)(lua_tolstring(L,2,&msize))) [0];
		}
		else if(lua_isnumber(L,2))
		{
			int byteData = lua_tointeger(L,2);
			if (byteData > 255)
			{
				outString(hPipe," [ERR] can't cast this number to a byte\n");
				return 0;
			}
			byteToSet = (char )byteData;
		}
		size = lua_tointeger(L,3);
	}
	else
	{
		outString(hPipe," [ERR] memset(dest,source,size) requires 3 arguments\n");
		return 0;
	}

	if(msize != size)
	{
		char mbuf[1024];
		sprintf(mbuf," [WRN] string size (%d) is not equal to provided size / arg 3 (%d)\n",(int )msize,(int )size);
		outString(hPipe,mbuf);
	}

	__try
	{
		memset(addrTo,byteToSet,size);
	}
	__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
	{
		outString(hPipe," [ERR] could not complete memory set operation\n");
	}

	return 0;
}

// ed, eb, ew so we can be like windbg
static int cs_ed(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 2)
	{
		DWORD *addrTo = (DWORD *)(UINT_PTR )lua_tointeger(L,1);
		DWORD value = (DWORD )lua_tointeger(L,2);
		__try{
			addrTo[0] = value;
		}
		__except(true)
		{
			outString(hPipe," [ERR] cant write here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] ed(dest,value) requires 2 arguments\n");
		return 0;
	}
	return 0;
}

static int cs_ew(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 2)
	{
		WORD *addrTo = (WORD *)(UINT_PTR )lua_tointeger(L,1);
		WORD value = (WORD )lua_tointeger(L,2);
		__try{
			addrTo[0] = value;
		}
		__except(true)
		{
			outString(hPipe," [ERR] cant write here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] ew(dest,value) requires 2 arguments\n");
		return 0;
	}
	return 0;
}

static int cs_db(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 1)
	{
		BYTE *addrTo = (BYTE *)(UINT_PTR )lua_tointeger(L,1);
		BYTE value = 0;
		__try{
			value = addrTo[0];
			char mbuf[1024];
			sprintf(mbuf," [0x%p] %02x\n",(void *)(UINT_PTR )addrTo, (unsigned char )value);
			outString(hPipe,mbuf);
			lua_pushinteger(L,value);
			return 1;
		}
		__except(true)
		{
			outString(hPipe," [ERR] cant read here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] db(dest) requires 1 argument\n");
		return 0;
	}
	return 0;
}

static int cs_dw(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 1)
	{
		WORD *addrTo = (WORD *)(UINT_PTR )lua_tointeger(L,1);
		WORD value = 0;
		__try{
			value = addrTo[0];
			char mbuf[1024];
			sprintf(mbuf," [0x%p] %04x\n",(void *)(UINT_PTR )addrTo, value);
			outString(hPipe,mbuf);
			lua_pushinteger(L,value);
			return 1;
		}
		__except(true)
		{
			outString(hPipe," [ERR] cant read here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] dw(dest) requires 1 argument\n");
		return 0;
	}
	return 0;
}

// fix this shit.
static int cs_dd(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 1)
	{
		int size = 32;
		DWORD *addrTo = (DWORD *)(UINT_PTR )lua_tointeger(L,1);
		DWORD value = 0;
		__try{
			value = addrTo[0];
			char mbuf[1024];
			sprintf(mbuf," [0x%p] %08x\n",(void *)(UINT_PTR )addrTo, value);
			outString(hPipe,mbuf);
			lua_pushinteger(L,value);
			return 1;
		}
		__except(true)
		{
			outString(hPipe," [ERR] cant read here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] dd(dest) requires 1 argument\n");
		return 0;
	}
	return 0;
}

static int cs_eb(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 2)
	{
		BYTE *addrTo = (BYTE *)(UINT_PTR )lua_tointeger(L,1);
		BYTE value = (BYTE )lua_tointeger(L,2);
		__try{
			addrTo[0] = value;
		}
		__except(true)
		{
			outString(hPipe," [ERR] cant write here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] eb(dest,value) requires 2 arguments\n");
		return 0;
	}
	return 0;
}

static int cs_memcpy(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char *addrTo = NULL;
	char *addrFrom = NULL;
	int size = 0;

	if (lua_gettop(L) == 2 || lua_gettop(L) == 3)
	{
		addrTo = (char *)(UINT_PTR )lua_tointeger(L,1);
		if(lua_isstring(L,2))
		{
			// data blob directly
			addrFrom = (char *)lua_tolstring(L,2,(size_t *)&size);
		}
		else if(lua_isnumber(L,2) && lua_gettop(L) == 3)
		{
			addrFrom = (char *)(UINT_PTR )lua_tointeger(L,2);
			size = lua_tointeger(L,3);
		}
		else
		{
			outString(hPipe," [ERR] memcpy(dest,source,size) requires 2 or 3 arguments\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] memcpy(dest,source,size) requires 2 or 3 arguments\n");
		return 0;
	}

	__try
	{
		char mbuf[1024];
		memcpy(addrTo,addrFrom,size);
		sprintf(mbuf," [NFO] copied %d bytes from 0x%p to 0x%p\n",size,addrFrom,addrTo);
		outString(hPipe,mbuf);
	}
	__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
	{
		outString(hPipe," [ERR] could not complete memory copy operation\n");
	}

	return 0;
}

int readfilter(unsigned int code, struct _EXCEPTION_POINTERS *ep) {
   // puts("in filter.");
   if (code == EXCEPTION_ACCESS_VIOLATION) {
      // puts("caught AV as expected.");
      return EXCEPTION_EXECUTE_HANDLER;
   }
   else {
      puts("didn't catch AV, unexpected.");
      return EXCEPTION_CONTINUE_SEARCH;
   };
}

static int cs_disassemble(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char *addrTo = NULL;
	int size = 0;

	if (lua_gettop(L) == 2)
	{
		addrTo = (char *)(UINT_PTR )lua_tointeger(L,1);
		size = lua_tointeger(L,2);
	}
	else if (lua_gettop(L) == 1)
	{
		addrTo = (char *)(UINT_PTR )lua_tointeger(L,1);
		size = 5;
		outString(hPipe," [NFO] assuming you want to disassemble 5 instructions\n");
	}
	else
	{
		outString(hPipe," [ERR] diasm(addr,{size}) requires 1-2 arguments\n");
		return 0;
	}

	char mbuf[1024];        // sprintf buffer
	char tempBuf[15];       // temp buf
	int currentHeader = 0;
	DISASM *d = (DISASM *)malloc(sizeof(DISASM));

	memset(d,0,sizeof(DISASM));
	d->Archi = ARCHI;
	int len = 0;
	
	int i = 0;
	for(;i < size;i++)
	{
		len = 1;
		__try
		{
			d->EIP = (UIntPtr )(addrTo+currentHeader);
			memcpy(tempBuf,(void *)(addrTo+currentHeader),15);
			len = Disasm(d);

			sprintf(mbuf," 0x%p : %s\n",(void *)(UIntPtr )(addrTo+currentHeader),d->CompleteInstr);
			outString(hPipe,mbuf);

		}
		__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
		{
			sprintf(mbuf," 0x%p : ..\n",(void *)(UIntPtr )(addrTo+currentHeader));
			outString(hPipe," ..\n");
		}
		currentHeader += len;
	}

	free(d);

	return 0;
}

static int cs_memread(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	/*
	size_t l;
	char* addressToResolve = (char *)lua_tolstring( L, -1 , &l);
    lua_pop(L, 1);
	*/

	char *addrTo = NULL;
	int size = 0;

	if (lua_gettop(L) == 2)
	{
		addrTo = (char *)(UINT_PTR )lua_tointeger(L,1);
		size = lua_tointeger(L,2);
	}
	else
	{
		outString(hPipe," [ERR] memread(addr,size) requires 2 arguments\n");
		return 0;
	}

	char *temp = (char *)malloc(size);
	memcpy(temp,addrTo,size);

	lua_pushlstring(L,temp,size);

	free(temp);

	return 1;
}

static int cs_hexdump(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char mbuf[1024];

	UINT_PTR addr = NULL;
	int n = 0;

	if (lua_gettop(L) == 2)
	{
		addr = (UINT_PTR )lua_tointeger(L,1);
		n = lua_tointeger(L,2);
	}
	else if(lua_gettop(L) == 1)
	{
		outString(hPipe," [NFO] no size supplied, defaulting to size 64\n");
		addr = (UINT_PTR )lua_tointeger(L,1);
		n = 64;
	}
	else
	{
		outString(hPipe," [ERR] hexdump(addr,size) requires 2 arguments\n");
		return 0;
	}

	sprintf(mbuf," - starting cs_hexdump, address is %p, length is %d\n",(void *)addr,n);
	outString(hPipe,mbuf);

	char currentLine[17];
	int isRead = 0;
	char thisChar = '\0';

	int i = 0;

	for(i = 0;i < n;i++)
	{
		if(i == 0 || i % 16 == 0)
		{
			#if ARCHI == 64
				sprintf(mbuf,"0x%p : \0",(void *)(UINT_PTR )(addr + i));
			#else
				sprintf(mbuf,"0x%p : \0",(void *)(UINT_PTR )(addr + i));
			#endif
			outString(hPipe,mbuf);
			memset(currentLine,'.',16);
			currentLine[16] = '\0';
		}
		
		__try
		{
			thisChar = (currentLine[i%16] = (char )*(char *)(addr + i)); // will throw an exception first, don't need everything else.
			sprintf(mbuf,"%02x \0",(unsigned char )(thisChar));
			outString(hPipe,mbuf);
			if(isprint(thisChar) && !isspace(thisChar))
			{
				currentLine[i % 16] = thisChar;
			}
			else
			{
				currentLine[i % 16] = '.';
			}
		}
		__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
		{
			outString(hPipe,".. ");
		}

		if((i + 1) % 16 == 0)
		{
			outString(hPipe,currentLine);
			outString(hPipe,"\n");
		}
	}

	if( i % 16 != 0)
	{
		// finish up.
		for(;i % 16 != 0;i++)
		{
			outString(hPipe,".. ");
		}
		outString(hPipe,currentLine);
		outString(hPipe,"\n");
	}
	return 0;
}

void outString(HANDLE hPipe, char *thisMsg)
{
	DWORD bytesWritten = 0;
	WriteFile(hPipe,thisMsg,strlen(thisMsg) + 1,&bytesWritten,NULL);
	OutputDebugString(thisMsg);
	return;
}

int validate_asm(asmBuffer *a)
{
	__try
	{
		if(a->signature == ASM_SIG)
		{
			return 1;
		}
	}
	__except(true)
	{
		return 0;
	}
	return 0;
}

static int cs_asm_new(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	UINT_PTR startAddress = NULL;
	int architecture = 32;

	if (lua_gettop(L) == 2)
	{
		startAddress = (UINT_PTR )lua_tointeger(L,1);
		architecture =  lua_tointeger(L,2);
	}
	else
	{
		outString(hPipe," [ERR] asm_new(offset,[32|64]) requires 2 arguments\n");
		return 0;
	}

	if(architecture != 32 && architecture != 64)
	{
		outString(hPipe," [ERR] asm_new(offset,[32|64]) / XEDParse only supports 32-bit and 64-bit intel architecture\n");
		return 0;
	}

	asmBuffer *d = (asmBuffer *)malloc(sizeof(asmBuffer));
	memset(d,0,sizeof(asmBuffer));

	d->signature = ASM_SIG;
	d->writeHead = startAddress;
	d->architecture = architecture;
	d->lineCount = 0;

	outString(hPipe," [NFO] asm_new() allocated new assembly buffer\n");
	lua_pushlightuserdata(L,(void *)d); // gc doesn't apply here.
	return 1;
}

static int cs_asm_add(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	asmBuffer *a = NULL;
	char *newLine = NULL;

	if (lua_gettop(L) == 2)
	{
		a = (asmBuffer *)lua_touserdata(L,1);
		if(validate_asm(a) == 0)
		{
			outString(hPipe," [ERR] asm_add(asmobj,assembly_data) / asmobj was not a valid assembly buffer\n");
			return 0;
		}
		newLine = (char *)lua_tostring(L,2);
	}
	else
	{
		outString(hPipe," [ERR] asm_add(asmobj,assembly_data) requires 2 arguments\n");
		return 0;
	}

	a->lines[a->lineCount] = strdup(newLine);
	a->lineCount += 1;

	return 0;
}

static int cs_asm_free(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	asmBuffer *a = NULL;

	if (lua_gettop(L) == 1)
	{
		a = (asmBuffer *)lua_touserdata(L,1);
		if(validate_asm(a) == 0)
		{
			outString(hPipe," [ERR] asm_free(asmobj) / asmobj was not a valid object\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] asm_free(asmobj) requires 1 argument\n");
		return 0;
	}

	// printf(""); // ?????

	a->signature = 0;

	int i = 0;
	for( ; i < a->lineCount; a++ )
	{
		if(a->lines[i] != 0)
		{
			free(a->lines[i]);
			a->lines[i] = 0;
		}
	}

	a->lineCount = 0;
	free(a);

	return 0;
}

static int cs_asm_commit(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	asmBuffer *a = NULL;

	if (lua_gettop(L) == 1)
	{
		a = (asmBuffer *)lua_touserdata(L,1);
		if(validate_asm(a) == 0)
		{
			outString(hPipe," [ERR] asm_commit(asmobj) / asmobj was not a valid asm buffer\n");
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] asm_commit(asmobj) requires 1 argument\n");
		return 0;
	}

	char mbuf[1024];
	sprintf(mbuf," [NFO] committing %d lines of assembly\n",a->lineCount);
	outString(hPipe,mbuf);

	// a->lines[a->lineCount] = strdup(newLine);
	// a->lineCount += 1;

	XEDPARSE parse;
	memset(&parse, 0, sizeof(parse));
	parse.x64 = false;
	if(a->architecture == 64)
	{
		parse.x64 = true;
	}

	int i = 0;
	char *assemblyBuf = (char *)malloc(a->lineCount * 15);
	int writeHeader = 0;

	parse.cip = a->writeHead;

	for( ; i < a->lineCount ; i++)
	{
		parse.cip += writeHeader;
		memset(parse.instr, 0, 256);
		memcpy(parse.instr, a->lines[i], 256);

		XEDPARSE_STATUS status = XEDParseAssemble(&parse);
		if (status == XEDPARSE_ERROR)
		{
			sprintf(mbuf," [ERR] parse error on line %d: %s\n", i , parse.error);
			outString(hPipe,mbuf);
			return 0;
		}
		else
		{
			sprintf(mbuf," 0x%p : %s\n",(void *)(UINT_PTR )parse.cip,parse.instr);
			outString(hPipe,mbuf);
			memcpy( (char *)(assemblyBuf + writeHeader), (char *)&parse.dest[0], parse.dest_size);
			writeHeader += parse.dest_size;
		}
	}

	__try{
		memcpy((void *)a->writeHead,assemblyBuf,writeHeader);
	}
	__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
	{
		sprintf(mbuf," [ERR] access violation. make sure you can write to 0x%p\n",(void *)(a->writeHead));
		outString(hPipe,mbuf);
	}

	free(assemblyBuf);

	return 0;
}

static int cs_assemble(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	UINT_PTR startAddress = 0;
	size_t asmSize;
	char* asmData;

	if (lua_gettop(L) == 2)
	{
		startAddress = (UINT_PTR )lua_tointeger(L,1);
		asmData =  (char *)lua_tolstring( L, 2 ,&asmSize);
	}
	else
	{
		outString(hPipe," [ERR] asm(address,data) requires 2 arguments\n");
		return 0;
	}

	if(asmSize >= 256)
	{
		outString(hPipe," [ERR] assembly data too large (64 byte maximum)\n");
		return 0;
	}

	// http://www.jmpoep.com/thread-223-1-1.html
	/*
		XEDPARSE parse;
        memset(&parse, 0, sizeof(parse));
        parse.x64 = false;
        parse.cip = dwASM;
        memset(parse.instr, 0, 256);
        memcpy(parse.instr, MyDisasm.CompleteInstr, 64);
        XEDPARSE_STATUS status = XEDParseAssemble(&parse);
        if (status == XEDPARSE_ERROR)
        {
                MyOutputDebugStringA("Parse Error:%s", parse.error);
                MyOutputDebugStringA("AddHook Failed:0x%p", dwHookAddr);
                return false;
        }
        memcpy(&Shell[dwASM - dwStart], &parse.dest[0], parse.dest_size);

        dwASM += parse.dest_size;
        MyDisasm.EIP  += nInstLen;
        if (nSize >= 5)
        {
                m_dwRetAddr = MyDisasm.EIP;
                m_dwHookAddr = dwHookAddr;
                break;
        }
	*/
	char mbuf[1024];

	XEDPARSE parse;
	memset(&parse, 0, sizeof(parse));
	#ifdef ARCHI_64
	    parse.x64 = true;
	#else
		parse.x64 = false;
	#endif
    parse.cip = startAddress;

	memset(parse.instr, 0, 256);
    memcpy(parse.instr, asmData, 256);

	XEDPARSE_STATUS status = XEDParseAssemble(&parse);
	if (status == XEDPARSE_ERROR)
    {
		sprintf(mbuf," [ERR] parse error: %s\n",parse.error);
		outString(hPipe,mbuf);
		return 0;
    }
	else
	{
		// outString(hPipe,mbuf);
		lua_pushlstring(L, (const char *)&parse.dest[0], parse.dest_size);
		return 1;
	}
	
	return 0;
}

void printShortResults(HANDLE hPipe,lua_State *L,searchResult *m)
{
	char mbuf[1024];
	if(validateSearchResult(m) == 0)
	{
		return;
	}
	if(m->numSolutions <= 10)
	{
        // luaL_dostring(L,"results = {}");
		int i = 0;
		for( ; i < m->numSolutions; i++)
		{
			sprintf(mbuf," [%d.] 0xp\n",i,(void *)(m->arraySolutions[i]));
			outString(hPipe,mbuf);
            // sprintf(mbuf,"results[%d] = 0x%0x",i,m->arraySolutions[i]);
            // luaL_dostring(L,mbuf);
		}
	}
	else
	{
		sprintf(mbuf," %d results\n",m->numSolutions);
		outString(hPipe,mbuf);
	}
	return;
}

static int cs_bind(lua_State *L)
{
    lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
    char mbuf[1024];

    if(lua_gettop(L) != 2)
    {
        sprintf(mbuf," [ERR] bind(key,cmd) requires 2 args\n");
        outString(hPipe,mbuf);
        return 0;
    }

    char *hotkey = (char *)lua_tostring(L,1);
    char *commandToRun = (char *)lua_tostring(L,2);

	int vkeycode = VkKeyScanEx(hotkey[0],GetKeyboardLayout(0));
	globalHotkeyArray[vkeycode] = strdup(commandToRun);

    // RegisterHotKey (NULL, (int )hotkey[0], MOD_NOREPEAT, (int )hotkey[0]);

    return 0;
}

static int cs_unbind(lua_State *L)
{
    lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
    char mbuf[1024];

    if(lua_gettop(L) != 1)
    {
        sprintf(mbuf," [ERR] unbind(key) requires 1 arg\n");
        outString(hPipe,mbuf);
        return 0;
    }

    char *hotkey = (char *)lua_tostring(L,1);

	int vkeycode = VkKeyScanEx(hotkey[0],GetKeyboardLayout(0));

	free(globalHotkeyArray[vkeycode]);
	globalHotkeyArray[vkeycode] = NULL;

    return 0;
}

#define KEY_UP(vk_code) ((GetAsyncKeyState(vk_code) & 0x8000) ? 1 : 0)
#define KEY_DOWN(vk_code) ((GetAsyncKeyState(vk_code) & 0x8000) ? 0 : 1)

DWORD WINAPI hotkeyThread(LPVOID param)
{
	__registerThread(GetCurrentThreadId());
	lua_State *L = (lua_State *)param;

	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
	int i = 0;

	BYTE keyboardState[256];
	while(true)
	{
		Sleep(globalSleepTime);
		// memset(globalHotkeyArray,0,sizeof( char * ) * 256);
		for ( i = 0; i < 256 ; i++)
		{
			if(globalHotkeyArray[i] != 0)
			{
				// http://www.cplusplus.com/forum/windows/6632/
				if(GetAsyncKeyState(i))
				{
					char *pchRequest = globalHotkeyArray[i];
					if( luaL_loadbuffer(L,pchRequest,strlen(pchRequest),"Timer") == 0 )
					{
						if( lua_pcall(L,0,0,0) )
						{
							cs_error(L,hPipe);
						}
					}
					else
					{
						cs_error(L,hPipe);
					}
				}
			}
		}
	}
	__unregisterThread(GetCurrentThreadId());
}

char *shortName(char *fullName)
{
    if(strlen(fullName) == 0)
    {
        // no nice way to pass interrupt-prints to the peek client
        // so let's have this on hold for now.
        return NULL;
    }
    int i = strlen(fullName) - 1;
    int firstToggle = 0;
    for( ; i > 0; i--)
    {
        // don't accept last character is '\\'
        if(fullName[i] == '\\' && firstToggle == 1)
        {
            return (char *)(fullName + i + 1);
        }
        firstToggle = 1;
    }

    return (char *)(fullName + i);
}

/*
	lua equivalent for CE's "who's writing to this":
	who_is_writing_to(ADDR)
	finish_hook()
*/

static int cs_who_writes_to(lua_State *L)
{
    lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

    char mbuf[1024];

    if(lua_gettop(L) != 2)
    {
        sprintf(mbuf," [ERR] who_writes_to(addr,size) requires 2 args\n");
        outString(hPipe,mbuf);
        return 0;
    }

    UINT_PTR addr = (UINT_PTR )lua_tointeger(L,1);
	int size = (int )lua_tointeger(L,2);
	protectLocation(addr,size,hPipe);

	sprintf(mbuf," [NFO] who_writes_to() active. use finish_who_writes_to() to check results\n");
	outString(hPipe,mbuf);

	sprintf(mbuf," [WRN] this functionality is unstable by nature, and will likely crash the program\n");
	outString(hPipe,mbuf);

    return 0;
}

static int cs_finish_who_writes_to(lua_State *L)
{
	unprotectLocation();
	return 0;
}

UINT_PTR watchPageStart = 0;
UINT_PTR watchPageEnd = 0;

UINT_PTR globalLockStart = 0;
size_t globalLockSize = 0;
DWORD globalLockOldProtect = 0;
HANDLE globalLockhPipe = NULL;

void protectLocation(UINT_PTR start, int size, HANDLE hPipe)
{
	if (globalLockhPipe == NULL)
	{
		globalLockhPipe = hPipe;
		AddVectoredExceptionHandler(1,veh);
		globalLockStart = start;
		globalLockSize = (size_t) size;
		VirtualProtect((LPVOID )globalLockStart,globalLockSize,PAGE_EXECUTE_READ,&globalLockOldProtect);
		return;
	}
	else
	{
		// outString(hPipe," [ERR] global memory page protection handler in use - please unlock first\n");
	}
	return;
}

void unprotectLocation()
{
	if(globalLockhPipe != NULL)
	{
		VirtualProtect((LPVOID )globalLockStart,globalLockSize,globalLockOldProtect,&globalLockOldProtect);
		globalLockhPipe = NULL;
		RemoveVectoredExceptionHandler(veh);
	}
	return;
}

UINT_PTR globalSeenExceptions[1024];
int globalSeenExceptionCount = 0;

LONG CALLBACK veh(EXCEPTION_POINTERS *ExceptionInfo)
{
	UINT_PTR where = (UINT_PTR )ExceptionInfo->ExceptionRecord->ExceptionAddress;
	DWORD oldProtect;

	VirtualProtect((LPVOID )watchPageStart, watchPageEnd - watchPageStart, PAGE_GUARD | PAGE_EXECUTE_READWRITE,&oldProtect);

	CONTEXT *context = (CONTEXT *)malloc(sizeof(CONTEXT));
	memcpy(context,ExceptionInfo->ContextRecord,sizeof(CONTEXT));

	UINT_PTR stackChecksum[1024];
	int stackNum = 0;

	if(ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{	
		#if ARCHI == 64
			
			UINT_PTR stackSum = 0;
			SymInitialize(GetCurrentProcess(), 0, true);
			STACKFRAME64 frame = { 0 };
			frame.AddrPC.Offset         = context->Rip;
			frame.AddrPC.Mode           = AddrModeFlat;
			frame.AddrStack.Offset      = context->Rsp;
			frame.AddrStack.Mode        = AddrModeFlat;
			frame.AddrFrame.Offset      = context->Rbp;
			frame.AddrFrame.Mode        = AddrModeFlat;

			// char mbuf[1024];

			while (StackWalk64(IMAGE_FILE_MACHINE_AMD64 ,
                   GetCurrentProcess(),
                   GetCurrentThread(),
                   &frame,
                   context,
                   0,
                   SymFunctionTableAccess64,
                   SymGetModuleBase64,
                   0 ) )
			 {
				// printf("*");
				stackChecksum[stackNum++] = (UINT_PTR )frame.AddrPC.Offset;
				stackSum += (UINT_PTR )frame.AddrPC.Offset;
			 }

			int i = 0;
			int seenThisBefore = 0;
			for(i = 0; i < globalSeenExceptionCount;i++)
			{
				if(globalSeenExceptions[i] == stackSum)
				{
					seenThisBefore = 1;
					break;
				}
			}
 
			if(seenThisBefore == 0)
			{
				globalSeenExceptions[globalSeenExceptionCount++] = stackSum;
				
				char mbuf[1024];
				for(i = 0;i < stackNum;i++)
				{
					sprintf((char *)(mbuf + (i * 18)),"[0x%p]",(void *)(stackChecksum[i]));
				}

				outString(globalLockhPipe,mbuf);
				outString(globalLockhPipe,"\n");
			}

			SymCleanup(GetCurrentProcess());
			
		#else

			UINT_PTR stackSum = 0;
			SymInitialize(GetCurrentProcess(), 0, true);
			STACKFRAME frame = { 0 };
			frame.AddrPC.Offset         = context->Eip;
			frame.AddrPC.Mode           = AddrModeFlat;
			frame.AddrStack.Offset      = context->Esp;
			frame.AddrStack.Mode        = AddrModeFlat;
			frame.AddrFrame.Offset      = context->Ebp;
			frame.AddrFrame.Mode        = AddrModeFlat;

			while (StackWalk(IMAGE_FILE_MACHINE_I386 ,
                   GetCurrentProcess(),
                   GetCurrentThread(),
                   &frame,
                   context,
                   0,
                   SymFunctionTableAccess,
                   SymGetModuleBase,
                   0 ) )
			 {
				stackChecksum[stackNum++] = (UINT_PTR )frame.AddrPC.Offset;
				stackSum += (UINT_PTR )frame.AddrPC.Offset;
			 }

			int i = 0;
			int seenThisBefore = 0;
			for(i = 0; i < globalSeenExceptionCount;i++)
			{
				if(globalSeenExceptions[i] == stackSum)
				{
					seenThisBefore = 1;
					break;
				}
			}
 
			if(seenThisBefore == 0)
			{
				globalSeenExceptions[globalSeenExceptionCount++] = stackSum;
				
				char mbuf[1024];
				for(i = 0;i < stackNum;i++)
				{
					sprintf((char *)(mbuf + (i * 10)),"[%08x]",stackChecksum[i]);
				}

				outString(globalLockhPipe,mbuf);
				outString(globalLockhPipe,"\n");
			}

			SymCleanup(GetCurrentProcess());
		#endif
		ExceptionInfo->ContextRecord->EFlags |= 0x100;
		VirtualProtect((LPVOID )globalLockStart,globalLockSize,PAGE_EXECUTE_READWRITE,&oldProtect);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if(ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		// printf(" * SINGLE STEP\n");
		VirtualProtect((LPVOID )globalLockStart,globalLockSize,PAGE_EXECUTE_READ,&oldProtect);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}
}

static int cs_msgbox(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 2)
	{
		if(lua_isstring(L,1) && lua_isnumber(L,2))
		{
			int result = MessageBox(0,lua_tostring(L,1),"shackle",lua_tointeger(L,2));
			lua_pushinteger(L,result);
			return 1;
		}
	}
	else if (lua_gettop(L) == 1)
	{
		if(lua_isstring(L,1))
		{
			MessageBox(0,lua_tostring(L,1),"shackle",MB_OK);
		}
		return 0;
	}
	else
	{
		outString(hPipe," [ERR] msgbox() needs 1 or 2 arguments\n");
		return 0;
	}
	return 0;
}
