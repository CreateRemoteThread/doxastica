//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <windows.h>
#include <intrin.h>
#include "shackle.h"
#include "winnt_structs.h"
#include "magicmirror.h"
//===============================================================================================//
// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;
//===============================================================================================//
#pragma intrinsic( _ReturnAddress )
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally 
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of 
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics 
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)_ReturnAddress(); }
//===============================================================================================//

ULONG_PTR WINAPI ReflectiveLoader( REFLECTIVE_LOADER_INFO *preloads )
{
	// the functions we need
	LOADLIBRARYA pLoadLibraryA     = (LOADLIBRARYA )(preloads->fLoadLibraryA);
	GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS )(preloads->fGetProcAddress);
	VIRTUALALLOC pVirtualAlloc     = (VIRTUALALLOC )(preloads->fVirtualAlloc);
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE )(preloads->fNtFlushInstructionCache);
	ULONG_PTR uiLibraryAddress = (ULONG_PTR )(preloads->lpDosHeader);

	USHORT usCounter = 0;

	// the initial location of this image in memory
	ULONG_PTR uiBaseAddress;
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;
	
	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc( NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	
	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while( uiValueA-- )
		*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

	// STEP 3: load in all of our sections...
	uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	
	while( uiValueE-- )
	{
		// uiValueB is the VA for this section
		uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

		// uiValueC = ( uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );
		uiValueC = ( uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

		// copy the section over
		// uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		while( uiValueD-- )
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	
	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );
	
	// itterate through all imports
	while( ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name )
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA( (LPCSTR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );

		uiValueD = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk );
		uiValueA = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk );

		while( DEREF(uiValueA) )
		{
			uiValueB = ( uiBaseAddress + DEREF_32(uiValueD) );
			// sanity check uiValueD as some compilers only import by FirstThunk
			if( uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

				// get the VA of the export directory
				uiExportDir = ( uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

				// get the VA for the array of addresses
				uiAddressArray = ( uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ( ( IMAGE_ORDINAL( ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->Base ) * sizeof(DWORD) );

				// patch in the address for this imported function
				DEREF_32(uiValueA) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = ( uiBaseAddress + DEREF_32(uiValueD) );
				// use GetProcAddress and patch in the address for this imported function
				DEREF_32(uiValueA) = (ULONG_PTR)pGetProcAddress( (HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name );
				// DEREF_32(uiValueA) = 0xAABBCCDD;
			}
			// get the next imported function
			uiValueA += sizeof( ULONG_PTR );
			if( uiValueD )
				uiValueD += sizeof( ULONG_PTR );
		}

		// get the next import
		uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
	}

	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	ULONG_PTR oldLibraryAddress = (ULONG_PTR )(preloads->lpPreviousRelocBase);
	uiLibraryAddress = uiBaseAddress; //  - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
	((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase = uiLibraryAddress;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
	
	// check if their are any relocations present
	if( ((PIMAGE_DATA_DIRECTORY)uiValueB)->Size )
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

		// and we itterate through all entries...
		while( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock )
		{
			// uiValueA = the VA for this relocation block
			uiValueA = ( uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress );

			// uiValueB = number of entries in this relocation block
			uiValueB = ( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while( uiValueB-- )
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64 )
				{
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) -= oldLibraryAddress;
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
					// *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) = (DWORD)0xFFFFFFFF;
				}
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW )
				{
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) -= (DWORD)oldLibraryAddress;
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
					// *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) = (DWORD)0xFFFFFFFF;
				}
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH )
				{
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) -= HIWORD(oldLibraryAddress);
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
					// *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) = 0xFFFF;
				}
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW )
				{
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) -= LOWORD(oldLibraryAddress);
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);
					// *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) = 0xFFFF;
				}

				// get the next entry in the current relocation block
				uiValueD += sizeof( IMAGE_RELOC );
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}
	
	// uiValueA = (ULONG_PTR )uiBaseAddress + (ULONG_PTR )(preloads->lpRVADllMain);
	uiValueA = (ULONG_PTR )uiBaseAddress +  ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint ;

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );

	// uiValueA = (ULONG_PTR )uiBaseAddress + (ULONG_PTR )(preloads->lpRVADllMain);

	__asm{
		int 3
	}
	// ((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_DETACH, NULL );	
	((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL );

	return uiValueA;
}

// fuckit just copy 5MB.
#define MAGICMIRROR_SIZE 5*1024*1024
int cs_magicmirror(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	int targetPid = 0;
	char mbuf[256];
	
	if (lua_gettop(L) == 1)
	{
		targetPid = lua_tointeger(L,1);
		sprintf(mbuf," [INFO] magic mirror called with target pid %d. finding own address\n",targetPid);
		outString(hPipe,mbuf);
		
		
		UINT_PTR uiLibraryAddress = caller();
		ULONG_PTR uiHeaderValue;
		
		while( TRUE )
		{
			if( ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE )
			{
				uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
				if( uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024 )
				{
					uiHeaderValue += uiLibraryAddress;
					if( ((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE )
						break;
				}
			}
			uiLibraryAddress--;
		}
		
		UINT_PTR rl_offset = (UINT_PTR )ReflectiveLoader - uiLibraryAddress;
		
		sprintf(mbuf," [INFO] own header located at 0x%p, offset to loader is at %p\n",(void *)uiLibraryAddress,(void *)rl_offset);
		outString(hPipe,mbuf);
		
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,targetPid);
		if (hProcess == NULL)
		{
			outString(hPipe," [FAIL] could not open process\n");
			return 0;
		}
		
		SIZE_T bW = 0;
		unsigned long oldProtect;
		
		outString(hPipe," [INFO] deploying magic mirror...\n");
		UINT_PTR remoteMemory = (UINT_PTR )VirtualAllocEx(hProcess,NULL,MAGICMIRROR_SIZE,MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(hProcess,(LPVOID )remoteMemory,(LPCVOID )uiLibraryAddress,MAGICMIRROR_SIZE,&bW);
		
		VirtualProtectEx(hProcess,(LPVOID )remoteMemory,MAGICMIRROR_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
		sprintf(mbuf," [INFO] %d bytes of magic mirror written, remote loc is %p\n",bW,(void *)remoteMemory);
		outString(hPipe,mbuf);
		
		outString(hPipe," [INFO] assembling care package...\n");
		REFLECTIVE_LOADER_INFO preloads;
		preloads.lpPreviousRelocBase = (LPVOID )uiLibraryAddress;
		preloads.lpDosHeader = (LPVOID )remoteMemory;
		preloads.fLoadLibraryA = (FARPROC )GetProcAddress(GetModuleHandle("kernel32"),"LoadLibraryA");
		preloads.fGetProcAddress = (FARPROC )GetProcAddress(GetModuleHandle("kernel32"),"GetProcAddress");
		preloads.fVirtualAlloc = (FARPROC )GetProcAddress(GetModuleHandle("kernel32"),"VirtualAlloc");
		preloads.fNtFlushInstructionCache = (FARPROC )GetProcAddress(GetModuleHandle("ntdll"),"NtFlushInstructionCache");
		preloads.lpRVADllMain = (LPVOID )(void *)((ULONG_PTR )&DllMain - uiLibraryAddress);
		
		outString(hPipe," [INFO] deploying care package...\n");
		UINT_PTR remoteMemory_carepackage = (UINT_PTR )VirtualAllocEx(hProcess,NULL,sizeof(preloads),MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(hProcess,(LPVOID )remoteMemory_carepackage,(LPCVOID )&preloads,sizeof(preloads),&bW);
		
		sprintf(mbuf," [INFO] DllEntry offset from main at %p\n",(void *)((ULONG_PTR )&DllMain - uiLibraryAddress));
		outString(hPipe,mbuf);

		HANDLE threadId = CreateRemoteThread(hProcess,NULL,5 * 1024 * 1024,(LPTHREAD_START_ROUTINE )(remoteMemory + rl_offset),(void *)remoteMemory_carepackage,NULL,NULL);
		
		if(threadId == NULL)
		{
			outString(hPipe," [FAIL] could not createremotethread\n");
			return 0;
		}
		else
		{
			sprintf(mbuf," [INFO] magic mirror deployed successfully, thread created at %p\n",(void *)(remoteMemory + rl_offset));
			outString(hPipe,mbuf);
			return 0;
		}
	}
	
	return 0;
}