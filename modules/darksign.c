#include <stdio.h>
#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lualib.h>
#include "shackle.h"
#include "darksign.h"
#include "winnt_structs.h"

#define MODE_EXE 0
#define MODE_DLL 1

ULONG_PTR darksign_reflect(ULONG_PTR payload_addr, int filesize,int mode)
{
	USHORT usCounter;

	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
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

	// STEP 0: calculate our images current base address	
	uiLibraryAddress = (ULONG_PTR )payload_addr;
	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = (ULONG_PTR)VirtualAlloc( NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while( uiValueA-- )
		*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

	// STEP 3: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
	
	// itterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while( uiValueE-- )
	{
		// uiValueB is the VA for this section
		uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

		// uiValueC if the VA for this sections data
		uiValueC = ( uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		while( uiValueD-- )
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	
	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );
	
	// itterate through all imports
	while( ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name )
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)LoadLibraryA( (LPCSTR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk );
	
		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk );

		// itterate through all imported functions, importing by ordinal if no name present
		while( DEREF(uiValueA) )
		{
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
				DEREF(uiValueA) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = ( uiBaseAddress + DEREF(uiValueA) );

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)GetProcAddress( (HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name );
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
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

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
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW )
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH )
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW )
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				uiValueD += sizeof( IMAGE_RELOC );
			}

			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}


	NTFLUSHINSTRUCTIONCACHE NtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE  )GetProcAddress(GetModuleHandle("ntdll"),"NtFlushInstructionCache");

	uiValueA = ( uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint );
	NtFlushInstructionCache( (HANDLE)-1, NULL, 0 );
	
	if(mode == MODE_DLL)
	{	
		((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL );
	}
	else
	{
		
		__asm{
			int 3
			mov eax, uiValueA
		}
		// need to update some structs in the PEB / TEB
		((WINMAIN)uiValueA)( (HINSTANCE)0XCCDDCCDD, 0,"pew", SW_SHOW );
		
	}

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return uiValueA;
}

int cs_darksign_reflect_raw(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char *targetDll = NULL;
	char mbuf[256];
	
	if (lua_gettop(L) == 1)
	{
		if(lua_isstring(L,1))
		{
			size_t filesize = 0;
			ULONG_PTR payload_addr = (ULONG_PTR )lua_tolstring(L,1,&filesize);
			// targetDll = (char *)lua_tostring(L,1);
			
			if(filesize ==0)
			{
				sprintf(mbuf," [INFO] darksign reflect: couldn't correctly demarshal payload, failing\n");
				outString(hPipe,mbuf);
				return 0;
			}
			
			if(((char *)payload_addr)[0] != 'M' ||  ((char *)payload_addr)[1] != 'Z')
			{
				sprintf(mbuf," [INFO] darksign reflect: couldn't detect MZ header, sanity failed\n");
				outString(hPipe,mbuf);
				return 0;
			}
			
			sprintf(mbuf," [INFO] darksign reflect called with payload size %d\n",(int )filesize);
			outString(hPipe,mbuf);
			
			if(darksign_reflect(payload_addr,(int )filesize,MODE_DLL) == 0)
			{
				sprintf(mbuf," [INFO] darksign reflect failed :(\n");
				outString(hPipe,mbuf);
			}
			else
			{
				sprintf(mbuf," [INFO] darksign reflect ok\n");
				outString(hPipe,mbuf);
			}
		}
	}
	return 0;
}

int cs_darksign_reflect_disk(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char *targetDll = NULL;
	char mbuf[256];
	
	if (lua_gettop(L) == 1)
	{
		if(lua_isstring(L,1))
		{
			targetDll = (char *)lua_tostring(L,1);
			sprintf(mbuf," [INFO] darksign reflect called with target dll %s\n",targetDll);
			outString(hPipe,mbuf);
			
				// we will start searching backwards from our callers return address.
			FILE *f = fopen(targetDll,"rb");
			if(f == NULL)
			{
				return 0;
			}
			fseek(f,0,SEEK_END);
			int filesize = ftell(f);
			fseek(f,0,SEEK_SET);
			ULONG_PTR payload_addr = (ULONG_PTR )malloc(filesize);
			fread((void *)payload_addr,1,filesize,f);
			fclose(f);
			
			if(((char *)payload_addr)[0] != 'M' ||  ((char *)payload_addr)[1] != 'Z')
			{
				sprintf(mbuf," [INFO] darksign reflect: couldn't detect MZ header, sanity failed\n");
				outString(hPipe,mbuf);
				return 0;
			}
			
			if(darksign_reflect(payload_addr,filesize,MODE_DLL) == 0)
			{
				sprintf(mbuf," [INFO] darksign reflect failed :(\n");
				outString(hPipe,mbuf);
			}
			else
			{
				sprintf(mbuf," [INFO] darksign reflect ok\n");
				outString(hPipe,mbuf);
			}
			free((void *)payload_addr);
		}
	}
	return 0;
}

int cs_darksign_hollow(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char mbuf[256];
	
	sprintf(mbuf," [INFO] darksign hollow called, testing for now...\n");
	outString(hPipe,mbuf);
	
	self_hollow(hPipe);
	
	return 0;
}

void self_hollow(HANDLE hPipe)
{
	int selfpid = GetProcessId(GetCurrentProcess());
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,GetProcessId(GetCurrentProcess()));
	THREADENTRY32 te;
	memset(&te,0,sizeof(te));
	te.dwSize = sizeof(te);
	
	char mbuf[256];
		int threadID = GetThreadId(GetCurrentThread());
	sprintf(mbuf," [INFO] hollowing: terminating all threads but self (%d)\n",threadID);
	outString(hPipe,mbuf);

	// HANDLE hThisThread = GetCurrentThread();

	
	int bCont = Thread32First(hSnap,&te);
	while(bCont == TRUE)
	{	
		if(te.th32ThreadID != threadID && te.th32OwnerProcessID == selfpid)
		{
			HANDLE hThreadToTerminate = OpenThread(THREAD_SUSPEND_RESUME,FALSE,te.th32ThreadID);
			if(hThreadToTerminate == NULL)
			{
				sprintf(mbuf," [INFO] hollowing: could not open own thread %d\n",te.th32ThreadID);
				outString(hPipe,mbuf);
			}
			else
			{
				sprintf(mbuf," [INFO] hollowing: suspending thread %d\n",te.th32ThreadID);
				outString(hPipe,mbuf);
				SuspendThread(hThreadToTerminate);
			}
		}
		bCont = Thread32Next(hSnap,&te);
	}
	
	sprintf(mbuf," [INFO] hollowing: threads suspended, finding base of current executable\n");
	outString(hPipe,mbuf);
	
	// stolen from iathook
	
	HMODULE hMods[1024];
	DWORD cbNeeded = 0;
	MODULEINFO modInfo;
	HANDLE hProcess = GetCurrentProcess();

	EnumProcessModules( GetCurrentProcess(), hMods, sizeof(hMods),&cbNeeded);
	
	UINT_PTR lpBase = NULL;

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
	
	sprintf(mbuf," [INFO] hollowing: found base at 0x%p, unmapping\n",(void *)lpBase);
	outString(hPipe,mbuf);
	
	if(UnmapViewOfFile((LPCVOID )lpBase) == 0)
	{
		sprintf(mbuf," [INFO] could not unmap\n");
		outString(hPipe,mbuf);
	}
	else
	{
		sprintf(mbuf," [INFO] unmap good, keep going!\n");
		outString(hPipe,mbuf);
	}
	
	
	sprintf(mbuf," [INFO] prepping HOLLOW_LOADER_INFO care package\n");
	outString(hPipe,mbuf);
	
	DWORD threadId;
	HOLLOW_LOADER_INFO *hli = (HOLLOW_LOADER_INFO *)malloc(sizeof(HOLLOW_LOADER_INFO));
	FILE *f = fopen("c:\\projects\\doxastica\\reflect.dll","rb");
	fseek(f,0,SEEK_END);
	hli->uiFilesize = ftell(f);
	fseek(f,0,SEEK_SET);
	hli->lpPayloadData = (ULONG_PTR )malloc((size_t )hli->uiFilesize);
	fread((void *)hli->lpPayloadData,1,hli->uiFilesize,f);
	fclose(f);
	
	sprintf(mbuf," [INFO] invoking rite of hollowing...\n");
	outString(hPipe,mbuf);
	
	darksign_reflect((ULONG_PTR )hli->lpPayloadData, hli->uiFilesize,MODE_EXE);
	
	return;
}