#include <stdio.h>
#include <stdlib.h>
extern "C"
{
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "pcontrol.h"
#include "shackle.h"
#include "beaengine\beaengine.h"

DWORD globalThreadArray[1024];
int totalThreads = 0;
int threadIdHead = 0;

CRITICAL_SECTION CriticalSection;

void outString_i(HANDLE hPipe, char *thisMsg)
{
	DWORD bytesWritten = 0;
	WriteFile(hPipe,thisMsg,strlen(thisMsg) + 1,&bytesWritten,NULL);
	OutputDebugString(thisMsg);
	return;
}

// only saves 1024 locations. if you have more than 1024
// locations writing to a given memory address, you're
// probably writing too much.

UINT_PTR globalSolutions[1024];
int globalSolutions_writeCount[1024];
char *globalSolutions_bytes[1024];
int globalSolutions_isOverflow = 0;

int canSetNewBreak = 1;
int needToFreeGSB = 0;

int vehTriggered = 0;

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

int cs_fetch_dword(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 1)
	{
		DWORD *addrTo = (DWORD * )(UINT_PTR )lua_tointeger(L,1);
		DWORD value = 0;
		__try{
			value = addrTo[0];
			lua_pushinteger(L,value);
			return 1;
		}
		__except(TRUE)
		{
			outString_i(hPipe," [ERR] cant read here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString_i(hPipe," [ERR] fetch_dword(dest) requires 1 argument\n");
		return 0;
	}
	return 0;
}

int cs_fetch_word(lua_State *L)
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
			lua_pushinteger(L,value);
			return 1;
		}
		__except(TRUE)
		{
			outString_i(hPipe," [ERR] cant read here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString_i(hPipe," [ERR] fetch_word(dest) requires 1 argument\n");
		return 0;
	}
	return 0;
}

int cs_fetch_byte(lua_State *L)
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
			lua_pushinteger(L,value);
			return 1;
		}
		__except(TRUE)
		{
			outString_i(hPipe," [ERR] cant read here, check memory protection\n");
			return 0;
		}
	}
	else
	{
		outString_i(hPipe," [ERR] db(dest) requires 1 argument\n");
		return 0;
	}
	return 0;
}

int cs_resumethreads(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	DWORD ownProcess = GetCurrentProcessId();
	DWORD ownThread = GetCurrentThreadId();
	THREADENTRY32 te32;

	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		outString_i(hPipe," [ERR] createtoolhelp32snapshot failed\n");
		return 0;
	}

	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString_i(hPipe," [ERR] thread32first returned 0, what's up?\n");
		return 0;
	}

	totalThreads = 0;

	do
	{
		// don't worry about our own threads.
		if(te32.th32OwnerProcessID == ownProcess && te32.th32ThreadID != GetCurrentThreadId() && __checkThread(te32.th32ThreadID) == 0)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);
			ResumeThread(hThread);
			CloseHandle(hThread);
			totalThreads += 1;
		}
	}
	while (Thread32Next(hThreadSnap,&te32));
	CloseHandle(hThreadSnap);

	lua_pushinteger(L,totalThreads);
	return 1;
}

int cs_stopthreads(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	DWORD ownProcess = GetCurrentProcessId();
	DWORD ownThread = GetCurrentThreadId();
	THREADENTRY32 te32;


	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		outString_i(hPipe," [ERR] createtoolhelp32snapshot failed\n");
		return 0;
	}

	// can you deny this?
	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString_i(hPipe," [ERR] thread32first returned 0, what's up?\n");
		return 0;
	}

	totalThreads = 0;

	do
	{
		// don't worry about our own threads.
		if(te32.th32OwnerProcessID == ownProcess && te32.th32ThreadID != GetCurrentThreadId() && __checkThread(te32.th32ThreadID) == 0)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);
			SuspendThread(hThread);
			CloseHandle(hThread);
			totalThreads += 1;
		}
	}
	while (Thread32Next(hThreadSnap,&te32));
	CloseHandle(hThreadSnap);

	lua_pushinteger(L,totalThreads);
	return 1;
}

int cs_listthreads(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	cProcInfo i_Proc;
	DWORD u32_Error = i_Proc.Capture();
	if(u32_Error)
	{
		outString_i(hPipe," [ERR] i_Proc.Capture() failed\n");
        return 0;
	}

	SYSTEM_PROCESS *pk_Proc = i_Proc.FindProcessByPid(GetCurrentProcessId());
	if(!pk_Proc)
	{
		outString_i(hPipe," [ERR] i_Proc.FindProcessByPid() failed\n");
		return 0;
	}

	char mbuf[1024];
	memset(mbuf,0,1024);

	DWORD ownProcess = GetCurrentProcessId();
	DWORD ownThread = GetCurrentThreadId();
	THREADENTRY32 te32;

	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		outString_i(hPipe," [ERR] createtoolhelp32snapshot failed\n");
		return 0;
	}

	// can you deny this?
	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString_i(hPipe," [ERR] thread32first returned 0, what's up?\n");
		return 0;
	}

	totalThreads = 0;

	lua_newtable(L);

	do
	{
		// don't worry about our own threads.
		if(te32.th32OwnerProcessID == ownProcess && te32.th32ThreadID != GetCurrentThreadId() && __checkThread(te32.th32ThreadID) == 0)
		{
			SYSTEM_THREAD *pk_Thread = i_Proc.FindThreadByTid(pk_Proc,te32.th32ThreadID);

			char threadPaused = '?';

			if(pk_Thread)
			{
				if(pk_Thread->dThreadState == Waiting && pk_Thread->WaitReason == Suspended)
				{
					threadPaused = 'Y';
				}
				else
				{
					threadPaused = 'N';
				}
				sprintf(mbuf," + %d [pause:%c] [addr:0x%p]\n",te32.th32ThreadID,threadPaused,pk_Thread->pStartAddress);	
			}
			else
			{
				sprintf(mbuf," + %d\n",te32.th32ThreadID);
			}

			outString_i(hPipe,mbuf);
			lua_pushinteger(L,totalThreads);
			lua_pushinteger(L,te32.th32ThreadID);
			lua_settable(L,-3);
			totalThreads += 1;
		}
	}
	while (Thread32Next(hThreadSnap,&te32));

	CloseHandle(hThreadSnap);
	return 1;
}

void __initThreadList()
{
	int i = 0;
	for(;i < 1024;i++)
	{
		globalThreadArray[i] = 0;
	}
	return;
}

void __registerThread(DWORD threadId)
{
	if(threadId != 0)
	{
		globalThreadArray[threadIdHead] = threadId;
		threadIdHead++;
	}
	return;
}

// lol fuck what
void __unregisterThread(DWORD threadId)
{
	int i = 0;
	for(; i < threadIdHead;i++)
	{
		if(globalThreadArray[i] == threadId)
		{
			globalThreadArray[i] = 0;
			i++;
			break;
		}
	}

	for(;i < threadIdHead;i++)
	{
		globalThreadArray[i - 1] = globalThreadArray[i];
	}

	threadIdHead--;

	return;
}

// 1 if we know about this thread
// 0 if we don't.
int __checkThread(DWORD threadId)
{
	int i = 0;
	for(; i < threadIdHead; i++)
	{
		if(globalThreadArray[i] == threadId)
		{
			return 1;
		}
	}
	return 0;
}

int protectCore(lua_State *L,int protectMode)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char mbuf[1024];
	memset(mbuf,0,1024);

	UINT_PTR protectAddr = 0;
	vehTriggered = 0;

	if (lua_gettop(L) == 1)
	{
		if(lua_isnumber(L,1))
		{
			protectAddr = lua_tointeger(L,1);
		}
	}
	else
	{
		sprintf(mbuf," [ERR] m_who_writes_to() needs an address\n");
		outString_i(hPipe,mbuf);
	}

	if(canSetNewBreak == 0)
	{
		outString_i(hPipe," [ERR] memory breakpoint shared cooldown already in use. m_finish() first.\n");
		return 0;
	}
	canSetNewBreak = 0;

	DWORD ownProcess = GetCurrentProcessId();
	DWORD ownThread = GetCurrentThreadId();
	THREADENTRY32 te32;

	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		outString_i(hPipe," [ERR] m_who_writes_to: createtoolhelp32snapshot failed\n");
		return 0;
	}

	// can you deny this?
	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString_i(hPipe," [ERR] m_who_writes_to: thread32first returned 0\n");
		return 0;
	}

	totalThreads = 0;

	InitializeCriticalSectionAndSpinCount(&CriticalSection,0x400);

	memset(globalSolutions,0,sizeof(UINT_PTR) * 1024);
	memset(globalSolutions_writeCount,0,sizeof(int) * 1024);
	if(needToFreeGSB == 0)
	{
		needToFreeGSB = 1;
		memset(globalSolutions_bytes,0,sizeof(char *) * 1024);
	}
	else
	{
		int i = 0;
		for(; i < 1024;i++)
		{
			if(globalSolutions_bytes[i] != NULL)
			{
				free(globalSolutions_bytes[i]);
			}
		}
		memset(globalSolutions_bytes,0,sizeof(char *) * 1024);
	}
	globalSolutions_isOverflow = 0;

	AddVectoredExceptionHandler(1,veh_m);

	do
	{
		// don't worry about our own threads.
		if(te32.th32OwnerProcessID == ownProcess && te32.th32ThreadID != GetCurrentThreadId() && __checkThread(te32.th32ThreadID) == 0)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);
			SuspendThread(hThread);
			protectSingleThread(hThread,protectAddr,protectMode);
			ResumeThread(hThread);
			CloseHandle(hThread);
			totalThreads += 1;
		}
	}
	while (Thread32Next(hThreadSnap,&te32));
	CloseHandle(hThreadSnap);

	sprintf(mbuf," [NFO] protected %d threads\n",totalThreads);
	outString_i(hPipe,mbuf);

	lua_pushinteger(L,totalThreads);
	return 1;
}

int cs_m_who_writes_to(lua_State *L)
{
	return protectCore(L,PROTECT_WRITE);
}

int cs_m_who_reads_from(lua_State *L)
{
	return protectCore(L,PROTECT_READ);
}

int cs_m_who_accesses(lua_State *L)
{
	return protectCore(L,PROTECT_READ | PROTECT_WRITE);
}

// something is broken here.
int cs_m_finish_who_writes_to(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if(canSetNewBreak == 1)
	{
		outString_i(hPipe," [ERR] no break in place, m_who_writes_to first\n");
		return 0;
	}

	canSetNewBreak = 1;

	char mbuf[1024];


	DWORD ownProcess = GetCurrentProcessId();
	DWORD ownThread = GetCurrentThreadId();
	THREADENTRY32 te32;

	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		outString_i(hPipe," [ERR] m_who_writes_to: createtoolhelp32snapshot failed\n");
		return 0;
	}

	// can you deny this?
	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString_i(hPipe," [ERR] m_who_writes_to: thread32first returned 0\n");
		return 0;
	}

	totalThreads = 0;

	do
	{
		// don't worry about our own threads.
		if(te32.th32OwnerProcessID == ownProcess && te32.th32ThreadID != GetCurrentThreadId() && __checkThread(te32.th32ThreadID) == 0)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);
			SuspendThread(hThread);
			unprotectSingleThread(hThread);
			ResumeThread(hThread);
			CloseHandle(hThread);
			totalThreads += 1;
		}
	}
	while (Thread32Next(hThreadSnap,&te32));

	RemoveVectoredExceptionHandler(veh_m);
	DeleteCriticalSection(&CriticalSection);

	CloseHandle(hThreadSnap);

	int i =0;

	char mbuf_resolve[1024];

	if(globalSolutions_isOverflow)
	{
		outString_i(hPipe," [NFO] overflow flag set = over 1024 access violations\n");
	}
	else
	{
		lua_newtable(L);

		int i = 0;

		char mbuf[1024];        // sprintf buffer
		char tempBuf[15];       // temp buf
		int currentHeader = 0;
		DISASM *d = (DISASM *)malloc(sizeof(DISASM));
		for ( i = 0; i < 1024 ; i++)
		{
			if(globalSolutions_bytes[i] == 0)
			{
				break;
			}

			lua_pushinteger(L,i);
			lua_pushinteger(L,globalSolutions[i]);
			lua_settable(L,-3);

			// doesn't work - never hits "except"
			__try
			{
				memset(d,0,sizeof(DISASM));
				d->Archi = ARCHI;
				int len = 0;
				d->EIP = (UIntPtr )globalSolutions_bytes[i];
				Disasm(d);
				if(globalSolutions[i] != 0)
				{
					unresolve(globalSolutions[i],mbuf_resolve);
					sprintf(mbuf," + [ADDR:0x%p(%s)] [WRITECOUNT:%d] [DISASM:%s]\n",(void *)globalSolutions[i],mbuf_resolve,globalSolutions_writeCount[i],d->CompleteInstr);
					outString_i(hPipe,mbuf);
				}
				else
				{
					break;
				}
			}
			__except(TRUE)
			{
				sprintf(mbuf," + [ADDR:0x%p] [WRITECOUNT:%d] NO DISASSEMBLY\n",(void *)globalSolutions[i],globalSolutions_writeCount[i]);
				outString_i(hPipe,mbuf);
			}
		}
		free(d);
	}

	sprintf(mbuf," [NFO] unprotected %d threads, %d results [vehTriggered = %d]\n",totalThreads,i,vehTriggered);
	outString_i(hPipe,mbuf);

	return 1;
}

// we only have a single register
void protectSingleThread(HANDLE hThread, UINT_PTR protectLocation, int protectMode)
{
	/*
	http://www.logix.cz/michal/doc/i386/chp12-02.htm

      31              23              15              7             0
     +---+---+---+---+---+---+---+---+---+-+-----+-+-+-+-+-+-+-+-+-+-+
     |LEN|R/W|LEN|R/W|LEN|R/W|LEN|R/W|   | |     |G|L|G|L|G|L|G|L|G|L|
     |   |   |   |   |   |   |   |   |0 0|0|0 0 0| | | | | | | | | | | DR7
     | 3 | 3 | 2 | 2 | 1 | 1 | 0 | 0 |   | |     |E|E|3|3|2|2|1|1|0|0|
     |---+---+---+---+---+---+---+---+-+-+-+-----+-+-+-+-+-+-+-+-+-+-|

	*/
	CONTEXT c;
	c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread,&c);
	c.Dr6 = 0;
    c.Dr0 = protectLocation;
	if(protectMode == PROTECT_READ)
	{
		// 0b00000000000011100000000000000011
		c.Dr7 = 0xD0003;
	}
	else if (protectMode == PROTECT_WRITE)
	{
		// 0b00000000000011100000000000000011
		c.Dr7 = 0xE0003;
	}
	else if(protectMode == (PROTECT_READ | PROTECT_WRITE ) )
	{
		c.Dr7 = 0xF0003;
	}
	else
	{
		// outString_i(hPipe," [ERR] need PROTECT_READ or PROTECT_WRITE when trying to mem break\n")
		return;
	}
	// c.Dr7 = 0xff55ffff; // 0b11111111010101011111111111111111;
	SetThreadContext(hThread,&c);
	return;
}

// AddVectoredExceptionHandler(1,veh_m);
// RemoveVectoredExceptionHandler(veh_m);

void unprotectSingleThread(HANDLE hThread)
{

	CONTEXT c;
	c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread,&c);
	c.Dr6 = 0;
	c.Dr0 = 0;
	c.Dr7 = 0;
	SetThreadContext(hThread,&c);
	return;
}

LONG CALLBACK veh_m(EXCEPTION_POINTERS *ExceptionInfo)
{
	int i;
	int doneFlag = 0;

	if(ExceptionInfo->ContextRecord->Dr6 == 0)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	// does this work, or do i need to roll with SetThreadContext?
	ExceptionInfo->ContextRecord->Dr6 = 0;

	char mbuf[1024];

	// take a look at EIP instead.

	#if ARCHI == 64
		UINT_PTR ea = (UINT_PTR )ExceptionInfo->ContextRecord->Rip;
	#else
		UINT_PTR ea = (UINT_PTR )ExceptionInfo->ContextRecord->Eip;
	#endif
	
	EnterCriticalSection(&CriticalSection);
	vehTriggered++;
	for ( i = 0; i < 1024; i++)
	{
		if(globalSolutions[i] == (UINT_PTR )(ea))
		{
			globalSolutions_writeCount[i] += 1;
			doneFlag = 1;
			break;
		}
		else if(globalSolutions[i] == 0)
		{
			globalSolutions[i] = (UINT_PTR )(ea);
			globalSolutions_writeCount[i] = 1;
			globalSolutions_bytes[i] = (char *)malloc(15);
			memcpy((char * )(globalSolutions_bytes[i]),(char * )ea,15);
			doneFlag = 1;
			break;
		}
	}

	if(doneFlag == 0)
	{
		globalSolutions_isOverflow = 1;
	}

	LeaveCriticalSection(&CriticalSection);
	return EXCEPTION_CONTINUE_EXECUTION;
}

int unresolve(UINT_PTR address, char *mbuf)
{
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
						sprintf(mbuf,shortName(szModName));
						return 1;
					}
					else if(address > (UINT_PTR )modInfo.lpBaseOfDll && address <= (UINT_PTR )((UINT_PTR )modInfo.lpBaseOfDll + modInfo.SizeOfImage))
					{
						sprintf(mbuf,"%s+0x%p",shortName(szModName),(void *)(address - (UINT_PTR )modInfo.lpBaseOfDll));
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

int cs_dump_module(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char mbuf[1024];
	char *dumpfile = (char *)lua_tostring(L,1);

	return 0;
}

// ------------------------------ ? ------------------------------

int cs_dump_everything_we_can(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	char mbuf[1024];
    char filebuf[1024];
	memset(filebuf,0,1024);
	memset(mbuf,0,1024);

	char *savedirectory = (char *)lua_tostring(L,1);

	DWORD dwAttrib = GetFileAttributes(savedirectory);
	if(dwAttrib != INVALID_FILE_ATTRIBUTES)
	{
		sprintf(mbuf," [+] '%s' already exists, not saving anything\n",savedirectory);
		outString_i(hPipe,mbuf);
		return 0;
	}
	else
	{
		sprintf(mbuf," [+] saving to directory '%s'\n",savedirectory);
		outString_i(hPipe,mbuf);
		CreateDirectory(savedirectory,NULL);
	}

	UINT_PTR readStart = 0;
	int skippedPages = 0;
	SYSTEM_INFO si;               // for dwPageSize
	MEMORY_BASIC_INFORMATION mbi; // for query check

	GetSystemInfo(&si);
	#if ARCHI == 64
		UINT_PTR hardMax = (UINT_PTR )si.lpMaximumApplicationAddress;
	#else
		UINT_PTR hardMax = 0x7FFFFFFF;
	#endif

	for( ; readStart < hardMax ; readStart += si.dwPageSize )
	{
		int vqresult = VirtualQuery((LPCVOID )readStart,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
		if(vqresult == 0)
		{
			readStart = (UINT_PTR )((UINT_PTR )mbi.BaseAddress + mbi.RegionSize);
			continue;
		}
		else if(mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
		{
			readStart = (UINT_PTR )((UINT_PTR )mbi.BaseAddress + mbi.RegionSize);
			continue;
		}

		UINT_PTR newReadStart = readStart;
		int readSize = 0;
		while(vqresult != 0 && !(mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS))
		{
			readSize += si.dwPageSize;
			newReadStart += (UINT_PTR )si.dwPageSize;
			VirtualQuery((LPCVOID )newReadStart,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
		}

		sprintf(filebuf,"%s/0x%p-0x%p.out",savedirectory,(void *)readStart,(void *)newReadStart);
		FILE *o = fopen(filebuf,"wb");
		fwrite((char *)readStart,1,newReadStart - readStart,o);
		fclose(o);
	}
	
	return 0;
}

