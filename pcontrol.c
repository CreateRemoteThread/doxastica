#include <stdio.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <windows.h>
#include <tlhelp32.h>
#include "pcontrol.h"
#include "shackle.h"

DWORD globalThreadArray[1024];
int totalThreads = 0;
int threadIdHead = 0;

int cs_resumethreads(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	DWORD ownProcess = GetCurrentProcessId();
	DWORD ownThread = GetCurrentThreadId();
	THREADENTRY32 te32;

	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		outString(hPipe," [ERR] createtoolhelp32snapshot failed\n");
		return 0;
	}

	// can you deny this?
	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString(hPipe," [ERR] thread32first returned 0, what's up?\n");
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

	lua_pushnumber(L,totalThreads);
	return 1;
}

int cs_stopthreads(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	DWORD ownProcess = GetCurrentProcessId();
	DWORD ownThread = GetCurrentThreadId();
	THREADENTRY32 te32;


	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		outString(hPipe," [ERR] createtoolhelp32snapshot failed\n");
		return 0;
	}

	// can you deny this?
	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString(hPipe," [ERR] thread32first returned 0, what's up?\n");
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

	lua_pushnumber(L,totalThreads);
	return 1;
}

int cs_listthreads(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	cProcInfo i_Proc;
	DWORD u32_Error = i_Proc.Capture();
	if(u32_Error)
	{
		outString(hPipe," [ERR] i_Proc.Capture() failed\n");
        return 0;
	}

	SYSTEM_PROCESS *pk_Proc = i_Proc.FindProcessByPid(GetCurrentProcessId());
	if(!pk_Proc)
	{
		outString(hPipe," [ERR] i_Proc.FindProcessByPid() failed\n");
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
		outString(hPipe," [ERR] createtoolhelp32snapshot failed\n");
		return 0;
	}

	// can you deny this?
	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString(hPipe," [ERR] thread32first returned 0, what's up?\n");
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
				sprintf(mbuf," + %d [pause:%c] [addr:0x%x]\n",te32.th32ThreadID,threadPaused,pk_Thread->pStartAddress);	
			}
			else
			{
				sprintf(mbuf," + %d\n",te32.th32ThreadID);
			}

			outString(hPipe,mbuf);
			lua_pushnumber(L,totalThreads);
			lua_pushnumber(L,te32.th32ThreadID);
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

// pop a memory break into every thread
int cs_membreak(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	DWORD ownProcess = GetCurrentProcessId();
	DWORD ownThread = GetCurrentThreadId();
	THREADENTRY32 te32;


	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		outString(hPipe," [ERR] createtoolhelp32snapshot failed\n");
		return 0;
	}

	// can you deny this?
	if(Thread32First(hThreadSnap,&te32) == 0)
	{
		outString(hPipe," [ERR] thread32first returned 0, what's up?\n");
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

	lua_pushnumber(L,totalThreads);
	return 1;
}