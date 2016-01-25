#include <stdio.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <windows.h>
#include <tlhelp32.h>
#include "pcontrol.h"
#include "shackle.h"
// process control library (stop threads, memory breaks, etc)

int cs_listthreads(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	DWORD ownProcess = GetCurrentProcessId();
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
	do
	{
		if(te32.th32ProcessID != ownProcess)
		{
			outString(hPipe," [NFO] +1\n");
		}
	}
	while (Thread32Next(hThreadSnap,&te32));

	CloseHandle(hThreadSnap);

	return 0;
}
