#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "vtable.h"
#include "shackle.h"

/*
	search_vtable (address)
	-- search backward for a vtable at an aligned address
	-- check for one or more executable functions [no vtable]
*/

int cs_search_vtable(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	char mbuf[1024];

	HANDLE currentProcess = GetCurrentProcess();

	if (lua_gettop(L) == 1)
	{
		UINT_PTR addrFrom = (UINT_PTR )lua_tonumber(L,1);
		__try{
			while(true)
			{
				if(isExecutableRegion(addrFrom))
				{

				}
				addrFrom -= 4;
			}
		}
		__except(true)
		{
			outString(hPipe," [ERR] cant read here, check memory protection\n");
			return 0;
		}
		// we have a vtable
	}
	else
	{
		outString(hPipe," [ERR] search_vtable requires 1 argument, address to search backward from\n");
		return 0;
	}
	return 0;
}
