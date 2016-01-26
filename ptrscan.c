#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "ptrscan.h"

static int cs_ptrscan(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);


	return 0;
}

int validatePtrResult(ptrResult *p)
{
	__try{
		if (p->signature == PTRSCAN_SIG)
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
