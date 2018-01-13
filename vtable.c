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
	HANDLE hPipe = (HANDLE )(int )lua_tointeger(L,-1);
	lua_pop(L,1);

	char mbuf[1024];

	HANDLE currentProcess = GetCurrentProcess();

	if (lua_gettop(L) == 1)
	{
		#if ARCHI_64
			UINT_PTR *addrFrom = (UINT_PTR *)((int )lua_tointeger(L,1) &  0xFFFFFFFFFFFFFF00);
		#else
			UINT_PTR *addrFrom = (UINT_PTR *)((int )lua_tointeger(L,1) & 0xFFFFFF00);
		#endif
		sprintf(mbuf," [NFO] searching vtable backward from 0x%p\n",addrFrom);
		outString(hPipe,mbuf);
		MEMORY_BASIC_INFORMATION mbi;

		UINT_PTR lastAllocation = 0;
		size_t lastSize = 0;
		DWORD lastProtect = 0;
		DWORD protectMode = 0;

		int currentExec = 0;
		int skipPtr = 0;

		__try{
			while(true)
			{
				UINT_PTR fPtr = (UINT_PTR )(addrFrom[0]);
				if(fPtr >= lastAllocation && fPtr <= (lastAllocation + (UINT_PTR )lastSize - sizeof(fPtr)))
				{
					OutputDebugString("same page\n");
				}
				else
				{
					OutputDebugString("newquery\n");
					int retval = VirtualQuery((LPCVOID )fPtr,&mbi,sizeof(mbi));
					if(retval == 0)
					{
						sprintf(mbuf," [NFO] virtualquery breaking at %x\n",(UINT_PTR )(addrFrom + 4));
						outString(hPipe,mbuf);
						return 0;
					}
					lastAllocation = (UINT_PTR )mbi.AllocationBase;
					lastSize = mbi.RegionSize;
					lastProtect = mbi.AllocationProtect;
				}

				if(lastProtect & PAGE_EXECUTE || lastProtect & PAGE_EXECUTE_READ || lastProtect & PAGE_EXECUTE_READWRITE || lastProtect & PAGE_EXECUTE_WRITECOPY)
				{
					currentExec = 1;
					sprintf(mbuf," [NFO] found executable ptr: %x\n",fPtr);
					outString(hPipe,mbuf);
				}
				else if(currentExec == 1 && skipPtr == 0)
				{
					sprintf(mbuf," [NFO] vtable search ending, hit non-executable section again at %x\n",(UINT_PTR )(addrFrom + 4));
					outString(hPipe,mbuf);
					lua_pushinteger(L,(UINT_PTR )(addrFrom + 4));
					return 1;
				}

				addrFrom = (UINT_PTR *)((char *)(addrFrom - 4));
			}
		}
		__except(true)
		{
			if (protectMode == 1)
			{
				sprintf(mbuf," [NFO] vtable search breaking on unreadable page at %x\n",(UINT_PTR )(addrFrom + 4));
				outString(hPipe,mbuf);
				lua_pushinteger(L,(UINT_PTR )(addrFrom + 4));
				return 1;
			}
			else
			{
				outString(hPipe," [ERR] cant read here, check memory protection / no vtable found\n");
				return 0;
			}
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
