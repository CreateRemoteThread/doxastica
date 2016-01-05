#include <stdio.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <windows.h>
#include "shackle.h"
#include "asmobj.h"
#include "xedparse\src\XEDParse.h"

static int cs_asm_new(lua_State *L)
{

	return 0;
}

static int cs_assemble(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	UINT_PTR startAddress = 0;
	size_t asmSize;
	char* asmData;

	if (lua_gettop(L) == 2)
	{
		startAddress = (UINT_PTR )lua_tonumber(L,1);
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
		outString(hPipe,mbuf);
		lua_pushlstring(L, (const char *)&parse.dest[0], parse.dest_size);
		return 1;
	}

	
	
	return 0;
}
