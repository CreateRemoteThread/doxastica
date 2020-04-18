#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <windows.h>
#include <intrin.h>
#include "shackle.h"

#include "gamestuff.h"

typedef struct{
	float x;
	float y;
	float z;
}Vector3;

int cs_toVector3(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 3)
	{
		Vector3 v3;
		v3.x = (float )lua_tonumber(L,1); // 260255.0; // 
		v3.y = (float )lua_tonumber(L,2); // -249336.0; // 
		v3.z = (float )lua_tonumber(L,3); // 1476.0; /// 
		
		lua_pushlstring(L, (const char *)&v3, sizeof(v3));
		return 1;
	}
	else
	{
		outString(hPipe," [ERR] toVector3(x,y,z) needs 3 arguments\n");
		return 0;
	}
	return 0;
}

int cs_fromVector3(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
	
	if (lua_gettop(L) == 1)
	{
		Vector3 *v3 = (Vector3 *)lua_tostring(L,1);
		lua_pushnumber(L, (float )(v3->x));
		lua_pushnumber(L, (float )(v3->y));
		lua_pushnumber(L, (float )(v3->z));
		return 3;
	}
	outString(hPipe," [ERR] fromVector3(bindata) needs 1 argument\n");
	return 0;
}
