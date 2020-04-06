#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "lua_socket.h"
#include "shackle.h"

WSADATA wsaData;
int wsaret = 0;

int cs_ls_connect(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 2)
	{
		if(lua_isstring(L,1) && lua_isnumber(L,2))
		{
			int result = 0;
			char *server_name= (char *)lua_tostring(L,1);
			int port = (int )lua_tointeger(L,2);
			struct sockaddr_in server;
			unsigned int addr;
			struct hostent *hp;
			wsaret = WSAStartup(0x101,&wsaData);
			if(wsaret != 0)
			{
				outString(hPipe," [ERR] connect(host,port) something went wrong in WSAStartup\n");
				return 0;
			}
			SOCKET conn;
			conn=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
			if(conn==INVALID_SOCKET)
			{
				return 0;
			}
			
			if(server_name[0] >= '0' && server_name[0] <= '9')
			{
				memset(&server, 0, sizeof(server));
				server.sin_addr.s_addr = inet_addr(server_name);
				server.sin_family = AF_INET;
				server.sin_port = htons(port);
			}
			else
			{
				hp = gethostbyname(server_name);
				if(hp == NULL)
				{
					outString(hPipe," [ERR] connect(host,port) error resolving hostname\n");
					return 0;
				}
				memset(&server, 0, sizeof(server));
				memcpy(&(server.sin_addr), hp->h_addr, hp->h_length);
				server.sin_family = hp->h_addrtype;
				server.sin_port = htons(port);
			}
			
			if(connect(conn, (struct sockaddr*)&server, sizeof(server))== SOCKET_ERROR)
			{
				outString(hPipe," [ERR] connect(host,port) could not connect\n");
				return 0;
			}
			else
			{
				outString(hPipe," [OK] connect(host,port) ok!\n");
				lua_pushinteger(L,(int )conn);
				return 1;
			}
		}
	}
	else
	{
		outString(hPipe," [ERR] connect(host,port) needs 2 arguments\n");
		return 0;
	}
	return 0;
}

int cs_ls_closesocket(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tointeger(L,-1);
	lua_pop(L,1);
	
	if (lua_gettop(L) == 1)
	{
		if(lua_isnumber(L,1))
		{
			SOCKET sock = (SOCKET )lua_tointeger(L,1);
			closesocket(sock);
			outString(hPipe," [OK] ls_closesocket() done\n");
			// lua_pushinteger(L,(int )conn);
			return 0;
		}
	}
	else
	{
		outString(hPipe," [ERR] connect(host,port) needs 2 arguments\n");
		return 0;
	}
	return 0;
}