#include <stdio.h>
#include <winsock2.h>
#include <stdlib.h>
#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "lua_socket.h"
#include "shackle.h"

#define WIN32_LEAN_AND_MEAN

WSADATA wsaData;
int wsaret = 0;
int wsaStartupDone = 0;

int cs_ls_bind(lua_State *L)
{
  lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
  if (lua_gettop(L) == 1)
  {
    if(lua_isnumber(L,1))
		{
      int result = 0;
      int lport = (int )lua_tointeger(L,1);
			struct sockaddr_in server;
			unsigned int addr;
			struct hostent *hp;
			fd_set 				write_set, err_set;
			unsigned long 		sock_mode;
			if(wsaStartupDone == 0)
			{
			wsaret = WSAStartup(0x202,&wsaData);
			if(wsaret != 0)
			{
				outString(hPipe," [ERR] bind(lport) something went wrong in WSAStartup\n");
				return 0;
			}
			wsaStartupDone = 1;
			}
      
      SOCKET serverListen = INVALID_SOCKET;
      // SOCKET serverClient = INVALID_SOCKET;
      
      struct sockaddr_in sin_serverListen;
      
      serverListen = socket(AF_INET , SOCK_STREAM , 0 );
      
      sin_serverListen.sin_family = AF_INET;
      sin_serverListen.sin_addr.s_addr = INADDR_ANY;
      sin_serverListen.sin_port = htons( lport );
      
      bind(serverListen ,(struct sockaddr *)&sin_serverListen, sizeof(sin_serverListen));
      
      listen(serverListen , 3);
      
      outString(hPipe," [NFO] bind(lport) in listen state...\n");
      
      // int size_sin_serverClient = sizeof(struct sockaddr_in);
      // serverClient = accept(serverListen , (struct sockaddr *)&sin_serverClient, &size_sin_serverClient);
      
      lua_pushinteger(L,(int )serverListen);
      return 1;
    }
    else{
      outString(hPipe," [ERR] bind(lport) lport must be a number\n");
      return 0;
    }
  }
  else
  {
    outString(hPipe," [ERR] bind(lport) requires one argument\n");
		return 0;
  }
}

// you need to pass it a function? lua_docall?
int cs_ls_accept(lua_State *L)
{
  lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 1)
	{
		if(lua_isnumber(L,1))
		{
      SOCKET serverListen = (SOCKET )lua_tointeger(L,1);
      struct sockaddr_in sin_serverClient;
      
      int size_sin_serverClient = sizeof(struct sockaddr_in);
      SOCKET serverClient = serverClient = accept(serverListen , (struct sockaddr *)&sin_serverClient, &size_sin_serverClient);
      
      TIMEVAL 			timeout;
	
			timeout.tv_sec = 0;
      // control the timeout value??
			timeout.tv_usec = 250000;
			
			int sock_mode = 1;
			if (ioctlsocket(serverClient, FIONBIO, &sock_mode) != 0) {
				outString(hPipe," [ERR] accept(lport) ioctlsocket set nonblocking failed\n");
				return 0;
			}
      
      // send();
      send(serverClient,"test",4,0);
      outString(hPipe," [NFO] accept(lport) accepted!\n");
      lua_pushinteger(L,(int )serverClient);
      return 1;
		}
	}
	else
	{
		outString(hPipe," [ERR] accept(lport) needs 1 argument\n");
		return 0;
	}
	return 0;
}

int cs_ls_connect(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
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
			fd_set 				write_set, err_set;
			unsigned long 		sock_mode;
			if(wsaStartupDone == 0)
			{
			wsaret = WSAStartup(0x202,&wsaData);
			if(wsaret != 0)
			{
				outString(hPipe," [ERR] connect(host,port) something went wrong in WSAStartup\n");
				return 0;
			}
			wsaStartupDone = 1;
			}
			SOCKET conn;
			// conn=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
			conn=socket(AF_INET,SOCK_STREAM,0);
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
			
			TIMEVAL 			timeout;
	
			timeout.tv_sec = 0;
      // control the timeout value??
			timeout.tv_usec = 250000;
			
			sock_mode = 1;
			if (ioctlsocket(conn, FIONBIO, &sock_mode) != 0) {
				outString(hPipe," [ERR] connect(host,port) ioctlsocket set nonblocking failed\n");
				return 0;
			}
			
			if(connect(conn, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
			{
				if(WSAGetLastError() ==   WSAEWOULDBLOCK)
				{
					// ignore, this is expected behavior
				}
				else
				{
					outString(hPipe," [ERR] connect(host,port) connect returned nonzero\n");
					return 0;
				}
			}
			
			sock_mode = 0;
			if (ioctlsocket(conn, FIONBIO, &sock_mode) != 0) {
				outString(hPipe," [ERR] connect(host,port) ioctlsocket restore blocking failed\n");
				return 0;
			}
		 
			FD_ZERO(&write_set);
			FD_ZERO(&err_set);
			FD_SET(conn, &write_set);
			FD_SET(conn, &err_set);
 
			select(0, NULL, &write_set, &err_set, &timeout);	
			if(FD_ISSET(conn, &write_set)) {
				outString(hPipe," [OK] connect(host,port) ok!\n");
				lua_pushinteger(L,(int )conn);
				return 1;
			}
			else
			{
				outString(hPipe," [ERR] connect(host,port) connect failed\n");
				return 0;
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
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
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

int cs_ls_recv(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
	
	if (lua_gettop(L) == 2)
	{
		if(lua_isnumber(L,1) && lua_isnumber(L,2))
		{
			SOCKET s = lua_tointeger(L,1);
			int msize = lua_tointeger(L,2);
			
			char *recvbuf = (char *)malloc(msize);
			memset(recvbuf,0,msize);
			int retval = recv(s,recvbuf,msize,0);
			if(retval == SOCKET_ERROR)
			{
				outString(hPipe," [ERR] recv(sock,data) something went wrong, SOCKET_ERROR\n");
				return 0;
			}
			else
			{
				lua_pushlstring(L,(const char *)recvbuf,retval);
				return 1;
			}
		}
	}
	else
	{
		outString(hPipe," [ERR] recv(sock,size) needs 2 arguments\n");
		return 0;
	}
	return 0;
}

int cs_ls_send(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
	
	if (lua_gettop(L) == 2)
	{
	
	char *databuf = NULL;
	size_t msize = 0;
	
	if(lua_isnumber(L,1) && lua_isstring(L,2))
	{
		SOCKET s = lua_tointeger(L,1);
		databuf = (char *)(lua_tolstring(L,2,&msize));
		int x = send(s,databuf,msize,0);
		lua_pushinteger(L,(int )x);
		return 1;
	}
	
	}
	else
	{
		outString(hPipe," [ERR] send(sock,data) needs 2 arguments\n");
		return 0;
	}
	return 0;
}