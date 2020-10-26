#include <stdio.h>
#include <winsock2.h>
#include <stdlib.h>
#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "lua_socket.h"
#include "shackle.h"

#define VERSION                        "1.00"
#define TIMEOUT                        300
#define MAXSIZE                        20480
#define HOSTLEN                        40
#define CONNECTNUM                  5


#define WIN32_LEAN_AND_MEAN

struct transocket
{
     SOCKET fd1;
     SOCKET fd2;
}transocket;

WSADATA wsaData;
int wsaret = 0;
int wsaStartupDone = 0;

int cs_ls_conn2conn(lua_State *L)
{
  lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
  if (lua_gettop(L) == 4)
	{
    if(!(lua_isnumber(L,2) && lua_isnumber(L,4) && lua_isstring(L,1) && lua_isstring(L,3)))
    {
      outString(hPipe," [ERR] ls_bind2bind requires str,int,str,int\n");
			return 0;
    }
    
    char *connect1Host = (char *)lua_tostring(L,1);
    int connect1Port = lua_tointeger(L,2);
    char *connect2Host = (char *)lua_tostring(L,3);
    int connect2Port = lua_tointeger(L,4);
    if(wsaStartupDone == 0)
		{
			wsaret = WSAStartup(0x202,&wsaData);
			if(wsaret != 0)
			{
				outString(hPipe," [ERR] bind2bind something went wrong in WSAStartup\n");
				return 0;
			}
			wsaStartupDone = 1;
		}

    outString(hPipe," ls_conn2conn preparing...\n");
    conn2conn(connect1Host,connect1Port,connect2Host,connect2Port);
    outString(hPipe," ls_conn2conn thread alive, returning control...\n");
		
  }
  return 0;
}


int cs_ls_bind2bind(lua_State *L)
{
  lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
  if (lua_gettop(L) == 2)
	{
    // tunneling inbound
    if(!(lua_isnumber(L,1) && lua_isnumber(L,2)))
    {
      outString(hPipe," [ERR] ls_bind2bind requires int,int\n");
			return 0;
    }
    
    int listenPort = lua_tointeger(L,1);
    int connectPort = lua_tointeger(L,2);
    if(wsaStartupDone == 0)
		{
			wsaret = WSAStartup(0x202,&wsaData);
			if(wsaret != 0)
			{
				outString(hPipe," [ERR] bind2bind something went wrong in WSAStartup\n");
				return 0;
			}
			wsaStartupDone = 1;
		}

    outString(hPipe," ls_bind2bind preparing...\n");
    bind2bind(listenPort,connectPort);
    outString(hPipe," ls_bind2bind thread alive, returning control...\n");
		
  }
  return 0;
}


int cs_ls_bind2conn(lua_State *L)
{
  // inbound tunnelling.
  lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(UINT_PTR )lua_tointeger(L,-1);
	lua_pop(L,1);
  if (lua_gettop(L) == 3)
	{
    // tunneling inbound
    if(!(lua_isstring(L,2) && lua_isnumber(L,1) && lua_isnumber(L,3)))
    {
      outString(hPipe," [ERR] ls_bind2conn requires int, str, int\n");
			return 0;
    }
    
    int listenPort = lua_tointeger(L,1);
    char *connectHost = (char *)lua_tostring(L,2);
    int connectPort = lua_tointeger(L,3);
    if(wsaStartupDone == 0)
		{
			wsaret = WSAStartup(0x202,&wsaData);
			if(wsaret != 0)
			{
				outString(hPipe," [ERR] bind2conn something went wrong in WSAStartup\n");
				return 0;
			}
			wsaStartupDone = 1;
		}

    outString(hPipe," ls_bind2conn preparing...\n");
    bind2conn(listenPort,connectHost,connectPort);
    outString(hPipe," ls_bind2conn alive, returning control...\n");
		
  }
  return 0;
}

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
      
      char mbuf[1024];
      sprintf(mbuf," [NFO] bind(%d) in listen state...\n",lport);
      
      outString(hPipe,mbuf);
      
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
      
      /*
      TIMEVAL 			timeout;
	
			timeout.tv_sec = 0;
      // control the timeout value??
			timeout.tv_usec = 250000;
			
			int sock_mode = 1;
      
			if (ioctlsocket(serverClient, FIONBIO, &sock_mode) != 0) {
				outString(hPipe," [ERR] accept(lport) ioctlsocket set nonblocking failed\n");
				return 0;
			}
      */
      
      // send();
      // send(serverClient,"test",4,0);
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
        lua_pushinteger(L,-1);
				return 1;
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
    if(x == SOCKET_ERROR)
    {
      lua_pushinteger(L,-1);
			return 1;
    }
    else
    {
      lua_pushinteger(L,(int )x);
      return 1;
    }
	}
	
	}
	else
	{
		outString(hPipe," [ERR] send(sock,data) needs 2 arguments\n");
		return 0;
	}
	return 0;
}


void transmitdata(LPVOID data)
{
     SOCKET fd1, fd2;
     struct transocket *sock;
     struct timeval timeset;
     fd_set readfd,writefd;
     int result,i=0;
     char read_in1[MAXSIZE],send_out1[MAXSIZE];
     char read_in2[MAXSIZE],send_out2[MAXSIZE];
     int read1=0,totalread1=0,send1=0;
     int read2=0,totalread2=0,send2=0;
     int sendcount1,sendcount2;
     int maxfd;
     struct sockaddr_in client1,client2;
     int structsize1,structsize2;
     char host1[20],host2[20];
     int port1=0,port2=0;
     char tmpbuf[100];

     sock = (struct transocket *)data;
     fd1 = sock->fd1;
     fd2 = sock->fd2;

     memset(host1,0,20);
     memset(host2,0,20);
     memset(tmpbuf,0,100);

     structsize1=sizeof(struct sockaddr);
     structsize2=sizeof(struct sockaddr);
     
     if(getpeername(fd1,(struct sockaddr *)&client1,&structsize1)<0)
     {
           strcpy(host1, "fd1");
     }
     else
     {      
//            // printf("[+]got, ip:%s, port:%d\r\n",inet_ntoa(client1.sin_addr),ntohs(client1.sin_port));
           strcpy(host1, inet_ntoa(client1.sin_addr));
           port1=ntohs(client1.sin_port);
     }

     if(getpeername(fd2,(struct sockaddr *)&client2,&structsize2)<0)
     {
           strcpy(host2,"fd2");
     }
     else
     {      
//            // printf("[+]got, ip:%s, port:%d\r\n",inet_ntoa(client2.sin_addr),ntohs(client2.sin_port));
           strcpy(host2, inet_ntoa(client2.sin_addr));
           port2=ntohs(client2.sin_port);
     }

     // printf("[+] Start Transmit (%s:%d <-> %s:%d) ......\r\n\n", host1, port1, host2, port2);
 
     maxfd=max(fd1,fd2)+1;
     memset(read_in1,0,MAXSIZE);
     memset(read_in2,0,MAXSIZE);
     memset(send_out1,0,MAXSIZE);
     memset(send_out2,0,MAXSIZE);
 
     timeset.tv_sec=TIMEOUT;
     timeset.tv_usec=0;

     while(1)
     {
           FD_ZERO(&readfd);
           FD_ZERO(&writefd);
       
           FD_SET((UINT)fd1, &readfd);
           FD_SET((UINT)fd1, &writefd);
           FD_SET((UINT)fd2, &writefd);
           FD_SET((UINT)fd2, &readfd);
       
           result=select(maxfd,&readfd,&writefd,NULL,&timeset);
           if((result<0) && (errno!=EINTR))
           {
                 // printf("[-] Select error.\r\n");
                 break;
           }
           else if(result==0)
           {
                 // printf("[-] Socket time out.\r\n");
                 break;
           }
           
           if(FD_ISSET(fd1, &readfd))
           {
                 /* must < MAXSIZE-totalread1, otherwise send_out1 will flow */
                 if(totalread1<MAXSIZE)
               {
                       read1=recv(fd1, read_in1, MAXSIZE-totalread1, 0);
                       if((read1==SOCKET_ERROR) || (read1==0))
                       {
                             // printf("[-] Read fd1 data error,maybe close?\r\n");
                             break;
                       }
                 
                       memcpy(send_out1+totalread1,read_in1,read1);
                       // s// printf(tmpbuf,"\r\nRecv %5d bytes from %s:%d\r\n", read1, host1, port1);
                       // printf(" Recv %5d bytes %16s:%d\r\n", read1, host1, port1);
                       // // makelog(tmpbuf,strlen(tmpbuf));
                       // // makelog(read_in1,read1);
                       totalread1+=read1;
                       memset(read_in1,0,MAXSIZE);
                 }
           }

           if(FD_ISSET(fd2, &writefd))
           {
                 int err=0;
                 sendcount1=0;
                 while(totalread1>0)
                 {
                       send1=send(fd2, send_out1+sendcount1, totalread1, 0);
                       if(send1==0)break;
                       if((send1<0) && (errno!=EINTR))
                       {
                             // printf("[-] Send to fd2 unknow error.\r\n");
                             err=1;
                             break;
                       }
                       
                       if((send1<0) && (errno==ENOSPC)) break;
                       sendcount1+=send1;
                       totalread1-=send1;

                       // printf(" Send %5d bytes %16s:%d\r\n", send1, host2, port2);
                 }
               
                 if(err==1) break;
                 if((totalread1>0) && (sendcount1>0))
                 {
                       /* move not sended data to start addr */
                       memcpy(send_out1,send_out1+sendcount1,totalread1);
                       memset(send_out1+totalread1,0,MAXSIZE-totalread1);
                 }
                 else
                 memset(send_out1,0,MAXSIZE);
           }
           
           if(FD_ISSET(fd2, &readfd))
           {
                 if(totalread2<MAXSIZE)
                 {
                       read2=recv(fd2,read_in2,MAXSIZE-totalread2, 0);
                       if(read2==0)break;
                       if((read2<0) && (errno!=EINTR))
                       {
                             // printf("[-] Read fd2 data error,maybe close?\r\n\r\n");
                             break;
                       }

                       memcpy(send_out2+totalread2,read_in2,read2);
                       // s// printf(tmpbuf, "\r\nRecv %5d bytes from %s:%d\r\n", read2, host2, port2);
                       // printf(" Recv %5d bytes %16s:%d\r\n", read2, host2, port2);
                       // // makelog(tmpbuf,strlen(tmpbuf));
                 // // makelog(read_in2,read2);
                 totalread2+=read2;
                 memset(read_in2,0,MAXSIZE);
                 }
           }

           if(FD_ISSET(fd1, &writefd))
           {
                 int err2=0;
               sendcount2=0;
               while(totalread2>0)
               {
                     send2=send(fd1, send_out2+sendcount2, totalread2, 0);
                     if(send2==0)break;
                     if((send2<0) && (errno!=EINTR))
                     {
                           // printf("[-] Send to fd1 unknow error.\r\n");
                             err2=1;
                           break;
                     }
                     if((send2<0) && (errno==ENOSPC)) break;
                     sendcount2+=send2;
                     totalread2-=send2;
                       
                       // printf(" Send %5d bytes %16s:%d\r\n", send2, host1, port1);
               }
                 if(err2==1) break;
             if((totalread2>0) && (sendcount2 > 0))
                 {
                       /* move not sended data to start addr */
                       memcpy(send_out2, send_out2+sendcount2, totalread2);
                       memset(send_out2+totalread2, 0, MAXSIZE-totalread2);
                 }
                 else
                       memset(send_out2,0,MAXSIZE);
           }

           Sleep(5);
     }
 
     closesocket(fd1);
     closesocket(fd2);
//      if(method == 3)
//            connectnum --;
     
     // printf("\r\n[+] OK! I Closed The Two Socket.\r\n");
}


void closeallfd()
{
     int i;

     // printf("[+] Let me exit ......\r\n");
     fflush(stdout);

     for(i=3; i<256; i++)
     {
           closesocket(i);      
     }
}

int create_socket()
{
     int sockfd;
     sockfd=socket(AF_INET,SOCK_STREAM,0);
     if(sockfd<0)
     {
           // printf("[-] Create socket error.\r\n");
           return(0);
     }
     
     return(sockfd);      
}

int create_server(int sockfd,int port)
{
     struct sockaddr_in srvaddr;
     int on=1;
   
     memset(&srvaddr, 0, sizeof(struct sockaddr));

     srvaddr.sin_port=htons(port);
     srvaddr.sin_family=AF_INET;
     srvaddr.sin_addr.s_addr=htonl(INADDR_ANY);
 
     setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR, (char*)&on,sizeof(on)); //so I can rebind the port

     if(bind(sockfd,(struct sockaddr *)&srvaddr,sizeof(struct sockaddr))<0)
     {
           // printf("[-] Socket bind error.\r\n");
           return(0);
     }

     if(listen(sockfd,CONNECTNUM)<0)
     {
           // printf("[-] Socket Listen error.\r\n");
           return(0);
     }
     
     return(1);
}

int client_connect(int sockfd,char* server,int port)
{
  struct sockaddr_in cliaddr;
  struct hostent *host;

  if(!(host=gethostbyname(server)))
  {
        // printf("[-] Gethostbyname(%s) error:%s\n",server,strerror(errno));
        return(0);
  }      
 
  memset(&cliaddr, 0, sizeof(struct sockaddr));
  cliaddr.sin_family=AF_INET;
  cliaddr.sin_port=htons(port);
  cliaddr.sin_addr=*((struct in_addr *)host->h_addr);
 
  if(connect(sockfd,(struct sockaddr *)&cliaddr,sizeof(struct sockaddr))<0)
  {
        // printf("[-] Connect error.\r\n");
        return(0);
  }
  return(1);
}

void bind2conn(int port1, char *host, int port2)
{
     SOCKET sockfd,sockfd1,sockfd2;
     struct sockaddr_in remote;
     int size;
     char buffer[1024];

     HANDLE hThread=NULL;
     struct transocket sock;
     DWORD dwThreadID;

     if (port1 > 65535 || port1 < 1)
     {
           // printf("[-] ConnectPort invalid.\r\n");
           return;
     }

     if (port2 > 65535 || port2 < 1)
     {
           // printf("[-] TransmitPort invalid.\r\n");
           return;
     }
     
     memset(buffer,0,1024);

     if((sockfd=create_socket()) == INVALID_SOCKET) return;

     if(create_server(sockfd, port1) == 0)
     {
           closesocket(sockfd);
           return;
     }
     
     size=sizeof(struct sockaddr);
     while(1)
     {
           // printf("[+] Waiting for Client ......\r\n");      
           if((sockfd1=accept(sockfd,(struct sockaddr *)&remote,&size))<0)
           {
                 // printf("[-] Accept error.\r\n");
                 continue;
           }

           // printf("[+] Accept a Client from %s:%d ......\r\n",
           // inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
             if((sockfd2=create_socket())==0)
             {
                   closesocket(sockfd1);
                   continue;      
             }
             // printf("[+] Make a Connection to %s:%d ......\r\n",host,port2);
             fflush(stdout);

           if(client_connect(sockfd2,host,port2)==0)
           {
                 closesocket(sockfd2);
                 MessageBoxA(0,"bind2conn connect failed","bind2conn",MB_OK);
                 // printf(buffer,"[SERVER]connection to %s:%d error\r\n", host, port2);
                 send(sockfd1,buffer,strlen(buffer),0);
                 memset(buffer, 0, 1024);
                 closesocket(sockfd1);
                 continue;
           }
           
           // printf("[+] Connect OK!\r\n");

           sock.fd1 = sockfd1;
           sock.fd2 = sockfd2;

           // MessageBoxA(0,"tcp kick","bind2conn",MB_OK);
           hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)transmitdata, (LPVOID)&sock, 0, &dwThreadID);
           if(hThread == NULL)
           {
                 TerminateThread(hThread, 0);
                 return;
           }

           Sleep(1000);
     }
}

void bind2bind(int port1, int port2)
{
     SOCKET fd1,fd2, sockfd1, sockfd2;
     struct sockaddr_in client1,client2;
     int size1,size2;

     HANDLE hThread=NULL;
     struct transocket sock;
     DWORD dwThreadID;
           
     if((fd1=create_socket())==0) return;
     if((fd2=create_socket())==0) return;

     // printf("[+] Listening port %d ......\r\n",port1);
     fflush(stdout);

     if(create_server(fd1, port1)==0)
     {
           closesocket(fd1);
           return;
     }

     // printf("[+] Listen OK!\r\n");
     // printf("[+] Listening port %d ......\r\n",port2);
     fflush(stdout);
     if(create_server(fd2, port2)==0)
     {
           closesocket(fd2);
           return;
     }

     // printf("[+] Listen OK!\r\n");
     size1=size2=sizeof(struct sockaddr);
     while(1)
     {
           // printf("[+] Waiting for Client on port:%d ......\r\n",port1);
           if((sockfd1 = accept(fd1,(struct sockaddr *)&client1,&size1))<0)
           {
                 // printf("[-] Accept1 error.\r\n");
                 continue;
           }

           // printf("[+] Accept a Client on port %d from %s ......\r\n", port1, inet_ntoa(client1.sin_addr));
           // printf("[+] Waiting another Client on port:%d....\r\n", port2);
             if((sockfd2 = accept(fd2, (struct sockaddr *)&client2, &size2))<0)
             {
                   // printf("[-] Accept2 error.\r\n");
                   closesocket(sockfd1);
                   continue;
             }

           // printf("[+] Accept a Client on port %d from %s\r\n",port2, inet_ntoa(client2.sin_addr));
           // printf("[+] Accept Connect OK!\r\n");

           sock.fd1 = sockfd1;
           sock.fd2 = sockfd2;

           hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)transmitdata, (LPVOID)&sock, 0, &dwThreadID);
           if(hThread == NULL)
           {
                 TerminateThread(hThread, 0);
                 return;
           }

           Sleep(1000);
           // printf("[+] CreateThread OK!\r\n\n");
      }
}


void conn2conn(char *host1,int port1,char *host2,int port2)
{
     SOCKET sockfd1,sockfd2;
     
     HANDLE hThread=NULL;
     struct transocket sock;
     DWORD dwThreadID;
     fd_set fds;
     int l;
     char buffer[MAXSIZE];

     while(1)
     {
/*
           while(connectnum)
           {
                 if(connectnum < CONNECTNUM)
                 {
                       Sleep(10000);
                       break;
                 }
                 else
                 {
                       Sleep(TIMEOUT*1000);
                       continue;
                 }            
           }
*/
           
           if((sockfd1=create_socket())==0) return;
           if((sockfd2=create_socket())==0) return;

           // printf("[+] Make a Connection to %s:%d....\r\n",host1,port1);
           fflush(stdout);
           if(client_connect(sockfd1,host1,port1)==0)
           {
                 closesocket(sockfd1);
                 closesocket(sockfd2);
                 continue;
           }
           
           // fix by bkbll
           // if host1:port1 recved data, than connect to host2,port2
           l=0;
           memset(buffer,0,MAXSIZE);
           while(1)
           {
                 FD_ZERO(&fds);
                 FD_SET(sockfd1, &fds);
                 
                 if (select(sockfd1+1, &fds, NULL, NULL, NULL) == SOCKET_ERROR)
                 {
                       if (errno == WSAEINTR) continue;
                       break;
                 }
                 if (FD_ISSET(sockfd1, &fds))
                 {
                       l=recv(sockfd1, buffer, MAXSIZE, 0);
                       break;
                 }
                 Sleep(5);
           }

           if(l<=0)
           {      
                 // printf("[-] There is a error...Create a new connection.\r\n");
                 continue;
           }
           while(1)
           {
                 // printf("[+] Connect OK!\r\n");
                 // printf("[+] Make a Connection to %s:%d....\r\n", host2,port2);
                 fflush(stdout);
                 if(client_connect(sockfd2,host2,port2)==0)
                 {
                       closesocket(sockfd1);
                       closesocket(sockfd2);
                       continue;
                 }

                 if(send(sockfd2,buffer,l,0)==SOCKET_ERROR)
                 {      
                       // printf("[-] Send failed.\r\n");
                       continue;
                 }

                 l=0;
                 memset(buffer,0,MAXSIZE);
                 break;
           }
     
           // printf("[+] All Connect OK!\r\n");

           sock.fd1 = sockfd1;
           sock.fd2 = sockfd2;

           hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)transmitdata, (LPVOID)&sock, 0, &dwThreadID);
           if(hThread == NULL)
           {
                 TerminateThread(hThread, 0);
                 return;
           }

//            connectnum++;

           Sleep(1000);
           // printf("[+] CreateThread OK!\r\n\n");
     }
}

