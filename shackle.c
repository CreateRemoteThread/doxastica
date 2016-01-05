#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include "beaengine\beaengine.h"
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <signal.h>
#include <ctype.h>
#include "shackle.h"
#include "xedparse\src\XEDParse.h"

#define EOFMARK		"<eof>"
#define marklen		(sizeof(EOFMARK)/sizeof(char) - 1)

// switched to beaengine for 64-bit support

#ifdef ARCHI_64
	#define ARCHI 64
	#define PC_REG Rip
	#define REGISTER_LENGTH DWORD64
	#define FUNCTION_PATCHLEN 14
	#define FUNCTION_SHORTPATCH_HACK 5
	#define INTEL_MAXINSTRLEN 15
	#define FUNCTION_TAILLEN 14
#else
	#define ARCHI 32
	#define PC_REG Eip
	#define REGISTER_LENGTH DWORD
	#define FUNCTION_PATCHLEN 6
	#define FUNCTION_SHORTPATCH_HACK 5
	#define INTEL_MAXINSTRLEN 15
	#define FUNCTION_TAILLEN 7
#endif

#define MANUAL_FUNCTION_PRELUDE 1

int init = 0;

_MessageBoxA oldMessageBox = NULL;
_send oldSend = NULL;
_send oldRecv = NULL;

/*
// okay, what's the function prelude of newmessagebox?
u $ip
shackle64!newMessageBox+0xd [c:\projects\elegurawolfe\shackle.c @ 43]:
00000001`8000100d c60061          mov     byte ptr [rax],61h
00000001`80001010 ff1512360400    call    qword ptr [shackle64!oldMessageBox (00000001`80044628)]
00000001`80001016 33c0            xor     eax,eax
00000001`80001018 4883c428        add     rsp,28h
00000001`8000101c c3              ret

// where does oldMessageBox point? this should be our function prelude
// that we control
0:000> dq 00000001`80044628
00000001`80044628  00000000`00300000 00000000`00000000
00000001`80044638  00000000`00000000 00000000`00000001
00000001`80044648  00000000`00000000 00000000`00000000
00000001`80044658  00000000`00000000 00380c33`da800000
00000001`80044668  00000001`00000000 00000000`01ce5c50
00000001`80044678  00000000`00000000 00000000`01ce5c90
00000001`80044688  00000000`00000000 00000000`00000000
00000001`80044698  00000000`00000000 00000001`80044f70

// this should be our function prelude
// but it looks broken as shit. this SHOULD be:
u 00000000`00300000
00000000`00300000 4883ec38        sub     rsp,38h
00000000`00300004 4533db          xor     r11d,r11d
00000000`00300007 44391dea0d0200  cmp     dword ptr [00000000`00320df8],r11d [ this one fucks us because it's a relative ]
00000000`0030000e ff2500000000    jmp     qword ptr [00000000`00300014]
00000000`00300014 52              push    rdx                           [ SHOULD BE QWORD READ AS DATA ]
00000000`00300015 139177000000    adc     edx,dword ptr [rcx+77h]
00000000`0030001b 0000            add     byte ptr [rax],al
00000000`0030001d 0000            add     byte ptr [rax],al

untouched user32!MessageBoxA:
00000000`77911344 4883ec38        sub     rsp,38h
00000000`77911348 4533db          xor     r11d,r11d
00000000`7791134b 44391dea0d0200  cmp     dword ptr [USER32!gapfnScSendMessage+0x927c (00000000`7793213c)],r11d
*/


#define CL_ON_64BIT_IS_A_PIECE_OF_SHIT 1

#define LUA_MAXINPUT		512

unsigned long WINAPI newMessageBox(unsigned long hwnd,char *msg,char *title,unsigned long flags)
{
	/*
	#ifdef CL_ON_64BIT_IS_A_PIECE_OF_SHIT
		char *p = (char *)0;
		p[0] = 'a';
	#endif
	*/
	oldMessageBox(hwnd,"NERDZ",title,flags);
	return 0;
}

unsigned long newSend(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	int i = oldSend(socket, buf, len, flags);
	OutputDebugString("send\n");
	return i;
}

unsigned long newRecv(unsigned long socket, char *buf, unsigned long len, unsigned long flags)
{
	int i = oldRecv(socket,buf,len,flags);
	OutputDebugString("recv\n");
	return i;
}

// dirty hack we use to enable short patching on 64-bit
// search from the addressFromto an address with "\XC3

UINT_PTR searchForShortCave(UINT_PTR addressFrom,int minLength)
{
	unsigned int maxSearchLen = 10000;
	unsigned int i = 0, n = 0;
	unsigned char *p = (unsigned char *)addressFrom;
	UINT_PTR foundAddress = 0;
	char *mbuf = (char *)malloc(1024);
	// memset(mbuf,0,1024);
	OutputDebugString("searching for short cave\n");
	for( i = 0; i < maxSearchLen;i++)
	{
		/*
		sprintf(mbuf,"[%02x]\00",(unsigned char )p[i]);
		if( i % 16 == 0)
		{
			OutputDebugString("\n");
		}
		*/
		OutputDebugString(mbuf);
		if ((unsigned char )p[i] == (unsigned char )'\xC3')
		{
			// OutputDebugString("\n ---- FOUND ---- \n");
			foundAddress = (UINT_PTR )(p + i + 1);
			for(n = 1;n < minLength;n++)
			{
				if ( (p[i+n] != (unsigned char )'\xCC' ) && (p[i+n] != (unsigned char )'\x00') && (p[i+n] != (unsigned char )'\x90') )
				{
					memset(mbuf,0,1024);
					sprintf(mbuf," exiting search for loop at %x, [%02x]\n" , (UINT_PTR )(p + i + n), (unsigned char )(p[i+n]));
					OutputDebugString(mbuf);
					foundAddress = 0;
				}
			}
			if(foundAddress)
			{
				// OutputDebugString("\n + FOUND \n");
				return (UINT_PTR )(p + i + 1);
			}
		}
	}
	return foundAddress;
}

void hook(UINT_PTR addressFrom, UINT_PTR addressTo, UINT_PTR *saveAddress)
{
	DWORD oldProtect = 0;
	int totalSize = 0;
	DISASM *d = (DISASM *)malloc(sizeof(DISASM));
	
	memset(d,0,sizeof(DISASM));
	d->Archi = ARCHI;
	d->EIP = (UIntPtr )addressFrom;
	totalSize += Disasm(d);

	int shortCutSize = 0;
	shortCutSize = totalSize;
	
	char *mbuf = (char *)VirtualAlloc(NULL,1024,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
	while(totalSize < FUNCTION_PATCHLEN)
	{
		d->EIP = (UIntPtr )(addressFrom + totalSize);
		totalSize += Disasm(d);
		if (shortCutSize < FUNCTION_SHORTPATCH_HACK)
		{
			shortCutSize = totalSize;
		}
	}

	//memset(mbuf,0,1024);
	//sprintf(mbuf," TRYING TO PATCH %x to %x, allocating total len of %d, closest cave %x (searching for cave size %d)\n", addressFrom,addressTo,totalSize, shortCaveAddr, shortCutSize);
	//OutputDebugString(mbuf);

	char *codeCave = (char *)VirtualAlloc(NULL,totalSize + FUNCTION_TAILLEN,MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD unused;
	VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_READWRITE,&oldProtect);

	// what the fuck was i smoking when i wrote this shit and left it in
	// let's virtualprotect right after i virtualprojtect
	// fucking a you imbecile
	// VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_READWRITE,&unused);\

	UINT_PTR shortCaveAddr = searchForShortCave(addressFrom,14);
	if (shortCaveAddr != 0)
	{
		totalSize = shortCutSize;
	}

	memset(codeCave,'\xCC',totalSize);
	memcpy(codeCave,(LPVOID )addressFrom,totalSize);

	#if ARCHI == 32
		codeCave[totalSize] = '\xE9';
		DWORD *cp = (DWORD *)((unsigned long )codeCave + totalSize + 1);
		cp[0] = (unsigned long )(addressFrom + totalSize - ((unsigned long )codeCave + totalSize + 5));
		saveAddress[0] = (unsigned long )codeCave;
		VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_EXECUTE_READ,&unused);
	#else
		codeCave[totalSize] = '\xFF';              // jmp [rip+0]
		codeCave[totalSize + 1] = '\x25';          // or if your name is nasm
		codeCave[totalSize + 2] = '\x00';          // jmp qword [rel $+0x0] then disasm / edit
		codeCave[totalSize + 3] = '\x00';
		codeCave[totalSize + 4] = '\x00';
		codeCave[totalSize + 5] = '\x00';
		UINT_PTR *cp = (UINT_PTR *)(codeCave + totalSize + 6);
		cp[0] = (UINT_PTR )(addressFrom + totalSize); // no need for shitlording with relative addr here
		saveAddress[0] = (UINT_PTR )codeCave;
		VirtualProtect(codeCave,totalSize + FUNCTION_TAILLEN,PAGE_EXECUTE_READ,&unused);
	#endif

	VirtualProtect((LPVOID )addressFrom,FUNCTION_PATCHLEN,PAGE_READWRITE,&oldProtect);
	memset((void *)addressFrom,'\xCC',totalSize);

	char *addressFromWrite = (char *)(addressFrom);

	#if ARCHI == 32
		addressFromWrite[0] = '\xE9';
		DWORD *p =  (DWORD *)((unsigned long ) addressFromWrite + 1 );
		p[0] = (DWORD )(addressTo - ((unsigned long ) addressFrom   + 5));
		VirtualProtect((LPVOID )addressFrom,7,oldProtect,&unused);
	#else
		// on 64-bit systems, search for a 14-byte cave we can jmp to within 0xFFFF
		// this way, we destroy only 5 bytes of the original prelude
		// greatly reducing our chances of fucking shit up.
		
		UINT_PTR *p = 0;

		if (shortCaveAddr != 0)
		{
			// stage 1 trampoline - E9 shortcaveaddr
			// assume this is executable for now, fix this later.
			addressFromWrite[0] = '\xE9';
			DWORD *p1 = (DWORD *)(addressFrom + 1);
			p1[0] = (DWORD )((UINT_PTR )shortCaveAddr - (UINT_PTR )addressFromWrite);
			p1[0] -= 5; // offset of current 5-byte instruction =)
			// stage 2 trampoline - JMP [RIP+0] DQ [absolute oldMessageBoxA]
			unsigned char *shortCaveAddrWrite = (unsigned char *)shortCaveAddr;
			VirtualProtect((LPVOID )shortCaveAddr,FUNCTION_PATCHLEN,PAGE_READWRITE,&unused);
			shortCaveAddrWrite[0] = '\xFF';
			shortCaveAddrWrite[1] = '\x25';
			shortCaveAddrWrite[2] = '\x00';
			shortCaveAddrWrite[3] = '\x00';
			shortCaveAddrWrite[4] = '\x00';
			shortCaveAddrWrite[5] = '\x00';
			p = (UINT_PTR *)(shortCaveAddr + 6);
			p[0] = (UINT_PTR )(addressTo);
			VirtualProtect((LPVOID )shortCaveAddr,FUNCTION_PATCHLEN,PAGE_EXECUTE_READ,&unused);
			VirtualProtect((LPVOID )addressFrom,FUNCTION_PATCHLEN,oldProtect,&unused);
		}
		else
		{
			addressFromWrite[0] = '\xFF';
			addressFromWrite[1] = '\x25';
			addressFromWrite[2] = '\x00';
			addressFromWrite[3] = '\x00';
			addressFromWrite[4] = '\x00';
			addressFromWrite[5] = '\x00';
			p = (UINT_PTR *)(addressFrom + 6);
			p[0] = (UINT_PTR )(addressTo);
			VirtualProtect((LPVOID )addressFrom,14,oldProtect,&unused);
		}
	#endif

	/*

	  hook structure:
	  hookFrom: E9 addressTo
	  addressTo: our function
	  codeCave is the new function
	*/

	memset(mbuf,0,1024);
	#if ARCHI == 32
	sprintf(mbuf,"* [32-BIT] [0x%x] HOOKED %02x %02x%02x%02x%02x (0x%x)\n",(UINT_PTR )addressFrom,
													(unsigned char )addressFromWrite[0],
													(unsigned char )addressFromWrite[1],
													(unsigned char )addressFromWrite[2],
													(unsigned char )addressFromWrite[3],
													(unsigned char )addressFromWrite[4],
													(UINT_PTR )addressTo);
	#else
	if(shortCaveAddr != 0)
	{
		sprintf(mbuf,"* [64-BIT] [0x%x] %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x (0x%x)\n",(UINT_PTR )addressFrom,
													(unsigned char )addressFromWrite[0],
													(unsigned char )addressFromWrite[1],
													(unsigned char )addressFromWrite[2],
													(unsigned char )addressFromWrite[3],
													(unsigned char )addressFromWrite[4],
													(unsigned char )addressFromWrite[5], // PATCH GOES HERE
													(unsigned char )addressFromWrite[6],
													(unsigned char )addressFromWrite[7],
													(unsigned char )addressFromWrite[8],
													(unsigned char )addressFromWrite[9],
													(unsigned char )addressFromWrite[10],
													(unsigned char )addressFromWrite[12],
													(unsigned char )addressFromWrite[13],
													(unsigned char )addressFromWrite[14],
													(UINT_PTR )addressTo);
	}
	else
	{
		sprintf(mbuf,"* [64-BIT] [0x%x] HOOKED-SHORTCAVE %02x %02x%02x%02x%02x (0x%x)\n",(UINT_PTR )addressFrom,
													(unsigned char )addressFromWrite[0],
													(unsigned char )addressFromWrite[1],
													(unsigned char )addressFromWrite[2],
													(unsigned char )addressFromWrite[3],
													(unsigned char )addressFromWrite[4],
													(UINT_PTR )shortCaveAddr);
	}
	#endif
	OutputDebugString(mbuf);

	VirtualFree(mbuf,0,MEM_RELEASE);

	return;
}


DWORD threadId = 0;

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH && init == 0)
      {
        init = 1;
		OutputDebugString(" - shackle dll loaded\n");
		CreateThread(NULL,0,IPCServerThread,NULL,0,&threadId);
		
		return TRUE;
      }
  return TRUE;
}

DWORD WINAPI IPCServerThread( LPVOID lpParam ) 
{
	char *mbuf = (char *)malloc(1024);
	char *pipeName = (char *)malloc(1024);
	// cuz im a hipster too
	for(;;)
	{
		BOOL   fConnected = FALSE; 
		DWORD  dwThreadId = 0; 
		HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL; 

		memset(pipeName,0,1024);
		sprintf(pipeName,"\\\\.\\pipe\\shackle-%d",GetCurrentProcessId());
		hPipe = CreateNamedPipe(pipeName,PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024,1024, 0 , NULL);
		if (hPipe == INVALID_HANDLE_VALUE)
		{
			memset(mbuf,0,1024);
			sprintf(mbuf," CreateNamedPipe failed, GLE = %d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}

		fConnected = ConnectNamedPipe(hPipe,NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		if (fConnected)
		{
			hThread = CreateThread( NULL, 0, IPCServerInstance, (LPVOID) hPipe, 0, &dwThreadId);
			if (hThread == NULL)
			{
				memset(mbuf,0,1024);
				sprintf(mbuf," CreateThread (listener instance) failed, GLE = %d\n",GetLastError());
				OutputDebugString(mbuf);
				break;
			}
			else
			{
				// don't need to track this.
				CloseHandle(hThread);
			}
		}
		else
		{
			CloseHandle(hPipe);
		}
	}
	free(pipeName);
	free(mbuf);
	return 0;
}

#define lua_saveline(L,line)	{ (void)L; (void)line; }
#define lua_freeline(L,b)	{ (void)L; (void)b; }

static int incomplete (lua_State *L, int status) {
  if (status == LUA_ERRSYNTAX) {
    size_t lmsg;
    const char *msg = lua_tolstring(L, -1, &lmsg);
    if (lmsg >= marklen && strcmp(msg + lmsg - marklen, EOFMARK) == 0) {
      lua_pop(L, 1);
      return 1;
    }
  }
  return 0;  /* else... */
}

static int addreturn (lua_State *L) {
  const char *line = lua_tostring(L, -1);  /* original line */
  const char *retline = lua_pushfstring(L, "return %s;", line);
  int status = luaL_loadbuffer(L, retline, strlen(retline), "=stdin");
  if (status == LUA_OK) {
    lua_remove(L, -2);  /* remove modified line */
    if (line[0] != '\0')  /* non empty? */
      lua_saveline(L, line);  /* keep history */
  }
  else
    lua_pop(L, 2);  /* pop result from 'luaL_loadbuffer' and modified line */
  return status;
}

static int pushline (lua_State *L, int firstline, HANDLE hPipe, int *exitToLoop) {
  // what kind of crackhead programming is this shit
  char buffer[LUA_MAXINPUT];
  char *b = buffer;
  size_t l;
  char *prmt = "IGNORED-PUSHLINE";
  int readstatus = lua_readline(L, b, prmt, hPipe, exitToLoop);
  if (readstatus == 0)
    return 0;  /* no input (prompt will be popped by caller) */
  lua_pop(L, 1);  /* remove prompt */
  l = strlen(b);
  if (l > 0 && b[l-1] == '\n')  /* line ends with newline? */
    b[--l] = '\0';  /* remove it */
  if (firstline && b[0] == '=')  /* for compatibility with 5.2, ... */
    lua_pushfstring(L, "return %s", b + 1);  /* change '=' to 'return' */
  else
    lua_pushlstring(L, b, l);
  lua_freeline(L, b);
  return 1;
}

static int multiline (lua_State *L, HANDLE hPipe, int *exitToLoop) {
  for (;;) {  /* repeat until _s a complete statement */
    size_t len;
    const char *line = lua_tolstring(L, 1, &len);  /* get what it has */
    int status = luaL_loadbuffer(L, line, len, "=stdin");  /* try it */
    if (!incomplete(L, status) || !pushline(L, 0, hPipe, exitToLoop) || *exitToLoop == 1) {
	  OutputDebugString("+fucked+\n");
      lua_saveline(L, line);  /* keep history */
      return status;  /* cannot or should not try to add continuation line */
    }
    lua_pushliteral(L, "\n");  /* add newline... */
    lua_insert(L, -2);  /* ...between the two lines */
    lua_concat(L, 3);  /* join them */
  }
}

int lua_readline(lua_State *L, char *buf, char *prompt, HANDLE hPipe, int *exitIoLoop)
{
	char mbuf[1024];
	BOOL fSuccess = FALSE;
	DWORD cbBytesRead = 0;
	fSuccess = ReadFile(hPipe,buf,LUA_MAXINPUT,&cbBytesRead,NULL);
	if (!fSuccess || cbBytesRead == 0)
	{
		memset(mbuf,0,1024);
		sprintf(mbuf," [ERR] read failed, gle=%d\n",GetLastError());
		OutputDebugString(mbuf);
		*exitIoLoop = 1;
		return 0;
	}
	return 1;
}

static int msghandler (lua_State *L) {
  const char *msg = lua_tostring(L, 1);
  if (msg == NULL) {  /* is error object not a string? */
    if (luaL_callmeta(L, 1, "__tostring") &&  /* does it have a metamethod */
        lua_type(L, -1) == LUA_TSTRING)  /* that produces a string? */
      return 1;  /* that is the message */
    else
      msg = lua_pushfstring(L, "(error object is a %s value)",
                               luaL_typename(L, 1));
  }
  luaL_traceback(L, L, msg, 1);  /* append a standard traceback */
  return 1;  /* return the traceback */
}

static void lstop (lua_State *L, lua_Debug *ar) {
  (void)ar;  /* unused arg. */
  lua_sethook(L, NULL, 0, 0);  /* reset hook */
  luaL_error(L, "interrupted!");
}

lua_State *globalL = NULL;

static void laction (int i) {
  signal(i, SIG_DFL); /* if another SIGINT happens, terminate process */
  lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}

static int docall (lua_State *L, int narg, int nres) {
  int status;
  int base = lua_gettop(L) - narg;  /* function index */
  lua_pushcfunction(L, msghandler);  /* push message handler */
  lua_insert(L, base);  /* put it under function and args */
  globalL = L;  /* we need to mutex this shit */
  signal(SIGINT, laction);  /* set C-signal handler */
  status = lua_pcall(L, narg, nres, base);
  signal(SIGINT, SIG_DFL); /* reset C-signal handler */
  lua_remove(L, base);  /* remove message handler from the stack */
  return status;
}

static int loadline (lua_State *L, HANDLE hPipe, int *exitToLoop) {
  int status;
  lua_settop(L, 0);
  if (!pushline(L, 1, hPipe, exitToLoop))
    return -1;  /* no input */
  if ((status = addreturn(L)) != LUA_OK)  /* 'return ...' did not work? */
    status = multiline(L,hPipe,exitToLoop);  /* try as command, maybe with continuation lines */
  lua_remove(L, 1);  /* remove line from the stack */
  lua_assert(lua_gettop(L) == 1);
  return status;
}

static int cs_print(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);
	DWORD cbWritten = 0;


	int n = lua_gettop(L);  /* number of arguments */
	int i;
	lua_getglobal(L, "tostring");
	for (i=1; i<=n; i++)
	{
		const char *s;
		size_t l;
		lua_pushvalue(L, -1);  /* function to be called */
		lua_pushvalue(L, i);   /* value to print */
		lua_call(L, 1, 1);
		s = lua_tolstring(L, -1, &l);  /* get result */
		if (s == NULL)
			return luaL_error(L, "'tostring' must return a string to 'print'");
		if (i>1)
			WriteFile(hPipe,"\t",1,&cbWritten,NULL);
		WriteFile(hPipe,s,l,&cbWritten,NULL);
		lua_pop(L, 1);  /* pop result */
    }
	lua_writeline();
	return 0;
}

static int cs_ALERT(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);
	DWORD cbWritten = 0;

	size_t l;
	const char* str = lua_tolstring( L, -1 , &l);
    lua_pop(L, 1);

    WriteFile(hPipe,str,l,&cbWritten,NULL);
    return 0;
}

static int test_lua(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	char *pchReply = "TEST_LUA\0";
	DWORD cbReplyBytes = 4;
	DWORD cbWritten = 0;
	char mbuf[1024];

	BOOL fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
	if (!fSuccess || cbReplyBytes != cbWritten)
	{
		sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
		OutputDebugString(mbuf);
	}

	fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
	if (!fSuccess || cbReplyBytes != cbWritten)
	{
		sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
		OutputDebugString(mbuf);
	}

	OutputDebugString(" + lua engine successfully recognizes test_lua(), good to go\n");
	// lua_pushnumber(L,123);
	return 0;
}

static int cs_resolve(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	size_t l;
	char* address = (char *)lua_tolstring( L, -1 , &l);
    lua_pop(L, 1);

	char mbuf[1024];
	memset(mbuf,0,1024);

	sprintf(mbuf," [NFO] resolving '%s'\n",address);
	outString(hPipe,mbuf);

	char *baseDll = NULL;
	char *function = NULL;
	char *offset = NULL;
	
	int i = 0, maxlen = strlen(address);
	baseDll = address;

	for( ; i < maxlen; i++)
	{
		if(address[i] == '!')
		{
			address[i] = '\0';
			function = baseDll + i + 1;
		}
		else if(address[i] == '+')
		{
			address[i] = '\0';
			offset = baseDll + i + 1;
		}
	}

	if(baseDll == NULL)
	{
		outString(hPipe," [ERR] no base dll provided (wtf?)\n");
		return 0;
	}
	
	UINT_PTR base = 0;
	if(function  == NULL)
	{
		MODULEINFO *mi = (MODULEINFO *)malloc( sizeof(MODULEINFO) );
		memset(mi,0,sizeof(MODULEINFO));
		HMODULE hMod = GetModuleHandle(baseDll);
		if(hMod == NULL)
		{
			outString(hPipe," [ERR] could not get handle of module (make sure it's loaded)\n");
			free(mi);
			return 0;
		}
		GetModuleInformation(GetCurrentProcess(),hMod,mi,sizeof(MODULEINFO));
		base = (UINT_PTR )mi->lpBaseOfDll;
		free(mi);
		// return 1;
	}
	else
	{
		HMODULE hMod = GetModuleHandle(baseDll);
		if(hMod == NULL)
		{
			outString(hPipe," [ERR] could not get handle of module (make sure it's loaded)\n");
			return 0;
		}
		base = (UINT_PTR )GetProcAddress(hMod,function);
		if (base == NULL)
		{
			outString(hPipe," [ERR] could not resolve function\n");
			return 0;
		}
	}

	if(offset != NULL)
	{
		base += atol(offset);
	}

	lua_pushnumber(L,base);
	return 1;
}

void cs_error(lua_State *L, HANDLE hPipe)
{
	char mbuf[1024];
	sprintf(mbuf," %s\n",lua_tostring(L,-1));
	outString(hPipe,mbuf);
	return;
}

DWORD WINAPI IPCServerInstance(LPVOID lpvParam)
{
	char *pchRequest = (char *)malloc(1024);
	char *pchReply = (char *)malloc(1024);
	char *mbuf = (char *)malloc(1024);
	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;
	HANDLE hPipe = (HANDLE )lpvParam;

	OutputDebugString(" - IPC Server Instance created\n");

	// moved here for thread-safety.
	lua_State *luaState = NULL;

	luaState = luaL_newstate();
	luaL_openlibs(luaState);
	// lua_register(luaState,"test_lua",test_lua);
	lua_register(luaState,"print",cs_print);
	lua_register(luaState,"_ALERT",cs_ALERT);
	lua_register(luaState,"hexdump",cs_hexdump);
	lua_register(luaState,"memcpy",cs_memcpy);
	lua_register(luaState,"memset",cs_memset);
	lua_register(luaState,"malloc",cs_malloc);
	lua_register(luaState,"mprotect",cs_mprotect);
	lua_register(luaState,"memread",cs_memread);
	lua_register(luaState,"disasm",cs_disassemble);
	lua_register(luaState,"disassemble",cs_disassemble);
	lua_register(luaState,"asm_new",cs_asm_new);
	lua_register(luaState,"asm_add",cs_asm_add);
	lua_register(luaState,"asm_commit",cs_asm_commit);
	lua_register(luaState,"asm_free",cs_asm_free);
	lua_register(luaState,"resolve",cs_resolve);

	// mprotect constants
	luaL_dostring(luaState,"PAGE_EXECUTE = 0x10");
	luaL_dostring(luaState,"PAGE_EXECUTE_READ = 0x20");
	luaL_dostring(luaState,"PAGE_EXECUTE_READWRITE = 0x40");
	luaL_dostring(luaState,"PAGE_EXECUTE_WRITECOPY = 0x80");
	luaL_dostring(luaState,"PAGE_NOACCESS = 0x1");
	luaL_dostring(luaState,"PAGE_READONLY = 0x2");
	luaL_dostring(luaState,"PAGE_READWRITE = 0x4");
	luaL_dostring(luaState,"PAGE_WRITECOPY = 0x8");
	luaL_dostring(luaState,"PAGE_TARGETS_INVALID = 0x40000000");
	luaL_dostring(luaState,"PAGE_TARGETS_NO_UPDATE = 0x40000000");
	luaL_dostring(luaState,"PAGE_GUARD = 0x100");
	luaL_dostring(luaState,"PAGE_NOCACHE = 0x200");
	luaL_dostring(luaState,"PAGE_WRITECOMBINE = 0x400");

	int exitToLoop = 0;

	strcpy(pchReply,"NEXTCMDREADY\0");
	cbReplyBytes = strlen(pchReply) + 1;

	HANDLE hProcess = (HANDLE )GetCurrentProcess();
	DWORD pid = (DWORD )GetCurrentProcessId();

	lua_pushnumber(luaState,(UINT_PTR )hPipe);
	lua_setglobal(luaState,"__hpipe");

	lua_pushnumber(luaState,(UINT_PTR )hProcess);
	lua_setglobal(luaState,"__hprocess");

	lua_pushnumber(luaState,pid);
	lua_setglobal(luaState,"__pid");

	sprintf(mbuf," - __hpipe = 0x%x | __hProcess = 0x%x | __pid = %d -\n",hPipe,hProcess,pid);
	outString(hPipe,mbuf);


	// collect process modules for resolver
	HMODULE hMods[1024];
	DWORD cbNeeded = 0;
	MODULEINFO modInfo;
	if( EnumProcessModules( hProcess, hMods, sizeof(hMods),&cbNeeded) )
	{
		int i = 0;
		for (; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char szModName[1024];
			GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo));
			if(GetModuleFileNameEx( hProcess,hMods[i],szModName,sizeof(szModName) / sizeof(char)) )
			{
				if ( GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo)) )
				{
					sprintf(mbuf," + %s (0x%08x) (EP:0x%0x)\n",szModName,hMods[i],modInfo.EntryPoint);
					outString(hPipe,mbuf);
				}
				else
				{
					sprintf(mbuf," + %s (0x%08x)\n",szModName,hMods[i]);
					outString(hPipe,mbuf);
				}
			}
		}
	}
	else
	{
		// maybe get 'peek' to do initialization.
	}

	outString(hPipe,"\n");

	sprintf(mbuf,"INITFINISHED\0");
	outString(hPipe,mbuf);

	while(1)
	{
		fSuccess = ReadFile(hPipe,pchRequest,1024,&cbBytesRead,NULL);
		if (!fSuccess || cbBytesRead == 0)
		{
			sprintf(mbuf," [ERR] read failed, gle=%d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}

		/*

		// http://stackoverflow.com/questions/20454725/how-to-replace-lua-default-error-print

		if (luaL_loadbuffer(L,script.c_str(),script.Length(),AnsiString(Name).c_str()) == 0) {
		if (lua_pcall(L, 0, 0, 0))        // Run loaded Lua script
			cs_error(L, "Runtime error: "); // Print runtime error
		} else {
			cs_error(L, "Compiler error: ");  // Print compiler error
		}
		*/

		if( luaL_loadbuffer(luaState,pchRequest,strlen(pchRequest),"IPCInput") == 0 )
		{
			if( lua_pcall(luaState,0,0,0) )
			{
				cs_error(luaState,hPipe);
			}
		}
		else
		{
			cs_error(luaState,hPipe);
		}

		// int status = luaL_dostring(luaState,pchRequest);

		fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
		if (!fSuccess || cbReplyBytes != cbWritten)
		{
			sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}
	}

	/*
	while ((status = loadline(luaState, hPipe, &exitToLoop)) != -1 && exitToLoop == 0) 
	{
		if (status == LUA_OK)
		{
			OutputDebugString("doing call\n");
			status = docall(luaState, 0, LUA_MULTRET);
		}
		if (status == LUA_OK)
		{
			memset(pchReply,0,1024);
			strcpy(pchReply,"123123");
			cbReplyBytes = strlen(pchReply) + 1;	
		}
		else
		{
			memset(pchReply,0,1024);
			strcpy(pchReply,"fqn wat 123123");
			cbReplyBytes = strlen(pchReply) + 1;
		}
		fSuccess = WriteFile(hPipe,pchReply,cbReplyBytes,&cbWritten,NULL);
		if (!fSuccess || cbReplyBytes != cbWritten)
		{
			sprintf(mbuf," [ERR] write failed, gle=%d\n",GetLastError());
			OutputDebugString(mbuf);
			break;
		}
	}
	*/

	lua_settop(luaState, 0);  /* clear stack */
	lua_writeline();
	lua_close(luaState);

	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	free(mbuf);
	free(pchRequest);
	free(pchReply);
	return 1;
}

/*

lua API (invoke via peek)
=========================

- void hexdump(addr offset, int size)
- void disassemble(addr offset, int instructionLength)
- str cs_assemble(addr offset, str input)
- void memcpy(addr offset, string data, int size)
- void memset(addr offset, char data, int size)
- (status, oldprotect) = mprotect(addr offset, size, int protectionconstant) // really virtualprotect, but sure.
- addr resolve(str resolvestring)
- addr malloc(size)
- void free(addr)

*/

static int cs_malloc(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);
	char mbuf[1024];

	int size = 0;

	if (lua_gettop(L) == 1)
	{
		size = lua_tonumber(L,1);
	}
	else
	{
		outString(hPipe," [ERR] malloc(size) requires 1 argument\n");
		return 0;
	}

	UINT_PTR returnvalue = (UINT_PTR )malloc(size);
	memset((void *)returnvalue,0,size);

	sprintf(mbuf," [NFO] allocated %d bytes at 0x%x",size,returnvalue);
	outString(hPipe,mbuf);

	lua_pushnumber(L,returnvalue);
	return 1;
}

static int cs_mprotect(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	char *addrTo = NULL;
	int protectconstant = 0;
	int size = 0;

	if (lua_gettop(L) == 3)
	{
		addrTo = (char *)(UINT_PTR )lua_tonumber(L,1);
		size = lua_tonumber(L,2);
		protectconstant = lua_tonumber(L,3);
	}
	else
	{
		outString(hPipe," [ERR] memprotect(dest,size,protect_constant) requires 3 arguments\n");
		return 0;
	}

	DWORD oldProtect = 0;
	int returnstatus = 0;

	returnstatus = VirtualProtect(addrTo,size,protectconstant,&oldProtect);
	if(returnstatus == 0)
	{
		returnstatus = GetLastError();
	}

	// return oldProtect / GetLastError OR zero

	lua_pushnumber(L,oldProtect);
	lua_pushnumber(L,returnstatus);

	return 2;
}

static int cs_memset(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	char *addrTo = NULL;
	char byteToSet = '\0';
	int size = 0;

	size_t msize = 0;

	if (lua_gettop(L) == 3)
	{
		addrTo = (char *)(UINT_PTR )lua_tonumber(L,1);
		if(lua_isstring(L,2))
		{
			byteToSet = (char ) ((char *)(lua_tolstring(L,2,&msize))) [0];
		}
		else if(lua_isnumber(L,2))
		{
			int byteData = lua_tonumber(L,2);
			if (byteData > 255)
			{
				outString(hPipe," [ERR] can't cast this number to a byte\n");
				return 0;
			}
			byteToSet = (char )byteData;
		}
		size = lua_tonumber(L,3);
	}
	else
	{
		outString(hPipe," [ERR] memcpy(dest,source,size) requires 3 arguments\n");
		return 0;
	}

	if(msize != size)
	{
		char mbuf[1024];
		sprintf(mbuf," [WRN] string size (%d) is not equal to provided size / arg 3 (%d)\n",msize,size);
		outString(hPipe,mbuf);
	}

	__try
	{
		memset(addrTo,byteToSet,size);
	}
	__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
	{
		outString(hPipe," [ERR] could not complete memory set operation\n");
	}

	return 0;
}

static int cs_memcpy(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	char *addrTo = NULL;
	char *addrFrom = NULL;
	int size = 0;

	if (lua_gettop(L) == 3)
	{
		addrTo = (char *)(UINT_PTR )lua_tonumber(L,1);
		if(lua_isstring(L,2))
		{
			// data blob directly
			addrFrom = (char *)lua_tostring(L,2);
		}
		else if(lua_isnumber(L,2))
		{
			// address
			addrFrom = (char *)(UINT_PTR )lua_tonumber(L,2);
		}
		size = lua_tonumber(L,3);
	}
	else
	{
		outString(hPipe," [ERR] memcpy(dest,source,size) requires 3 arguments\n");
		return 0;
	}

	__try
	{
		char mbuf[1024];
		memcpy(addrTo,addrFrom,size);
		sprintf(mbuf," [NFO] copied %d bytes from 0x%x to 0x%x\n",size,addrFrom,addrTo);
		outString(hPipe,mbuf);
	}
	__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
	{
		outString(hPipe," [ERR] could not complete memory copy operation\n");
	}

	return 0;
}

int readfilter(unsigned int code, struct _EXCEPTION_POINTERS *ep) {
   // puts("in filter.");
   if (code == EXCEPTION_ACCESS_VIOLATION) {
      // puts("caught AV as expected.");
      return EXCEPTION_EXECUTE_HANDLER;
   }
   else {
      puts("didn't catch AV, unexpected.");
      return EXCEPTION_CONTINUE_SEARCH;
   };
}

static int cs_disassemble(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	char *addrTo = NULL;
	int size = 0;

	if (lua_gettop(L) == 2)
	{
		addrTo = (char *)(UINT_PTR )lua_tonumber(L,1);
		size = lua_tonumber(L,2);
	}
	else if (lua_gettop(L) == 1)
	{
		addrTo = (char *)(UINT_PTR )lua_tonumber(L,1);
		size = 5;
		outString(hPipe," [NFO] assuming you want to disassemble 5 instructions\n");
	}
	else
	{
		outString(hPipe," [ERR] diasm(addr,{size}) requires 1-2 arguments\n");
		return 0;
	}

	char mbuf[1024];        // sprintf buffer
	char tempBuf[15];       // temp buf
	int currentHeader = 0;
	DISASM *d = (DISASM *)malloc(sizeof(DISASM));

	memset(d,0,sizeof(DISASM));
	d->Archi = ARCHI;
	int len = 0;
	
	int i = 0;
	for(;i < size;i++)
	{
		len = 1;
		__try
		{
			d->EIP = (UIntPtr )(addrTo+currentHeader);
			memcpy(tempBuf,(void *)(addrTo+currentHeader),15);
			len = Disasm(d);

			sprintf(mbuf," 0x%0x : %s\n",(UIntPtr )(addrTo+currentHeader),d->CompleteInstr);
			outString(hPipe,mbuf);

		}
		__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
		{
			sprintf(mbuf," 0x%0x : ..\n",(UIntPtr )(addrTo+currentHeader));
			outString(hPipe," ..\n");
		}
		currentHeader += len;
	}

	free(d);

	return 0;
}

static int cs_memread(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	/*
	size_t l;
	char* addressToResolve = (char *)lua_tolstring( L, -1 , &l);
    lua_pop(L, 1);
	*/

	char *addrTo = NULL;
	int size = 0;

	if (lua_gettop(L) == 2)
	{
		addrTo = (char *)(UINT_PTR )lua_tonumber(L,1);
		size = lua_tonumber(L,2);
	}
	else
	{
		outString(hPipe," [ERR] memread(addr,size) requires 2 arguments\n");
		return 0;
	}

	char *temp = (char *)malloc(size);
	memcpy(temp,addrTo,size);

	lua_pushlstring(L,temp,size);

	free(temp);

	return 1;
}

static int cs_hexdump(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	char mbuf[1024];

	UINT_PTR addr = NULL;
	int n = 0;

	if (lua_gettop(L) == 2)
	{
		addr = (UINT_PTR )lua_tonumber(L,1);
		n = lua_tonumber(L,2);
	}
	else if(lua_gettop(L) == 1)
	{
		outString(hPipe," [NFO] no size supplied, defaulting to size 64\n");
		addr = (UINT_PTR )lua_tonumber(L,1);
		n = 64;
	}
	else
	{
		outString(hPipe," [ERR] hexdump(addr,size) requires 2 arguments\n");
		return 0;
	}

	sprintf(mbuf," - starting cs_hexdump, address is %x, length is %d\n",addr,n);
	outString(hPipe,mbuf);

	char currentLine[17];
	int isRead = 0;
	char thisChar = '\0';

	int i = 0;

	for(i = 0;i < n;i++)
	{
		if(i == 0 || i % 16 == 0)
		{
			#if ARCHI == 64
				sprintf(mbuf,"0x%016x : \0",(UINT_PTR )(addr + i));
			#else
				sprintf(mbuf,"0x%08x : \0",(UINT_PTR )(addr + i));
			#endif
			outString(hPipe,mbuf);
			memset(currentLine,'.',16);
			currentLine[16] = '\0';
		}
		
		__try
		{
			thisChar = (currentLine[i%16] = (char )*(char *)(addr + i)); // will throw an exception first, don't need everything else.
			sprintf(mbuf,"%02x \0",(unsigned char )(thisChar));
			outString(hPipe,mbuf);
			currentLine[i % 16] = thisChar;
		}
		__except( readfilter(GetExceptionCode(), GetExceptionInformation()) )
		{
			outString(hPipe,".. ");
		}

		if((i + 1) % 16 == 0)
		{
			outString(hPipe,currentLine);
			outString(hPipe,"\n");
		}
	}

	if( i % 16 != 0)
	{
		// finish up.
		for(;i % 16 != 0;i++)
		{
			outString(hPipe,".. ");
		}
		outString(hPipe,currentLine);
		outString(hPipe,"\n");
	}
	
	return 0;
}

void outString(HANDLE hPipe, char *thisMsg)
{
	DWORD bytesWritten = 0;
	WriteFile(hPipe,thisMsg,strlen(thisMsg) + 1,&bytesWritten,NULL);
	OutputDebugString(thisMsg);
	return;
}

static int cs_asm_new(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	UINT_PTR startAddress = NULL;
	int architecture = 32;

	if (lua_gettop(L) == 2)
	{
		startAddress = (UINT_PTR )lua_tonumber(L,1);
		architecture =  lua_tonumber(L,2);
	}
	else
	{
		outString(hPipe," [ERR] asm_new(offset,[32|64]) requires 2 arguments\n");
		return 0;
	}

	if(architecture != 32 && architecture != 64)
	{
		outString(hPipe," [ERR] asm_new(offset,[32|64]) / XEDParse only supports 32-bit and 64-bit intel architecture\n");
		return 0;
	}

	asmBuffer *d = (asmBuffer *)malloc(sizeof(asmBuffer));
	memset(d,0,sizeof(asmBuffer));

	d->writeHead = startAddress;
	d->architecture = architecture;
	d->lineCount = 0;

	outString(hPipe," [NFO] asm_new() allocated new assembly buffer\n");
	lua_pushlightuserdata(L,(void *)d); // gc doesn't apply here.
	return 1;
}

static int cs_asm_add(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	asmBuffer *a = NULL;
	char *newLine = NULL;

	if (lua_gettop(L) == 2)
	{
		a = (asmBuffer *)lua_touserdata(L,1);
		newLine = (char *)lua_tostring(L,2);
	}
	else
	{
		outString(hPipe," [ERR] asm_add(asmobj,assembly_data) requires 2 arguments\n");
		return 0;
	}

	a->lines[a->lineCount] = _strdup(newLine);
	a->lineCount += 1;

	return 0;
}

static int cs_asm_free(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	asmBuffer *a = NULL;

	if (lua_gettop(L) == 1)
	{
		a = (asmBuffer *)lua_touserdata(L,1);
	}
	else
	{
		outString(hPipe," [ERR] asm_free(asmobj) requires 1 argument\n");
		return 0;
	}

	int i = 0;
	for( ; i < a->lineCount; a++ )
	{
		free(a->lines[i]);
	}

	return 0;
}

static int cs_asm_commit(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	asmBuffer *a = NULL;

	if (lua_gettop(L) == 1)
	{
		a = (asmBuffer *)lua_touserdata(L,1);
	}
	else
	{
		outString(hPipe," [ERR] asm_commit(asmobj) requires 1 argument\n");
		return 0;
	}

	char mbuf[1024];
	sprintf(mbuf," [NFO] committing %d lines of assembly\n",a->lineCount);
	outString(hPipe,mbuf);

	// a->lines[a->lineCount] = _strdup(newLine);
	// a->lineCount += 1;

	XEDPARSE parse;
	memset(&parse, 0, sizeof(parse));
	parse.x64 = false;
	if(a->architecture == 64)
	{
		parse.x64 = true;
	}

	int i = 0;
	char *assemblyBuf = (char *)malloc(a->lineCount * 15);
	int writeHeader = 0;

	parse.cip = a->writeHead;

	for( ; i < a->lineCount ; i++)
	{
		parse.cip += writeHeader;
		memset(parse.instr, 0, 256);
		memcpy(parse.instr, a->lines[i], 256);

		XEDPARSE_STATUS status = XEDParseAssemble(&parse);
		if (status == XEDPARSE_ERROR)
		{
			sprintf(mbuf," [ERR] parse error on line %d: %s\n", i , parse.error);
			outString(hPipe,mbuf);
			return 0;
		}
		else
		{
			sprintf(mbuf," 0x%0x : %s\n",(UINT_PTR )parse.cip,parse.instr);
			outString(hPipe,mbuf);
			memcpy( (char *)(assemblyBuf + writeHeader), (char *)&parse.dest[0], parse.dest_size);
			writeHeader += parse.dest_size;
		}
	}

	memcpy((void *)a->writeHead,assemblyBuf,writeHeader);
	free(assemblyBuf);

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
		// outString(hPipe,mbuf);
		lua_pushlstring(L, (const char *)&parse.dest[0], parse.dest_size);
		return 1;
	}

	
	
	return 0;
}
