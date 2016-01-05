typedef int (*lua_CFunction) (lua_State *L);
static int cs_hexdump(lua_State *L);
static int cs_memcpy(lua_State *L);
static int cs_mprotect(lua_State *L);
static int cs_memset(lua_State *L);
static int cs_malloc(lua_State *L);
static int cs_resolve(lua_State *l);
static int cs_memread(lua_State *L);
static int cs_disassemble(lua_State *L);
static int cs_assemble(lua_State *L);
int readfilter(unsigned int code, struct _EXCEPTION_POINTERS *ep);

typedef DWORD (WINAPI * _MessageBoxA) (DWORD, LPCVOID, LPCVOID, DWORD);
typedef DWORD (WINAPI * _send) (DWORD, char *, DWORD, DWORD);
void hook(UINT_PTR addressFrom, UINT_PTR addressTo, UINT_PTR *saveAddress);
UINT_PTR searchForShortCave(UINT_PTR addressFrom,int minLength);
DWORD WINAPI IPCServerThread( LPVOID lpParam );
DWORD WINAPI IPCServerInstance(LPVOID lpvParam);
void processCommand(char *pchRequest, char *pchReply);
static int test_lua(lua_State *L);
void outString(HANDLE hPipe, char *thisMsg);

static int loadline (lua_State *L, HANDLE hPipe, int *exitToLoop);
static int pushline (lua_State *L, int firstline, HANDLE hPipe, int *exitToLoop);
static int multiline (lua_State *L, HANDLE hPipe, int *exitToLoop);
int lua_readline(lua_State *L, char *buf, char *prompt, HANDLE hPipe, int *exitIoLoop);
static int docall (lua_State *L, int narg, int nres);
static int msghandler (lua_State *L) ;
UINT_PTR resolve(HANDLE hPipe, char *address);

void cs_error(lua_State *L, HANDLE hPipe);