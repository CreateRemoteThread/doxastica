ULONG_PTR darksign_reflect(char *payload_addr, int filesize, int mode);

#ifndef DEREF_MACROS_TAG
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)
#define DEREF_MACROS_TAG
#endif

typedef DWORD  (NTAPI * NTFLUSHINSTRUCTIONCACHE)( HANDLE, PVOID, ULONG );
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved);
// BOOL WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow);

typedef BOOL (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );
typedef BOOL (WINAPI * WINMAIN)( HINSTANCE, HINSTANCE, LPCSTR, DWORD );

int cs_darksign_reflect_disk(lua_State *L);
int cs_darksign_reflect_raw(lua_State *L);
int cs_darksign_hollow(lua_State *L);

void self_hollow(HANDLE hPipe);

#define LUAINIT_DARKSIGN lua_register(luaState,"__darksign_reflect_disk",cs_darksign_reflect_disk); \
	luaL_dostring(luaState,"darksign = {}"); \
	luaL_dostring(luaState,"darksign.reflect_disk = __darksign_reflect_disk"); \
	lua_register(luaState,"__darksign_reflect_raw",cs_darksign_reflect_raw); \
	luaL_dostring(luaState,"darksign.reflect = __darksign_reflect_raw"); \
	lua_register(luaState,"__darksign_hollow",cs_darksign_hollow); \
	luaL_dostring(luaState,"darksign.hollow = __darksign_hollow"); 

typedef struct _HOLLOW_LOADER_INFO
{
	ULONG_PTR	lpPayloadData;
	int			uiFilesize;

} HOLLOW_LOADER_INFO, *P_HOLLOW_LOADER_INFO;
