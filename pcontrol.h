int cs_listthreads(lua_State *L);

void __initThreadList();
void __registerThread(DWORD threadId);
void __unregisterThread(DWORD threadId);
void __closeThread(DWORD threadId);
int __checkThread(DWORD threadId);

int cs_stopthreads(lua_State *L);
int cs_resumethreads(lua_State *L);