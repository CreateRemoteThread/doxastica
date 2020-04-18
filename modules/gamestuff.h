int cs_toVector3(lua_State *);
int cs_fromVector3(lua_State *);

#define LUAINIT_GAMESTUFF lua_register(luaState,"toVector3",cs_toVector3);\
                          lua_register(luaState,"fromVector3",cs_fromVector3);