#define PTRSCAN_SIG 0x01440245


typedef struct
{
	DWORD signature;
} ptrResult;

int cs_ptrscan(lua_State *L);
int validatePtrResult(ptrResult *p);
