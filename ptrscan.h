#define PTRSCAN_SIG 0x01440245


struct ptrResult
{
	DWORD signature;
};

static int cs_ptrscan(lua_State *L);
int validatePtrResult(ptrResult *p);
