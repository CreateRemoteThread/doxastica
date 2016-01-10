#define PTRSCAN_SIG 0x01440245

static int cs_ptrscan(lua_State *L);
int validatePtrResult(ptrResult *p);

struct ptrResult
{
	DWORD signature;
};