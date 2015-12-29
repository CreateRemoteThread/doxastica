#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <beaengine/beaengine.h>

int main(int argc, char **argv)
{
	printf("test\n");
	DISASM MyDisasm;
	unsigned char *hello = (unsigned char *)malloc(1024);

	memset(&MyDisasm,0,sizeof(DISASM));
	memset(hello,0xCC,1024);
	MyDisasm.EIP = (UIntPtr )hello;


	int len = UNKNOWN_OPCODE + 1;
	int i = 0;
	while (len != UNKNOWN_OPCODE && i < 100)
	{
		len = Disasm(&MyDisasm);
		printf("+ %s\n",MyDisasm.CompleteInstr);
		MyDisasm.EIP = MyDisasm.EIP + len;
		i++;
	}

	printf(" > ok\n");
	return 0;
}