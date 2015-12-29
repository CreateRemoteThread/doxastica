#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char **argv)
{
	HANDLE h = LoadLibrary("putty2.dll");	
	if (h == INVALID_HANDLE_VALUE || h == NULL)
	{
		printf("fuck\n");
	}
	MessageBox(0,"asdf","asdf",MB_OK);
	return 0;
}