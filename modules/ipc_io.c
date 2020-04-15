#include <stdio.h>
#include <windows.h>

void outString(HANDLE hPipe, char *thisMsg)
{
	DWORD bytesWritten = 0;
	WriteFile(hPipe,thisMsg,strlen(thisMsg) + 1,&bytesWritten,NULL);
	OutputDebugString(thisMsg);
	return;
}
