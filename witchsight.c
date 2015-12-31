#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv)
{
	if(argc != 2)
	{
		printf(" [-] usage: %s {process-id}\n",argv[0]);
		return 0;
	}

	char *pipeName = (char *)malloc(1024);
	memset(pipeName,0,1024);
	sprintf(pipeName,"",atoi(argv[1]));

	HANDLE hPipe = CreateFile("lpszFileName
	return 0;
}
