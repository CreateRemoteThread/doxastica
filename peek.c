#include <stdio.h>
#include <windows.h>

/*
	- pretty much ipc telnet, server is in the shackle library
*/

void chomp(char *s);

int main(int argc, char **argv)
{
	if(argc != 2)
	{
		printf(" [-] usage: %s {process-id}\n",argv[0]);
		return 0;
	}

	char *pipeName = (char *)malloc(1024);
	memset(pipeName,0,1024);
	sprintf(pipeName,"\\\\.\\pipe\\shackle-%d",atoi(argv[1]));
	HANDLE hPipe = INVALID_HANDLE_VALUE;

	while(1)
	{
		hPipe = CreateFile(pipeName,GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
		if(hPipe != INVALID_HANDLE_VALUE)
		{
			break;
		}
		if(GetLastError() != ERROR_PIPE_BUSY)
		{
			printf(" [ERR] could not open pipe, gle=%d\n",GetLastError());
			return -1;
		}
		if(!WaitNamedPipe(pipeName,10000))
		{
			printf(" [ERR] could not open pipe, timed out\n");
			return -1;
		}
	}

	DWORD dwMode = PIPE_READMODE_MESSAGE;
	BOOL fSuccess = FALSE;
	char *chBuf = (char *)malloc(1024);
	DWORD cbWritten = 0, cbRead = 0;

	fSuccess = SetNamedPipeHandleState(hPipe,&dwMode,NULL,NULL);
	if(!fSuccess)
	{
		printf(" [ERR] could not set pipe to read message mode, gle=%d\n",GetLastError());
		return -1;
	}

	printf(" > ");

	// err...
	while(1)
	{
		memset(chBuf,0,1024);
		fgets(chBuf,1024,stdin);
		chomp(chBuf);

		if(strlen(chBuf) == 0)
		{
			continue;
		}
		if(chBuf[0] == '.')
		{
			// local command
			if(strcmp(chBuf,".q") == 0 || strcmp(chBuf,".quit") == 0 || strcmp(chBuf,".quit()") == 0)
			{
				break;
			}
		}

		fSuccess = WriteFile(hPipe,chBuf,strlen(chBuf) + 1,&cbWritten,NULL);
		if(!fSuccess)
		{
			printf(" [ERR] write failed, gle=%d\n",GetLastError());
			return -1;
		}

		do{
			memset(chBuf,0,1024);
			fSuccess = ReadFile(hPipe,chBuf,1024,&cbRead,NULL);
			if ( ! fSuccess && GetLastError() != ERROR_MORE_DATA )
				break; 
			printf("%s\n",chBuf);

		}while(!fSuccess);

		if(!fSuccess)
		{
			printf(" [ERR] read failed, gle=%d\n",GetLastError());
			return -1;
		}
		printf(" > ");
	}

	printf(" [INFO] done, cleaning up\n");

	free(chBuf);
	CloseHandle(hPipe);

	return 0;
}

void chomp(char *s)
{
  int i = 0;
  int stop = strlen (s);
  for (i = 0; i < stop; i++)
    {
      if (!(isprint (s[i])) || s[i] == '\r' || s[i] == '\n')
        {
          s[i] = 0;
          return;
        }
    }
}
