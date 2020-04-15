#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

struct cmdbuf
{
	DWORD type;
	DWORD size;
};

#define TYPE_SEND 5555
#define TYPE_RECV 3333

int main(int argc, char **argv)
{
	HANDLE hPipe = NULL;
	BOOL fConnected = FALSE;
	char *pipeName = (char *)malloc(1024);
	memset(pipeName,0,1024);
	sprintf(pipeName,"\\\\.\\pipe\\ipcutil");
	hPipe = CreateNamedPipe(pipeName,PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024,1024, 0 , NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		printf("error, could not create ipc server");
		return 0;
	}
	// wait
	BOOL fSuccess = FALSE;
	DWORD cbBytesRead;
	
	struct cmdbuf cbuf;
	char *databuf = NULL;
	memset(&cbuf,0,sizeof(cbuf));
	
	FILE *recover = fopen("c:/projects/pwnadventure3.cap","wb");
	
	char staticbuf[1024];
	int i = 0;
	char *readHead;
	fConnected = ConnectNamedPipe(hPipe,NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
	if (fConnected)
	{
		printf("got a connection! pew pew pew");
		while(1)
		{
			fSuccess = ReadFile(hPipe,&cbuf,sizeof(cmdbuf),&cbBytesRead,NULL);
			if (!fSuccess || cbBytesRead == 0)
			{
				printf("what? cmd");
				break;
			}
			
			fwrite(&cbuf,sizeof(cbuf),1,recover);
			
			if(cbuf.size < 1024)
			{
				// databuf = (char *)malloc(cbuf.size);
				fSuccess = ReadFile(hPipe,staticbuf,cbuf.size,&cbBytesRead,NULL);
				// printf("Optimized %d bytes\n",cbBytesRead);
				// readHead = staticbuf;
				if (!fSuccess || cbBytesRead == 0)
				{
					printf("what? data");
					break;
				}
				fwrite(staticbuf,cbuf.size,1,recover);
				if(cbuf.type != TYPE_SEND)
				{
					continue;
				}
				if(staticbuf[0] == 0x6d)
				{
					continue;
				}
				if(cbuf.type == TYPE_SEND)
				{
					printf(" ---------------- SEND ---------------- \n");
				}
				else
				{
					printf(" ---------------- RECV ---------------- \n");
				}
				for(i = 0;i < cbuf.size;i++)
				{
					if(i != 0 && i % 32 == 0)
					{
						printf("\n");
					}
					printf("%02x ",(unsigned char )staticbuf[i]);
				}
			}
			else
			{
				databuf = (char *)malloc(cbuf.size);
				fSuccess = ReadFile(hPipe,databuf,cbuf.size,&cbBytesRead,NULL);
				
				if (!fSuccess || cbBytesRead == 0)
				{
					printf("what? data");
					break;
				}
				fwrite(databuf,cbuf.size,1,recover);
				if(cbuf.type == TYPE_SEND)
				{
					printf(" ---------------- SEND ---------------- \n");
				}
				else
				{
					printf(" ---------------- RECV ---------------- \n");
				}
				// readHead = databuf;
				for(i = 0;i < cbuf.size;i++)
				{
					if(i != 0 && i % 32 == 0)
					{
						printf("\n");
					}
					printf("%02x ",(unsigned char )databuf[i]);
				}
				free(databuf);
			}
		printf("\n");
			
		}
	}
	else
	{
		CloseHandle(hPipe);
	}
}