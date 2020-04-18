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

/*
#define PRINT_PS 1
#define PRINT_MV 1
#define PRINT_MA 1
#define PRINT_MK 1
#define PRINT_EA 1
#define PRINT_ST 1
#define PRINT_ACK 1
#define PRINT_XX 1
#define PRINT_EXTRA  1

#define PRINT_SEND 1
*/
#define PRINT_PP 1

void splitPacket(char *buf,int size)
{
	int i = 0;
	int x = 0;
	while(i < size)
	{
		if(buf[i] == 'p' && buf[i+1] == 's')
		{
			#ifdef PRINT_PS
			printf("ps ");
			for(x = 2;x < 30;x++)
			{
				printf("%02x",(unsigned char )buf[i+x]);
			}
			printf("\n");
			#endif
			i += 30;
		}
		else if(buf[i] == 'm' && buf[i+1] == 'v')
		{
			#ifdef PRINT_MV
			printf("mv ");
			for(x = 2;x < 24;x++)
			{
				printf("%02x",(unsigned char )buf[i+x]);
			}
			printf("\n");
			#endif
			i += 24;
		}
		else if(buf[i] == 'm' && buf[i+1] == 'a')
		{
			#ifdef PRINT_MA
			printf("ma ");
			for(x = 2;x < 6;x++)
			{
				printf("%02x",(unsigned char )buf[i+x]);
			}
			printf("\n");
			#endif
			i += 6;
		}
		else if(buf[i] == 'm' && buf[i+1] == 'k')
		{
			#ifdef PRINT_MK
			printf("mk ");
			for(x = 2;x < 43;x++)
			{
				printf("%02x",(unsigned char )buf[i+x]);
			}
			printf("\n");
			#endif
			i += 43;
		}
		else if(buf[i] == 'e' && buf[i+1] == 'a')
		{
			#ifdef PRINT_EA
			printf("ea ");
			for(x = 2;x < 13;x++)
			{
				printf("%02x",(unsigned char )buf[i+x]);
			}
			printf("\n");
			#endif
			i += 13;
		}
		else if(buf[i] == '\x00' && buf[i + 1] == '\x00')
		{
			#ifdef PRINT_ACK
			printf("ack\n");
			#endif
			i += 2;
		}
		else if(buf[i] == '+' && buf[i+1] == '+')
		{
			#ifdef PRINT_PP
			
			// ++ 1a000000f2ffffff
			DWORD hitpoints = ((DWORD *)(buf + 2 + 4))[0];
			if(hitpoints > 4000)
			{
			printf("++ ");
			printf("%d\n",hitpoints);
			}
			/*
			for(x = 2;x < 26;x++)
			{
				printf("%02x",(unsigned char )buf[i+x]);
			}
			printf("\n");
			*/
			#endif
			i += 26;
		}
		else if(buf[i] == 'x' && buf[i+1] == 'x')
		{
			#ifdef PRINT_XX
			printf("xx ");
			for(x = 2;x < 6;x++)
			{
				printf("%02x",(unsigned char )buf[i+x]);
			}
			printf("\n");
			#endif
			i += 6;
		}
		else if(buf[i] == 's' && buf[i+1] == 't')
		{
			#ifdef PRINT_ST
			// 73 74 f3 01 00 00 03 00 52 75 6e 01
			printf("++ ");
			for(x = 2;x < 12;x++)
			{
				printf("%02x",(unsigned char )buf[i+x]);
			}
			printf("\n");
			
			#endif
			i += 12;
		}
		else
		{
			break;
		}
	}
	if(i >= size)
	{
		return;
	}
	else
	{
		#ifdef PRINT_EXTRA
		printf("\n");
		for(;i < size;i++)
		{
			if(i != 0 && i % 32 == 0)
			{
				printf("\n");
			}
			printf("%02x ",(unsigned char )buf[i]);
		}
		#endif
	}
}

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
	
	char staticbuf[10240];
	int i = 0;
	int packetCounter = 0;
	char *readHead;
	fConnected = ConnectNamedPipe(hPipe,NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
	if (fConnected)
	{
		printf("got a connection! pew pew pew");
		while(1)
		{
			// type and recover.
			if(packetCounter % 50 == 0 && packetCounter != 0)
			{
				fflush(recover);
				packetCounter = 0;
			}
			packetCounter += 1;
			fSuccess = ReadFile(hPipe,&cbuf,sizeof(cmdbuf),&cbBytesRead,NULL);
			if (!fSuccess || cbBytesRead == 0)
			{
				printf("what? cmd");
				break;
			}
			
			fwrite(&cbuf,sizeof(cbuf),1,recover);
			
			if(cbuf.size < 10240)
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
				/*
				if(cbuf.type != TYPE_SEND)
				{
					continue;
				}
				*/
				if(staticbuf[0] == 0x6D && staticbuf[1] == 0x76)
				{
					continue;
				}
				if(cbuf.type == TYPE_SEND)
				{
					#ifdef PRINT_SEND
					printf("S\n");
					for(i = 0;i < cbuf.size;i++)
					{
						if(i != 0 && i % 32 == 0)
						{
							printf("\n");
						}
						printf("%02x ",(unsigned char )staticbuf[i]);
					}
					for(i = 0;i < cbuf.size;i++)
					{
						if(!isprint(staticbuf[i]))
						{
							staticbuf[i] = '.';
						}
					}
					staticbuf[cbuf.size] = '\x00';
					printf("  %s  \n",staticbuf);
					#endif
				}
				else
				{
					// printf("R\n");
					splitPacket(staticbuf,cbuf.size);
				}
			}
			else
			{
				printf("massive packet : %d\n",cbuf.size);
				exit(0);
			}
		
			
		}
	}
	else
	{
		CloseHandle(hPipe);
	}
}