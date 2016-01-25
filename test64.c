#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

DWORD WINAPI IPCServerThread( LPVOID lpParam ) ;
void enumThreads();

int main(int argc, char **argv)
{
	DWORD threadId1,threadId2,threadId3;
	MessageBoxA(0,"starting 3 threads","test64",MB_OK);
	
	CreateThread(NULL,0,IPCServerThread,NULL,0,&threadId1);
	CreateThread(NULL,0,IPCServerThread,NULL,0,&threadId2);
	CreateThread(NULL,0,IPCServerThread,NULL,0,&threadId3);

	enumThreads();

	MessageBoxA(0,"DIE","test64",MB_OK);
	return 0;
}

void enumThreads()
{
	HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
	{
		return; 
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32 ); 


	if(!Thread32First(hThreadSnap,&te32))
	{
		printf("dicks\n");
		return;
	}

	printf("lolfirst\n");

	do
	{
		if(te32.th32OwnerProcessID == GetCurrentProcessId())
		{
			printf("lol\n");
		}
	}
	while(Thread32Next(hThreadSnap,&te32));

	return;
}

DWORD WINAPI IPCServerThread( LPVOID lpParam ) 
{
	while(1)
	{
		Sleep(1000);
	}
	return 1;
}