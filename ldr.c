#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "peb.h"

// https://www.virtualbox.org/svn/vbox/trunk/src/VBox/HostDrivers/Support/testcase/tstNtQueryStuff.cpp

#ifdef ARCHI_64
	#define ARCHI 64
	#define PC_REG Rip
	#define REGISTER_LENGTH DWORD64
	#define PEB_ARCHI PEB64
#else
	#define ARCHI 32
	#define PC_REG Eip
	#define REGISTER_LENGTH DWORD
	#define PEB_ARCHI PEB32
#endif

void chomp(char *s);
char *guessWorkDir (char *path);
HANDLE createNewProcess (char *exeName, char *workingDirectory);
int listProcesses_matchFirst(char *strToMatch);
void help();

char *globalExeName = NULL;
char *globalWorkingDirectory = NULL;

typedef DWORD (WINAPI * _DebugBreakProcess) (HANDLE);
typedef DWORD (WINAPI * _DebugActiveProcessStop) (DWORD);
typedef HANDLE (WINAPI * _OpenThread) (DWORD, BOOL, DWORD);
typedef DWORD (WINAPI * _NtQueryInformationProcess) (HANDLE, int , PVOID, ULONG, SIZE_T *);
int findprocessbywindow(char *strToMatch);

_NtQueryInformationProcess NtQueryInformationProcess;

DWORD globalPid = 0;

#define OPMODE_DEFAULT 0
#define OPMODE_LIST 1
#define OPMODE_INJECT 2

#define OPM_FLAGS_NONE 0
#define OPM_FLAGS_DNR 1
#define OPM_FLAGS_SNAKESALIVE 2
#define OPM_FLAGS_MSCOREE 4
#define OPM_FLAGS_WAIT 8
#define OPM_FLAGS_PEEK 16

int globalWait = 0;
int globalTest = 0;
int globalCooldown = 0;
int globalInject = 0;
char *globalDll = NULL;
char *stringToMatch = NULL;
int opMode = OPMODE_DEFAULT;
int opFlags = OPM_FLAGS_NONE;

typedef struct _LSA_UNICODE_STRING
{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PROCESS_PARAMETERS
{
  ULONG AllocationSize;
  ULONG Size;
  ULONG Flags;
  ULONG Reserved;
  LONG Console;
  ULONG ProcessGroup;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
  UNICODE_STRING CurrentDir;
  HANDLE CurrentDirectoryHandle;
  UNICODE_STRING LoadSearchPath;
  UNICODE_STRING ImageName;
  UNICODE_STRING CommandLine;
  PWSTR Enviroment;
  ULONG dwX;
  ULONG dwY;
  ULONG dwXSize;
  ULONG dwYSize;
  ULONG dwXCountChars;
  ULONG dwYCountChars;
  ULONG dwFillAttributes;
  ULONG dwFlags;
  ULONG wShowWindow;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING Desktop;
  UNICODE_STRING Reserved1;
  UNICODE_STRING Reserved2;
} PROCESS_PARAMETERS, *PPROCESS_PARAMETERS;

typedef struct _PROCESS_BASIC_INFORMATION
{
  PVOID Reserved1;
  PVOID PebBaseAddress;
  PVOID Reserved2[2];
  ULONG_PTR UniqueProcessId;
  PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

char *shortName(char *fullName)
{
    if(strlen(fullName) == 0)
    {
        // no nice way to pass interrupt-prints to the peek client
        // so let's have this on hold for now.
        return NULL;
    }
    int i = strlen(fullName) - 1;
    int firstToggle = 0;
    for( ; i > 0; i--)
    {
        // don't accept last character is '\\'
        if(fullName[i] == '\\' && firstToggle == 1)
        {
            return (char *)(fullName + i + 1);
        }
        firstToggle = 1;
    }

    return (char *)(fullName + i);
}

UINT_PTR guessExecutableEntryPoint (HANDLE globalhProcess, UINT_PTR baseaddr);
int exists(const char *fname);
char *fullpath(char *dllName);

void help()
{
	printf(" [INFO] dll ldr v0.1\n");
	printf(" [INFO] -wait : wait for input before injecting\n");

	printf(" [INFO] -timer : wait x seconds until inject\n");
	printf(" [INFO] -dll : specify name of dll to inject\n");
	printf(" [INFO] -inject : inject into PID (hexadecimal)\n");
	printf(" [INFO]  -> -fastinject : inject into first instance of executable name\n");
	printf(" [INFO]  -> -findwindow : inject into the first window with a matching title :D\n");
	printf(" [INFO] -list : list all processes matching mask\n");
	printf(" [INFO] -listall : list all processes\n");
	printf(" [INFO] -exe : use specified executable\n");
	printf(" [INFO] -wdir : use specified working directory (raw)\n");
	printf(" [INFO] -wait : wait before inesrting payload (to attach debugger)\n");
	printf(" [INFO] --flag-dnr : do not recover (leave \\xEB\\xFE in) \n");
	printf(" [INFO] --flag-snakesalive : special sauce shellcode mode\n");
	printf(" [INFO] --flag-mscoree : special sauce fix .net mode\n");
	return;
}

void parseArgs(int argc, char **argv)
{
	int i = 1;
	if (argc == 1)
	{
		help();
		exit(0);
		return;
	}

	for (; i < argc; i++ )
	{
		if (strcmp(argv[i],"-wait") == 0)
		{
			globalWait = 1;
		}
		else if (strcmp(argv[i],"--flag-snakesalive") == 0)
		{
			#ifdef ARCHI_64
			printf(" [INFO] snakesalive mode not implemented for 64-bit, ignoring flag\n");
			#else
			opFlags |= OPM_FLAGS_SNAKESALIVE;
			#endif
		}
		else if (strcmp(argv[i],"--flag-peek") == 0)
		{
			opFlags |= OPM_FLAGS_PEEK;
		}
		else if (strcmp(argv[i],"--flag-dnr") == 0)
		{
			opFlags |= OPM_FLAGS_DNR;
		}
		else if (strcmp(argv[i],"--flag-wait") == 0)
		{
			opFlags |= OPM_FLAGS_WAIT;
		}
		else if (strcmp(argv[i],"--flag-mscoree") == 0)
		{
			opFlags |= OPM_FLAGS_MSCOREE;
		}
		else if (strcmp(argv[i],"-timer") == 0 && i + 1 < argc)
		{
			globalCooldown = atoi(argv[i+1]);
			i++;
		}
		else if((strcmp(argv[i],"-findwindow") == 0 || strcmp(argv[i],"--findwindow") == 0)\
				&& i + 1 < argc\
				&& opMode == OPMODE_DEFAULT)
		{
			opMode = OPMODE_INJECT;
			globalInject = findprocessbywindow(argv[i+1]);

			if (globalInject == 0)
			{
				printf(" [FAIL] could not parse process id \"%s\", ignoring subsequent arguments\n",argv[i+1]);
				opMode = OPMODE_DEFAULT;
				return;
			}

			i++;
		}
		else if((strcmp(argv[i],"-fastinject") == 0 || strcmp(argv[i],"--fastinject") == 0)\
				&& i + 1 < argc\
				&& opMode == OPMODE_DEFAULT)
		{
			opMode = OPMODE_INJECT;
			globalInject = listProcesses_matchFirst(argv[i+1]);
			
			if(globalInject == 0)
			{
				printf(" [FAIL] could not find process \"%s\", ignoring subsequent arguments\n",argv[i+1]);
				opMode = OPMODE_DEFAULT;
				return;
			}
			i++;
		}
		else if(strcmp(argv[i],"-inject") == 0 && i + 1 < argc && opMode == OPMODE_DEFAULT)
		{
			opMode = OPMODE_INJECT;
			globalInject = (int )strtol(argv[i+1],NULL,0);
			if( globalInject == 0)
			{
				printf(" [FAIL] could not parse process id \"%s\", ignoring subsequent arguments\n",argv[i+1]);
				opMode = OPMODE_DEFAULT;
				return;
			}
			i++;
		}
		else if(strcmp(argv[i],"-listall") == 0 && opMode == OPMODE_DEFAULT)
		{
			opMode = OPMODE_LIST;
		}
		else if (strcmp(argv[i],"-dll") == 0 && i + 1 < argc)
		{
			globalDll = fullpath(argv[i+1]);
			i++;
		}
		else if (strcmp(argv[i],"-exe") == 0 && i + 1 < argc)
		{
			globalExeName = fullpath(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i],"-wdir") == 0 && i + 1 < argc)
		{
			globalWorkingDirectory = strdup(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i],"-list") == 0 && i+1 < argc && opMode == OPMODE_DEFAULT)
		{
			opMode = OPMODE_LIST;
			if (strcmp(argv[i+1],"all") != 0)
			{
				stringToMatch = argv[i+1];
			}
			i++;
		}
		else
		{
			printf(" [FAIL] unexpected argument \"%s\", ignoring\n",argv[i]);
			return;
		}
	}
	return;
}

char *fullpath(char *dllName)
{
	if (dllName[0] == '\\')
	{
		return dllName;
	}

	if(dllName[1] == ':')
	{
		return dllName;
	}

	char *retnValue = (char *)malloc(MAX_PATH);
	memset(retnValue,0,MAX_PATH);

	GetCurrentDirectory(MAX_PATH,retnValue);
	strcat(retnValue,"\\");
	strcat(retnValue,dllName);
	
	return retnValue;
}

int findprocessbywindow(char *strToMatch)
{
	HWND hproc = FindWindow(NULL,strToMatch);
	if(hproc == NULL)
	{
		return 0;
	}
	DWORD PID = 0;
	DWORD tid = GetWindowThreadProcessId(hproc,&PID);
	return PID;
}

int listProcesses_matchFirst(char *strToMatch)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	PROCESSENTRY32 pe32;
	memset(&pe32,0,sizeof(pe32));
	pe32.dwSize = sizeof(pe32);

	int bCont = Process32First(hSnap,&pe32);
	while(bCont == TRUE)
	{
		if (strToMatch != NULL && pe32.szExeFile != NULL)
		{
			if(strstr(pe32.szExeFile,strToMatch) != NULL)
			{
				printf(" %04x : %s\n",pe32.th32ProcessID,pe32.szExeFile );
				return pe32.th32ProcessID;
			}
		}
		bCont = Process32Next(hSnap,&pe32);
	}
	return 0;
}

void listProcesses(char *strToMatch)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	PROCESSENTRY32 pe32;
	memset(&pe32,0,sizeof(pe32));
	pe32.dwSize = sizeof(pe32);

	int bCont = Process32First(hSnap,&pe32);
	while(bCont == TRUE)
	{
		if (strToMatch != NULL)
		{
			if(strstr(pe32.szExeFile,strToMatch) != NULL)
			{
				printf(" %04x : %s\n",pe32.th32ProcessID,pe32.szExeFile );
			}
		}
		else
		{
			printf(" %04x : %s\n",pe32.th32ProcessID,pe32.szExeFile );
		}
		bCont = Process32Next(hSnap,&pe32);
	}
	return;
}

BOOL IsDll64Bit(char *dllName)
{
	IMAGE_DOS_HEADER *imgDosHdr = (IMAGE_DOS_HEADER *)malloc(sizeof(IMAGE_DOS_HEADER ));
	IMAGE_NT_HEADERS *imgNtHdrs = (IMAGE_NT_HEADERS *)malloc(sizeof(IMAGE_NT_HEADERS ));

	FILE *f = fopen(dllName,"rb");

	fread(imgDosHdr,sizeof(IMAGE_DOS_HEADER),1,f);
	fseek(f,sizeof(IMAGE_DOS_HEADER) + imgDosHdr->e_lfanew,SEEK_SET);
	fread(imgNtHdrs,sizeof(IMAGE_NT_HEADERS),1,f);
	fclose(f);

	printf("MMMAAGGIC : %x\n",imgNtHdrs->OptionalHeader.Magic);

	free(imgDosHdr);
	free(imgNtHdrs);
	return TRUE;
}

void injectIntoProcess(int processId, char *dllInput)
{
	printf(" [WARN] inject mode, this is inherently risky\n");

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,processId);
	if (hProcess == NULL)
	{
		printf(" [FAIL] could not open process %04x\n",processId);
		return;
	}

	globalPid = processId;
	printf(" [INFO] injected into process %d\n",processId);

	SIZE_T bW = 0, bR = 0;
	printf(" [INFO] attempting to create data cave\n");
	LPVOID remoteMemory = VirtualAllocEx(hProcess,NULL,strlen(dllInput) + 1,MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess,(LPVOID )remoteMemory,dllInput,strlen(dllInput) + 1,&bW);

	HANDLE hKernel = LoadLibrary("kernel32.dll");
	LPVOID addrLoadLibrary = GetProcAddress( (HMODULE )hKernel, "LoadLibraryA");
	
	printf(" [INFO] trying to create a remote thread at 0x%p\n",(void *)addrLoadLibrary);

	char *dllOutput = (char *)malloc(MAX_PATH);
	memset(dllOutput,0,MAX_PATH);
	ReadProcessMemory(hProcess,(LPCVOID )remoteMemory,dllOutput,MAX_PATH,&bR);

	printf(" [INFO] confirming process has cave with \"%s\"\n",dllOutput);
	free(dllOutput);

	if(globalWait)
	{
		printf(" [WAIT] press any key to create remote thread...\n");
		getc(stdin);
	}

	HANDLE threadId = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE )addrLoadLibrary,remoteMemory,NULL,NULL);
	if (threadId == NULL)
	{
		printf(" [INFO] could not create remote thread\n");
		return;
	}
	else
	{
		WaitForSingleObject(threadId, INFINITE);   //this waits untill thread thread has finished
		// VirtualFree(remoteMemory, 0, MEM_RELEASE); //free myFunc memory
		CloseHandle(threadId);
		CloseHandle(hProcess);
	 }

	printf(" [INFO] success!\n");

	if (globalPid != 0)
	{
		printf("\n\n - to connect to this process, use peek %d - \n\n", globalPid);
	}

	return;
}

int main(int argc,char **argv)
{
	parseArgs(argc, argv);

	SIZE_T bW = 0, bR = 0;
	char *exeInput = (char *)malloc(MAX_PATH);
	char *dllInput = (char *)malloc(MAX_PATH);
	char *wdrInput = (char *)malloc(MAX_PATH);

	memset(exeInput,0,MAX_PATH);
	memset(dllInput,0,MAX_PATH);
	memset(wdrInput,0,MAX_PATH);

	if (opMode == OPMODE_LIST)
	{
		listProcesses(stringToMatch);
		return 0;
	}
	else if(opMode == OPMODE_INJECT)
	{
		if (globalDll == NULL)
		{
			printf(" [dll] > ");
			fgets(dllInput,MAX_PATH,stdin);
		}
		else
		{
			strcpy(dllInput,globalDll);
		}
		injectIntoProcess(globalInject,dllInput);
		return 0;
	}

	if (globalTest)
	{
		printf("bye!\n");
		exit(0);
	}
	else if(globalExeName == NULL || globalWorkingDirectory == NULL || globalDll == NULL)
	{
		// printf("* SOMETHING MISSING %08x%08x%08x\n", (unsigned long )globalExeName, (unsigned long )globalWorkingDirectory, (unsigned long )globalDll);
		printf(" [exe] > ");
		fgets(exeInput,MAX_PATH,stdin);
		if (globalDll == NULL)
		{
			printf(" [dll] > ");
			fgets(dllInput,MAX_PATH,stdin);
		}
		else
		{
			strcpy(dllInput,globalDll);
		}
		printf(" [wdr] > ");
		fgets(wdrInput,MAX_PATH,stdin);

		chomp(exeInput);
		chomp(dllInput);
		chomp(wdrInput);
	}
	else
	{
		strcpy(exeInput,globalExeName);
		strcpy(dllInput,globalDll);
		strcpy(wdrInput,globalWorkingDirectory);
	}

	if (exists(exeInput) == 0)
	{
		printf(" [FAIL-EXE] %s does not exist\n",exeInput);
		return 0;
	}

	if(exists(dllInput) == 0)
	{
		printf(" [FAIL-DLL] %s does not exist\n",dllInput);
		return 0;
	}

	PROCESS_INFORMATION pi;
	STARTUPINFO si;

	memset (&pi,0,sizeof(PROCESS_INFORMATION));
	memset (&si, 0, sizeof (STARTUPINFO));
	si.cb = sizeof(si);

	HANDLE hNtDll = LoadLibrary("ntdll.dll");
	NtQueryInformationProcess = (_NtQueryInformationProcess )(GetProcAddress( (HMODULE )hNtDll, "NtQueryInformationProcess"));
	HANDLE hKernel = LoadLibrary("kernel32.dll");
	LPVOID addrLoadLibrary = GetProcAddress( (HMODULE )hKernel, "LoadLibraryA");

	BOOL derp = CreateProcess(exeInput, exeInput, NULL, NULL, FALSE, CREATE_SUSPENDED + CREATE_NEW_CONSOLE, NULL, wdrInput, &si, &pi);
	if (derp == NULL)
	{
		char *errorMessage;
		FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER +
                     FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError (), 0,
                     (char *) &errorMessage, 1, NULL);
		printf (" [FAIL] %s", errorMessage);
		return 0;
	}

	HANDLE hProcess = pi.hProcess;
	HANDLE hThread = pi.hThread;

	globalPid = pi.dwProcessId;
	printf(" * [INFO] new process id is %d\n",pi.dwProcessId);

	#if ARCHI == 64
		BOOL wow64 = FALSE;
		IsWow64Process(hProcess,&wow64);

		if (wow64 == TRUE)
		{
			IsDll64Bit(globalDll);
			printf(" [WARN] injecting into wow64 ");
		}
	#endif

	printf(" [INFO] process handle is 0x%p\n",(void *)hProcess);

	PROCESS_BASIC_INFORMATION pib;
	PEB_ARCHI globalPEB;

	NtQueryInformationProcess (hProcess, 0, (PVOID )(&pib), sizeof (pib),& bW);
	printf(" [INFO] pib.PebBaseAddress = 0x%p (size of field is %d)\n", pib.PebBaseAddress, (int )sizeof(pib.PebBaseAddress));
	if(pib.PebBaseAddress == 0)
	{
		printf(" [INFO] pebbaseaddress == 0; are you trying ldr32 on a 64bit process?\n");
		exit(0);
	}

	ReadProcessMemory (hProcess, pib.PebBaseAddress, &globalPEB, sizeof (globalPEB), &bR);
	if (bR != sizeof (globalPEB))
    {
		char *errorMessage;
		FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER +
                     FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError (), 0,
                     (char *) &errorMessage, 1, NULL);
		printf (" [FAIL] %s", errorMessage);
		return 0;
    }

	printf(" [INFO] peb.ImageBaseAddress = %p\n", (void *)(globalPEB.ImageBaseAddress));

	UINT_PTR entryPoint = guessExecutableEntryPoint (hProcess, globalPEB.ImageBaseAddress);
	printf(" [INFO] entryPoint = 0x%p\n", (void *)entryPoint);
	
	entryPoint &= 0xFFFFFFFF;
	if((void *)entryPoint < (void *)globalPEB.ImageBaseAddress)
	{
		printf(" [INFO] entrypoint < base address, compensating for ASLR\n");
		entryPoint += globalPEB.ImageBaseAddress;
	}

	char oldEntryChars[2];
	DWORD oldProtect = 0;
	DWORD discardProtect = 0;
	
	DWORD dotNetFix_oldProtect = 0;
	
	char newEntryChars[2];
	
	if((opFlags & OPM_FLAGS_SNAKESALIVE) == 0)
	{

		VirtualProtectEx(hProcess,(LPVOID )entryPoint,1, PAGE_READWRITE, &oldProtect);
		ReadProcessMemory(hProcess,(LPCVOID )entryPoint,(char *)oldEntryChars,2,&bR);
		printf(" [INFO] old entry is %02x %02x\n", (unsigned char )oldEntryChars[0],(unsigned char )oldEntryChars[1]);
		if(oldEntryChars[0] == '\xFF' && oldEntryChars[1] == '\x25' )
		{
			if(opFlags & OPM_FLAGS_MSCOREE)
			{
				printf(" [.NET] this looks like a .net executable, --flag-mscoree detected, proceeding\n");
			}
			else
			{
				printf(" [.NET] this looks like a .net executable, recommend --flag-mscoree, proceeding regardless\n");
			}
		}
		else if(opFlags & OPM_FLAGS_MSCOREE)
		{
			printf(" [.NET] this doesn't look like a .net executable...\n");
		}
		
		printf(" [INFO] writing...\n");

		if(WriteProcessMemory(hProcess,(LPVOID )entryPoint,"\xEB\xFE",2,&bW) == 0)
		{
			printf(" [FAIL] WriteProcessMemory failed, check for countermeasures\n");
		}
		if(oldProtect == PAGE_READONLY)
		{
			VirtualProtectEx(hProcess,(LPVOID )entryPoint,1,PAGE_EXECUTE_READ,&discardProtect);
			printf(" [INFO] .net page permissions fix, saving original permissions\n");
			dotNetFix_oldProtect = PAGE_READONLY;
		}
		else
		{
			
			VirtualProtectEx(hProcess,(LPVOID )entryPoint,1,oldProtect,&discardProtect);
		}

		ReadProcessMemory(hProcess,(LPCVOID )entryPoint,(char *)newEntryChars,2,&bR);
		if (newEntryChars[0] == '\xEB' && newEntryChars[1] == '\xFE')
		{
			printf(" [INFO] new entry is %02x %02x\n", (unsigned char )newEntryChars[0],(unsigned char )newEntryChars[1]);
		}
		else
		{
			printf(" [INFO] new entry is %02x %02x, something's wrong\n", (unsigned char )newEntryChars[0],(unsigned char )newEntryChars[1]);
			return 0;
		}
	
	}
	
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;

	GetThreadContext (hThread, &context);
	context.PC_REG = entryPoint;
	SetThreadContext(hThread,&context);
	
	if(opFlags & OPM_FLAGS_SNAKESALIVE)
	{
		#define SNAKESALIVE_MIN 20
		// niche-case process hollowing. use with care.
		int i = 0;
		if(opFlags & OPM_FLAGS_WAIT)
		{
			printf(" [SNAKES] --wait specified, attach a debugger now and hit enter\n");
			getchar();
		}
		HMODULE hMods[1024];
		DWORD cbNeeded = 0;
		MODULEINFO modInfo;
		char mbuf[1024];
		memset(mbuf,0,1024);
		if( EnumProcessModules( hProcess, hMods, sizeof(hMods),&cbNeeded) )
		{
			int i = 0;
			for (; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				char szModName[1024];
				GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo));
				if(GetModuleFileNameEx( hProcess,hMods[i],szModName,sizeof(szModName) / sizeof(char)) )
				{
					if ( GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo)) )
					{
						sprintf(mbuf," + %s (0x%p, size:%x) (entry:0x%p)\n",shortName(szModName),hMods[i],modInfo.SizeOfImage,modInfo.EntryPoint);
						printf(mbuf);
					}
					else
					{
						sprintf(mbuf," + %s (no info available)\n",shortName(szModName));
						printf(mbuf);
					}	
				
				}
			}
		}
		
		// just to sanity check. should be at the same place.
		UINT_PTR ptrLoadLibraryA = (UINT_PTR )GetProcAddress(LoadLibrary("kernel32"),"LoadLibraryA");
		printf(" [SNAKES] Local LoadLibraryA = %p\n",(void *)ptrLoadLibraryA);
		
		int llc = 0;
		char *loadLibraryPrefix = (char *)malloc(10);
		ReadProcessMemory(hProcess,(LPCVOID )ptrLoadLibraryA,(char *)loadLibraryPrefix,10,&bR);
		for(llc = 0;llc < 10;llc++)
		{
			if(((char *)ptrLoadLibraryA)[llc]  != loadLibraryPrefix[llc])
			{
				printf(" [SNAKES] local loadlibary != remote loadlibrary, exiting\n");
				exit(0);
			}
		}
		free(loadLibraryPrefix);
		 
		
		// LPVOID remoteMemory = VirtualAllocEx(hProcess,NULL,strlen(dllInput) + 1,MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE);
		// WriteProcessMemory(hProcess,(LPVOID )remoteMemory,dllInput,strlen(dllInput) + 1,&bW);
		
		// printf(" [SNAKES] inserting libname at %p\n",(void *)remoteMemory);
		
		int SNAKESALIVE_BUFSIZE = SNAKESALIVE_MIN + strlen(dllInput) + 1;
		
		printf(" [SNAKES] exteded shellcode %d bytes\n",SNAKESALIVE_BUFSIZE);
		char *lla_bytes = (char *)malloc(SNAKESALIVE_BUFSIZE);
		memset(lla_bytes,0xCC,SNAKESALIVE_BUFSIZE);
		
		// actual entrypoint
		int x = 0;
		lla_bytes[x++] = 0x68;
		((DWORD *)((char *)lla_bytes + x))[0] = (DWORD )entryPoint + SNAKESALIVE_MIN;
		// wrong opcode, let's use the push / ret trick again.
		x += 4;
		lla_bytes[x++] = 0x90;
		((DWORD *)((char *)lla_bytes + x))[0] = (DWORD )0x90909090;
		x += 4;
		lla_bytes[x++] = 0xE8;
		((DWORD *)((char *)lla_bytes + x))[0] = (DWORD )(ptrLoadLibraryA - (entryPoint + x + 4));
		x += 4;
		lla_bytes[x++] = 0xEB;
		lla_bytes[x++] = 0xFE;
		x = SNAKESALIVE_MIN;
		printf(" [SNAKES] inserting libname at %p\n",(void *)(lla_bytes + SNAKESALIVE_MIN));
		strcpy(lla_bytes + x, dllInput);
		
		// lla_bytes[x+13] = 0xFE;
		// lla_bytes[x+14] = 0xFE;

		printf(" [SNAKES] inserting shellcode...\n");
		VirtualProtectEx(hProcess,(LPVOID )entryPoint,1, PAGE_READWRITE, &oldProtect);
		// ReadProcessMemory(hProcess,(LPCVOID )entryPoint,(char *)oldEntryChars,2,&bR);
		// printf(" [INFO] old entry is %02x %02x\n", (unsigned char )oldEntryChars[0],(unsigned char )oldEntryChars[1]);
		// printf(" [INFO] writing...\n");
		i = WriteProcessMemory(hProcess,(LPVOID )entryPoint,lla_bytes,SNAKESALIVE_BUFSIZE,&bW);
		if (i == 0)
		{
			char *errorMessage;
			FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER +
						 FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError (), 0,
						 (char *) &errorMessage, 1, NULL);
			printf (" [FAIL] %s", errorMessage);
			return 0;
		}
		
		char *snakesalive_confirm = (char *)malloc(SNAKESALIVE_BUFSIZE);
		memset(snakesalive_confirm,0,SNAKESALIVE_BUFSIZE);
		
		// ReadProcessMemory(hProcess,(LPCVOID )remoteMemory,dllOutput,SNAKESALIVE_BUFSIZE,&bR);
		// printf(" [INFO] confirming process has cave with \"%s\"\n",dllOutput);
		
		if(dotNetFix_oldProtect)
		{
			oldProtect = dotNetFix_oldProtect;
		}
		VirtualProtectEx(hProcess,(LPVOID )entryPoint,1,oldProtect,&discardProtect);
		ResumeThread(pi.hThread);
		
		if(opFlags & OPM_FLAGS_PEEK)
		{
			printf(" .. launching peek ..\n");
			sprintf(snakesalive_confirm,"peek %d",pi.dwProcessId);

			system(snakesalive_confirm);
			free(snakesalive_confirm);
		}
		printf(" [INFO] bye!");
		free(exeInput);
		free(dllInput);
		free(wdrInput);
		return 0;
	}
	
	if(opFlags & OPM_FLAGS_WAIT)
	{
		printf(" [INFO] --wait specified, hit enter when ready...\n");
		getchar();
	}
	ResumeThread(pi.hThread);
	
	LPVOID remoteMemory = VirtualAllocEx(hProcess,NULL,strlen(dllInput) + 1,MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess,(LPVOID )remoteMemory,dllInput,strlen(dllInput) + 1,&bW);

	printf(" [INFO] trying to create a remote thread at 0x%p\n",(void *)addrLoadLibrary);

	char *dllOutput = (char *)malloc(MAX_PATH);
	memset(dllOutput,0,MAX_PATH);
	ReadProcessMemory(hProcess,(LPCVOID )remoteMemory,dllOutput,MAX_PATH,&bR);
	printf(" [INFO] confirming process has cave with \"%s\"\n",dllOutput);
	free(dllOutput);

	if(globalWait)
	{
		printf(" [WAIT] press any key to create remote thread...\n");
		getc(stdin);
	}

	HANDLE threadId = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE )addrLoadLibrary,remoteMemory,NULL,NULL);
	if (threadId == NULL)
	{
		printf(" [INFO] could not create remote thread\n");
		return 0;
	}
	else
	{
		WaitForSingleObject(threadId, INFINITE);   //this waits untill thread thread has finished
		// VirtualFree(remoteMemory, 0, MEM_RELEASE); //free myFunc memory
		CloseHandle(threadId);
		// CloseHandle(hProcess);
	 }

	int i = globalCooldown;
	for (; i > 0; i--)
	{
		printf(" [INFO] waiting %d seconds\n",i);
		Sleep(1000);
	}

	if(opFlags & OPM_FLAGS_DNR)
	{
		printf(" [INFO] --flag-dnr supplied, leaving process locked\n");
	}
	else if(opFlags & OPM_FLAGS_MSCOREE)
	{
		printf(" [.NET] deploying trickery for MSCOREE recovery\n");
		// see http://srevas.net/notes/2007/12/25/mscoree/
		SuspendThread(pi.hThread);
		
					REGISTER_LENGTH remoteMscoreeBase = 0;
		// prep: identify where CorExeMain is in our own process.
		MODULEINFO module_info; memset(&module_info, 0, sizeof(module_info));
		HANDLE mscoree_base = LoadLibrary("mscoree.dll");
		HANDLE mscoree_handle = GetModuleHandle("mscoree.dll");
		if (GetModuleInformation(GetCurrentProcess(), (HMODULE )mscoree_handle, &module_info, sizeof(module_info))) {
			DWORD module_size = module_info.SizeOfImage;
			BYTE * module_ptr = (BYTE*)module_info.lpBaseOfDll;
			printf(" [.NET] local MSCOREE at %p, size %d\n",module_ptr,module_size);
			BYTE * corexe_ptr = (BYTE *)GetProcAddress((HMODULE )mscoree_base,"_CorExeMain");
			printf(" [.NET] local _CorExeMain at %p, offset %x\n",corexe_ptr,(unsigned long )(corexe_ptr - module_ptr));
			
			printf(" [.NET] enumerating for remote MSCOREE... \n");
			
			HMODULE hMods[1024];
			DWORD cbNeeded = 0;
			MODULEINFO modInfo;
			char mbuf[1024];
			memset(mbuf,0,1024);

			if( EnumProcessModules( hProcess, hMods, sizeof(hMods),&cbNeeded) )
			{
				int i = 0;
				for (; i < (cbNeeded / sizeof(HMODULE)); i++)
				{
					char szModName[1024];
					GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo));
					if(GetModuleFileNameEx( hProcess,hMods[i],szModName,sizeof(szModName) / sizeof(char)) )
					{
						if ( GetModuleInformation(hProcess,hMods[i],&modInfo,sizeof(modInfo)) )
						{
							sprintf(mbuf," + %s (0x%p, size:%x) (entry:0x%p)\n",shortName(szModName),hMods[i],modInfo.SizeOfImage,modInfo.EntryPoint);
							printf(mbuf);
							if(strcmp(shortName(szModName),"MSCOREE.DLL") == 0)
							{
								printf(" [.NET] found MSCOREE at %p\n",hMods[i]);
								remoteMscoreeBase = (REGISTER_LENGTH )hMods[i];
								break;
							}
						}
						else
						{
							sprintf(mbuf," + %s (no info available)\n",shortName(szModName));
							printf(mbuf);
						}	
					}
				}
			}
			
			if(remoteMscoreeBase == 0)
			{
				printf(" [.NET] --flag-mscoree specified but MSCOREE not loaded, exiting\n");
				exit(0);
			}
			printf(" [.NET] ignoring relocations, doing it ourselves...\n");
			REGISTER_LENGTH iatEntry = (REGISTER_LENGTH )(remoteMscoreeBase + (corexe_ptr - module_ptr));
			VirtualProtectEx(hProcess,(LPVOID )(entryPoint + 10),1, PAGE_READWRITE, &oldProtect);
			i = WriteProcessMemory(hProcess,(LPVOID )(entryPoint + 10),(char *)&iatEntry,sizeof(REGISTER_LENGTH),&bW);
			if (i == 0)
			{
				char *errorMessage;
				FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER +
							 FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError (), 0,
							 (char *) &errorMessage, 1, NULL);
				printf (" [FAIL] %s", errorMessage);
				return 0;
			}
			VirtualProtectEx(hProcess,(LPVOID )(entryPoint + 10),1, oldProtect, &discardProtect);
		}
		else
		{
			printf(" [FAIL] couldn't get information for mscoree in our own process\n");
			exit(0);
		}
		
		/*
		// step 1 is to fix the static call address (i.e. ida -> live)
		char *mscoree_fix = (char *)malloc(6);
		mscoree_fix[0] = '\xFF';
		mscoree_fix[1] = '\x25';
		// todo: avoid assuming .net compiles the same way.
		((DWORD *)((char *)mscoree_fix + 2))[0] = entryPoint - (globalPEB.ImageBaseAddress + 0x2000);
		*/
		
		char *mscoree_fix = (char *)malloc(7);
		mscoree_fix[0] = '\xFF';
		mscoree_fix[1] = '\x25';
		// todo: avoid assuming .net compiles the same way.
		((DWORD *)((char *)mscoree_fix + 2))[0] = 4;
		
		printf(" [.NET] inserting custom loader\n");
		// step 2 is to dynamic load the static call address (?)
		VirtualProtectEx(hProcess,(LPVOID )entryPoint,1, PAGE_READWRITE, &oldProtect);
		i = WriteProcessMemory(hProcess,(LPVOID )entryPoint,(char *)mscoree_fix,6,&bW);
		if (i == 0)
		{
			char *errorMessage;
			FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER +
						 FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError (), 0,
						 (char *) &errorMessage, 1, NULL);
			printf (" [FAIL] %s", errorMessage);
			return 0;
		}
		ReadProcessMemory(hProcess,(LPCVOID )entryPoint,mscoree_fix,6,&bR);
		VirtualProtectEx(hProcess,(LPVOID )entryPoint,1, oldProtect, &discardProtect);
		
		GetThreadContext (hThread, &context);
		context.PC_REG = entryPoint;
		SetThreadContext(hThread,&context);
		ResumeThread(pi.hThread);
	}
	else
	{
		printf(" [INFO] restoring entrypoint...\n");
		SuspendThread(pi.hThread);

		VirtualProtectEx(hProcess,(LPVOID )entryPoint,1, PAGE_READWRITE, &oldProtect);
		i = WriteProcessMemory(hProcess,(LPVOID )entryPoint,(char *)&oldEntryChars,2,&bW);
		if (i == 0)
		{
			char *errorMessage;
			FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER +
						 FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError (), 0,
						 (char *) &errorMessage, 1, NULL);
			printf (" [FAIL] %s", errorMessage);
			return 0;
		}
		ReadProcessMemory(hProcess,(LPCVOID )entryPoint,(char *)newEntryChars,2,&bR);
		VirtualProtectEx(hProcess,(LPVOID )entryPoint,1, oldProtect, &discardProtect);

		printf(" [INFO] entry restored to %02x %02x\n", (unsigned char )newEntryChars[0],(unsigned char )newEntryChars[1]);
		GetThreadContext (hThread, &context);
		context.PC_REG = entryPoint;
		SetThreadContext(hThread,&context);
		ResumeThread(pi.hThread);
	}
	
	if(opFlags & OPM_FLAGS_PEEK)
	{
		char cmdbuf[50];
		printf(" .. launching peek ..\n");
		sprintf(cmdbuf,"peek %d",pi.dwProcessId);
		system(cmdbuf);
	}
	
	printf(" [INFO] bye!");
	free(exeInput);
	free(dllInput);
	free(wdrInput);

	return 0;
}

UINT_PTR guessExecutableEntryPoint (HANDLE globalhProcess, UINT_PTR baseaddr)
{
  IMAGE_DOS_HEADER imgDosHdr;
  IMAGE_NT_HEADERS imgNtHdr;
  SIZE_T bR;

  memset (&imgDosHdr, 0, sizeof (IMAGE_DOS_HEADER));
  memset (&imgNtHdr, 0, sizeof (IMAGE_NT_HEADERS));

  ReadProcessMemory (globalhProcess, (LPCVOID ) baseaddr, &imgDosHdr,
                     sizeof (IMAGE_DOS_HEADER), &bR);

  if (bR != sizeof (IMAGE_DOS_HEADER))
    {
      printf (" [FAIL] could not read IMAGE_DOS_HEADER (read 0x%04x bytes)\n",(unsigned int )bR);
      return 0;
    }

  ReadProcessMemory (globalhProcess,
                     (LPCVOID ) (baseaddr + imgDosHdr.e_lfanew), &imgNtHdr,
                     sizeof (IMAGE_NT_HEADERS), &bR);
  if (bR != sizeof (IMAGE_NT_HEADERS))
    {
      printf (" [INFO] could not read IMAGE_NT_HEADERS (read 0x%04x bytes)\n",(unsigned int )bR);
      return 0;
    }
	
	printf(" [DEBUG] guessExecutableEntryPoint: imgNtHdr.OptionalHeader.ImageBase = %p\n",(void *)imgNtHdr.OptionalHeader.ImageBase);
	printf(" [DEBUG] guessExecutableEntryPoint: imgNtHdr.OptionalHeader.AddressOfEntryPoint = %p\n",(void *)(UINT_PTR )(imgNtHdr.OptionalHeader.AddressOfEntryPoint));
	
	if(imgNtHdr.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
	{
		printf(" [INFO] ASLR indicated by PE header, returning minimal entry\n");
		return imgNtHdr.OptionalHeader.AddressOfEntryPoint;	
	}
	else
	{
		return imgNtHdr.OptionalHeader.AddressOfEntryPoint + imgNtHdr.OptionalHeader.ImageBase;
	}
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

int exists(const char *fname)
{
    FILE *file;
    if (file = fopen(fname, "r"))
    {
        fclose(file);
        return 1;
    }
    return 0;
}
