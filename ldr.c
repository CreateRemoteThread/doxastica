#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>

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
typedef DWORD (WINAPI * _NtQueryInformationProcess) (HANDLE, DWORD, DWORD, DWORD, DWORD);

_NtQueryInformationProcess NtQueryInformationProcess;

#define OPMODE_DEFAULT 0
#define OPMODE_LIST 1
#define OPMODE_INJECT 2

int globalWait = 0;
int globalTest = 0;
int globalCooldown = 0;
int globalInject = 0;
char *globalDll = NULL;
char *stringToMatch = NULL;
int opMode = OPMODE_DEFAULT;

typedef struct _PEB
{
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN Spare;
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PVOID LoaderData;
  // PPEB_LDR_DATA LoaderData;
  PVOID ProcessParameters;
  // PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PVOID FastPebLock;
  PVOID FastPebLockRoutine;
  // PPEBLOCKROUTINE FastPebLockRoutine;
  PVOID FastPebUnlockRoutine;
  // PPEBLOCKROUTINE FastPebUnlockRoutine; 
  ULONG EnvironmentUpdateCount;
  PVOID KernelCallbackTable;
  // PPVOID KernelCallbackTable;
  PVOID EventLogSection;
  PVOID EventLog;
  PVOID FreeList;
  // PPEB_FREE_BLOCK FreeList; 
  ULONG TlsExpansionCounter;
  PVOID TlsBitmap;
  ULONG TlsBitmapBits[0x2];
  PVOID ReadOnlySharedMemoryBase;
  PVOID ReadOnlySharedMemoryHeap;
  PVOID ReadOnlyStaticServerData;
  // PPVOID ReadOnlyStaticServerData; 
  PVOID AnsiCodePageData;
  PVOID OemCodePageData;
  PVOID UnicodeCaseTableData;
  ULONG NumberOfProcessors;
  ULONG NtGlobalFlag;
  BYTE Spare2[0x4];
  LARGE_INTEGER CriticalSectionTimeout;
  ULONG HeapSegmentReserve;
  ULONG HeapSegmentCommit;
  ULONG HeapDeCommitTotalFreeThreshold;
  ULONG HeapDeCommitFreeBlockThreshold;
  ULONG NumberOfHeaps;
  ULONG MaximumNumberOfHeaps;
  PVOID ProcessHeaps;
  // PPVOID *ProcessHeaps;
  PVOID GdiSharedHandleTable;
  PVOID ProcessStarterHelper;
  PVOID GdiDCAttributeList;
  PVOID LoaderLock;
  ULONG OSMajorVersion;
  ULONG OSMinorVersion;
  ULONG OSBuildNumber;
  ULONG OSPlatformId;
  ULONG ImageSubSystem;
  ULONG ImageSubSystemMajorVersion;
  ULONG ImageSubSystemMinorVersion;
  ULONG GdiHandleBuffer[0x22];
  ULONG PostProcessInitRoutine;
  ULONG TlsExpansionBitmap;
  BYTE TlsExpansionBitmapBits[0x80];
  ULONG SessionId;
} PEB, *PPEB;

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
  PPEB PebBaseAddress;
  PVOID Reserved2[2];
  ULONG_PTR UniqueProcessId;
  PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

DWORD guessExecutableEntryPoint (HANDLE globalhProcess, DWORD baseaddr);
int exists(const char *fname);
char *fullpath(char *dllName);

void help()
{
	printf(" [INFO] dll ldr v0.1\n");
	printf(" [INFO] -wait : wait for input before injecting\n");
	printf(" [INFO] -test : inject shackle.dll into test.exe (hardcoded)\n");
	printf(" [INFO] -timer : wait x seconds until inject\n");
	printf(" [INFO] -dll : specify name of dll to inject\n");
	printf(" [INFO] -inject : inject into PID (hexadecimal)\n");
	printf(" [INFO] -fastinject : inject into first instance of executable name\n");
	printf(" [INFO] -list : list all processes matching mask\n");
	printf(" [INFO] -listall : list all processes\n");
	printf(" [INFO] -exe : use specified executable\n");
	printf(" [INFO] -wdir : use specified working directory (raw)\n");
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
		else if (strcmp(argv[i],"-test") == 0)
		{
			globalTest = 1;
		}
		else if (strcmp(argv[i],"-timer") == 0 && i + 1 < argc)
		{
			globalCooldown = atoi(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i],"-fastinject") == 0 && i + 1 < argc && opMode == OPMODE_DEFAULT)
		{
			opMode = OPMODE_INJECT;
			globalInject = listProcesses_matchFirst(argv[i+1]);
			
			if(globalInject == 0)
			{
				printf(" [FAIL] could not parse process id \"%s\", ignoring subsequent arguments\n",argv[i+1]);
				opMode = OPMODE_DEFAULT;
				return;
			}
			i++;
		}
		else if(strcmp(argv[i],"-inject") == 0 && i + 1 < argc && opMode == OPMODE_DEFAULT)
		{
			opMode = OPMODE_INJECT;
			if(sscanf(argv[i+1],"%x",&globalInject) != 1)
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

void injectIntoProcess(int processId, char *dllInput)
{
	printf(" [WARN] inject mode, this is inherently risky\n");

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,processId);
	if (hProcess == NULL)
	{
		printf(" [FAIL] could not open process %04x\n",processId);
		return;
	}

	DWORD bW = 0, bR = 0;
	printf(" [INFO] attempting to create data cave\n");
	LPVOID remoteMemory = VirtualAllocEx(hProcess,NULL,strlen(dllInput) + 1,MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess,(LPVOID )remoteMemory,dllInput,strlen(dllInput) + 1,&bW);

	HANDLE hKernel = LoadLibrary("kernel32.dll");
	LPVOID addrLoadLibrary = GetProcAddress( (HMODULE )hKernel, "LoadLibraryA");
	
	printf(" [INFO] trying to create a remote thread at %08x\n",(unsigned long )addrLoadLibrary);

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
	return;
}

int main(int argc,char **argv)
{
	parseArgs(argc, argv);

	DWORD bW = 0, bR = 0;
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
		strcpy(exeInput,"test.exe");
		strcpy(dllInput,"shackle.dll");
		strcpy(wdrInput,"c:\\projects\\elegurawolfe\\");
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

	printf(" [INFO] process handle is %08x\n",(unsigned long )hProcess);

	PROCESS_BASIC_INFORMATION pib;
	PEB globalPEB;

	NtQueryInformationProcess (hProcess, 0, (DWORD) & pib, sizeof (pib), (DWORD) & bW);
	printf(" [INFO] pib.PebBaseAddress = %08x\n", (unsigned long )pib.PebBaseAddress);

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

	printf(" [INFO] peb.ImageBaseAddress = %08x\n", (unsigned long )globalPEB.ImageBaseAddress);

	unsigned long entryPoint = guessExecutableEntryPoint (hProcess, (DWORD) globalPEB.ImageBaseAddress);
	printf(" [INFO] entryPoint = %08x\n", entryPoint);

	char oldEntryChars[2];
	DWORD oldProtect = 0;
	DWORD discardProtect = 0;

	VirtualProtectEx(hProcess,(LPVOID )entryPoint,1, PAGE_READWRITE, &oldProtect);
	ReadProcessMemory(hProcess,(LPCVOID )entryPoint,(char *)oldEntryChars,2,&bR);
	printf(" [INFO] old entry is %02x %02x\n", (unsigned char )oldEntryChars[0],(unsigned char )oldEntryChars[1]);
	printf(" [INFO] writing...\n");

	WriteProcessMemory(hProcess,(LPVOID )entryPoint,"\xEB\xFE",2,&bW);
	VirtualProtectEx(hProcess,(LPVOID )entryPoint,1,oldProtect,&discardProtect);

	char newEntryChars[2];

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
	
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;

	GetThreadContext (hThread, &context);
	context.Eip = entryPoint;
	SetThreadContext(hThread,&context);
	ResumeThread(pi.hThread);

	LPVOID remoteMemory = VirtualAllocEx(hProcess,NULL,strlen(dllInput) + 1,MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess,(LPVOID )remoteMemory,dllInput,strlen(dllInput) + 1,&bW);

	printf(" [INFO] trying to create a remote thread at %08x\n",(unsigned long )addrLoadLibrary);

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
	context.Eip = entryPoint;
	SetThreadContext(hThread,&context);
	ResumeThread(pi.hThread);
	
	printf(" [INFO] bye!");
	free(exeInput);
	free(dllInput);
	free(wdrInput);

	return 0;
}

DWORD guessExecutableEntryPoint (HANDLE globalhProcess, DWORD baseaddr)
{
  IMAGE_DOS_HEADER imgDosHdr;
  IMAGE_NT_HEADERS imgNtHdr;
  DWORD bR;

  memset (&imgDosHdr, 0, sizeof (IMAGE_DOS_HEADER));
  memset (&imgNtHdr, 0, sizeof (IMAGE_NT_HEADERS));

  ReadProcessMemory (globalhProcess, (LPDWORD) baseaddr, &imgDosHdr,
                     sizeof (IMAGE_DOS_HEADER), &bR);

  if (bR != sizeof (IMAGE_DOS_HEADER))
    {
      printf (" [FAIL] could not read IMAGE_DOS_HEADER\n");
      return 0;
    }

  ReadProcessMemory (globalhProcess,
                     (LPDWORD) (baseaddr + imgDosHdr.e_lfanew), &imgNtHdr,
                     sizeof (IMAGE_NT_HEADERS), &bR);
  if (bR != sizeof (IMAGE_NT_HEADERS))
    {
      printf (" [INFO] could not read IMAGE_NT_HEADERS\n");
      return 0;
    }

  return imgNtHdr.OptionalHeader.AddressOfEntryPoint + imgNtHdr.OptionalHeader.ImageBase;
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
