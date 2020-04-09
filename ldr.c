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
#define OPM_FLAGS_SNAKESALIVE 1

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
	printf(" [INFO] --flag-dnr : do not recover\n");
	printf(" [INFO] --flag-snakesalive : special sauce shellcode mode\n");
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
			opFlags |= OPM_FLAGS_SNAKESALIVE;
		}
		else if (strcmp(argv[i],"--flag-dnr") == 0)
		{
			opFlags |= OPM_FLAGS_DNR;
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

	printf(" [INFO] process handle is %08x\n",(unsigned long )hProcess);

	PROCESS_BASIC_INFORMATION pib;
	PEB_ARCHI globalPEB;

	NtQueryInformationProcess (hProcess, 0, (PVOID )(&pib), sizeof (pib),& bW);
	printf(" [INFO] pib.PebBaseAddress = 0x%p (size of field is %d)\n", pib.PebBaseAddress, sizeof(pib.PebBaseAddress));

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
	printf(" [INFO] entryPoint = 0x%8x\n", entryPoint);

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
	context.PC_REG = entryPoint;
	SetThreadContext(hThread,&context);
	
	ResumeThread(pi.hThread);
	
	if(opFlags & OPM_FLAGS_SNAKESALIVE)
	{
		printf(" [INFO] ~~~~~snakesalive~~~~~\n");
		Sleep(1000);
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
		printf(" [INFO] bye!");
		free(exeInput);
		free(dllInput);
		free(wdrInput);
		return 0;
	}
	
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

	if(opFlags & OPM_FLAGS_DNR)
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
	else
	{
		printf(" [INFO] --flag-dnr supplied, skipping recovery\n");
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
      printf (" [FAIL] could not read IMAGE_DOS_HEADER (read %x bytes)\n",bR);
      return 0;
    }

  ReadProcessMemory (globalhProcess,
                     (LPCVOID ) (baseaddr + imgDosHdr.e_lfanew), &imgNtHdr,
                     sizeof (IMAGE_NT_HEADERS), &bR);
  if (bR != sizeof (IMAGE_NT_HEADERS))
    {
      printf (" [INFO] could not read IMAGE_NT_HEADERS (read %x bytes)\n",bR);
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
