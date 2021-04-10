#include <stdio.h>
#include <windows.h>

typedef DWORD (WINAPI * _MessageBoxA) (DWORD, LPCVOID, LPCVOID, DWORD);

_MessageBoxA oldMsgBox = NULL;

void __stdcall callback(ULONG_PTR addr)
{
	if(oldMsgBox == NULL)
	{
		OutputDebugString("Filling oldSend\n");
		oldMsgBox = (_MessageBoxA )addr;
	}
	return;
}

DWORD WINAPI NewMsgBox(DWORD hinst, LPCVOID title, LPCVOID msg, DWORD opts)
{
  oldMsgBox(0,"HOOKED MSGBOX SUCCESS","HOOKED MSGBOX SUCCESS",MB_OK);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
	if(fdwReason == DLL_PROCESS_ATTACH)
    {	
		return TRUE;
	}
}
