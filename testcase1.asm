COMMENT '
	sexeh demo
'
	
	.586p
	.model flat,stdcall
	option casemap:none

	include c:/masm32/include/kernel32.inc
	include c:/masm32/include/user32.inc
	include c:/masm32/include/windows.inc	
	includelib c:/masm32/lib/kernel32.lib
	includelib c:/masm32/lib/user32.lib	

	;; BEGIN--
	;; DO c:\masm32\bin\bldall.bat %namePrefix
	;; END--

	.data

	wut db "wut",0
	wutt db "WRONG",0
	; sz_nightshade db "c:\\projects\\games\\nightshade_dll\\Debug\\nightshade.dll",0
	
	.code

_start:

	invoke MessageBoxA,0,ADDR wut,ADDR wutt,MB_OK
	invoke MessageBoxA,0,ADDR wut,ADDR wutt,MB_OK

	invoke ExitProcess,0
	
end _start