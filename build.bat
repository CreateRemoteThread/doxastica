@echo off

IF NOT EXIST xed32 MKDIR xed32
IF NOT EXIST xed64 MKDIR xed64
IF NOT EXIST lua32 MKDIR lua32
IF NOT EXIST lua64 MKDIR lua64

cd src

IF [%1]==[prereqs64] call build.bat bea64
IF [%1]==[prereqs64] call build.bat xed64
IF [%1]==[prereqs64] call build.bat lua64

IF [%1]==[prereqs32] call build.bat bea32
IF [%1]==[prereqs32] call build.bat xed32
IF [%1]==[prereqs32] call build.bat lua32

IF [%1]==[bins32] call build.bat shackle32
IF [%1]==[bins32] call build.bat ldr32
IF [%1]==[bins32] call build.bat peek

IF [%1]==[bins64] call build.bat shackle64
IF [%1]==[bins64] call build.bat ldr64
IF [%1]==[bins64] call build.bat peek

IF [%1]==[ldr64] cl /I modules /D ARCHI_64 /Zi /c /Fomodules/ldr64.obj /Tp ldr.c
IF [%1]==[ldr64] link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:ldr64.exe ldr64.obj user32.lib

IF [%1]==[ldr32] cl /I modules /Zi /c /Fomodules/ldr32.obj /Tp ldr.c
IF [%1]==[ldr32] link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:ldr32.exe ldr32.obj user32.lib

IF [%1]==[shackle64] cl /I modules /D ARCHI_64 /Zi /c /I lua53 /EHsc /Fomodules/ptrscan64.obj /Tp modules/ptrscan.c
IF [%1]==[shackle64] cl /I modules /Zi /c /I lua53 /EHsc /Fomodules/lua_socket64.obj /Tp modules/lua_socket.c
IF [%1]==[shackle64] cl /I modules /D ARCHI_64 /Zi /c /EHsc /I lua53 /Fomodules/search64.obj /Tp modules/search.c
IF [%1]==[shackle64] cl /I modules /D ARCHI_64 /Zi /c /EHsc /I lua53 /Fomodules/vtable64.obj /Tp modules/vtable.c
IF [%1]==[shackle64] cl /I modules /D ARCHI_64 /Zi /c /I beainclude /EHsc /I lua53 /Fomodules/pcontrol64.obj /Tp modules/pcontrol.c
IF [%1]==[shackle64] cl /I modules /D ARCHI_64 /D WIN_X64 /Zi /c /I beainclude /EHsc /I lua53 /Fomodules/magicmirror64.obj /Tp modules/magicmirror.c
IF [%1]==[shackle64] cl /I modules /D ARCHI_64 /Zi /c /I lua53 /I beainclude /EHsc /Fomodules/shackle64.obj /Tp shackle.c
IF [%1]==[shackle64] link /DEF:shackle.def /DLL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:shackle64.dll modules/shackle64.obj modules/lua_socket64.obj modules/vtable64.obj modules/ptrscan64.obj beasrc/BeaEngine64.obj lua64/*.obj user32.lib psapi.lib xed64/*.obj modules/search64.obj modules/pcontrol64.obj xedparse/xed2/lib/libxed_x64.lib imagehlp.lib ws2_32.lib modules/magicmirror64.obj

IF [%1]==[shackle32] cl /I modules /Zi /c /I lua53 /EHsc /Fomodules/ptrscan32.obj /Tp modules/ptrscan.c
IF [%1]==[shackle32] cl /I modules /Zi /c /I lua53 /EHsc /Fomodules/lua_socket32.obj /Tp modules/lua_socket.c
IF [%1]==[shackle32] cl /I modules /Zi /c /EHsc /I lua53 /Fomodules/search32.obj /Tp modules/search.c
IF [%1]==[shackle32] cl /I modules /Zi /c /EHsc /I lua53 /Fomodules/vtable32.obj /Tp modules/vtable.c
IF [%1]==[shackle32] cl /I modules /Zi /c /I beainclude /EHsc /I lua53 /Fomodules/pcontrol32.obj /Tp modules/pcontrol.c
IF [%1]==[shackle32] cl /I modules /D WIN_X86 /Zi /c /I beainclude /EHsc /I lua53 /Fomodules/magicmirror32.obj /Tp modules/magicmirror.c
IF [%1]==[shackle32] cl /I modules /Zi /c /I lua53 /I beainclude /EHsc /Fomodules/shackle32.obj /Tp shackle.c
IF [%1]==[shackle32] link /DEF:shackle.def /DLL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:shackle32.dll modules/shackle32.obj modules/lua_socket32.obj modules/vtable32.obj modules/ptrscan32.obj beasrc/BeaEngine32.obj lua32/*.obj user32.lib psapi.lib xed32/*.obj modules/search32.obj modules/pcontrol32.obj xedparse/xed2/lib/libxed_x86.lib imagehlp.lib advapi32.lib ws2_32.lib modules/magicmirror32.obj

IF [%1]==[bea32] cd beasrc
IF [%1]==[bea32] cl /I modules /Zi /c /I ../beainclude /Fomodules/BeaEngine32.obj /Tp BeaEngine.c
IF [%1]==[bea32] cd ..

IF [%1]==[lua32] cd lua53 
IF [%1]==[lua32] cl /I modules /D LUA_COMPAT_5_2 /D LUA_BUILD_AS_DLL /c /EHsc /Tp *.c
IF [%1]==[lua32] del lua.obj
IF [%1]==[lua32] del luac.obj
IF [%1]==[lua32] cd ..
IF [%1]==[lua32] move lua53\*.obj lua32\

IF [%1]==[lua64] cd lua53 
IF [%1]==[lua64] cl /I modules /D LUA_COMPAT_5_2 /D LUA_BUILD_AS_DLL /c /EHsc /Tp *.c
IF [%1]==[lua64] del lua.obj
IF [%1]==[lua64] del luac.obj
IF [%1]==[lua64] cd ..
IF [%1]==[lua64] move lua53\*.obj lua64\

IF [%1]==[bea64] cd beasrc
IF [%1]==[bea64] cl /I modules /Zi /c /I ../beainclude /Fomodules/BeaEngine64.obj /Tp BeaEngine.c
IF [%1]==[bea64] cd ..

IF [%1]==[test64] cl /I modules /Zi /c /Tp modules/test64.c
IF [%1]==[test64] link /out:test64.exe test64.obj user32.lib

IF [%1]==[test32] cl /I modules /Zi /c /Tp modules/test64.c
IF [%1]==[test32] link /out:test32.exe test64.obj user32.lib

IF [%1]==[test64] cl /I modules /Zi /c /Tp modules/test64.c
IF [%1]==[test64] link /out:test64.exe test64.obj user32.lib

IF [%1]==[xed32] del /Q xed32\*.*
IF [%1]==[xed32] cd xedparse\src
IF [%1]==[xed32] cl /I modules /D XEDPARSE_STATIC /Zi /c /Tp *.cpp
IF [%1]==[xed32] cd ..
IF [%1]==[xed32] cd ..
IF [%1]==[xed32] move xedparse\src\*.obj xed32\

IF [%1]==[xed64] del /Q xed64\*.*
IF [%1]==[xed64] cd xedparse\src
IF [%1]==[xed64] cl /I modules /D XEDPARSE_STATIC /Zi /c /Tp *.cpp
IF [%1]==[xed64] cd ..
IF [%1]==[xed64] cd ..
IF [%1]==[xed64] move xedparse\src\*.obj xed64\

IF [%1]==[peek] cl /I modules /Zi /c /Tp modules/peek.c
IF [%1]==[peek] link /out:peek.exe peek.obj

IF [%1] EQU [] ECHO build {target}. Valid targets are:
IF [%1] EQU [] ECHO ++ bea{32,64} [PREREQ: BEA Disassembly]
IF [%1] EQU [] ECHO ++ lua{32,64} [PREREQ: LUA Scripting]
IF [%1] EQU [] ECHO ++ xed{32,64} [PREREQ: XED Assembler]
IF [%1] EQU [] ECHO ++ shackle{32,64}
IF [%1] EQU [] ECHO ++ ldr{32,64}
IF [%1] EQU [] ECHO ++ peek
IF [%1] EQU [] ECHO if you get something about x86 vs x64, ensure you've recompiled bea/lua for your target architecture.