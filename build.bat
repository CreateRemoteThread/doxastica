@echo off

del *.obj
del lua53\*.obj

IF [%1]==[ldr64] cl /D ARCHI_64 /O2 /Zi /c /Foldr64.obj /Tp ldr.c
IF [%1]==[ldr64] link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:ldr64.exe ldr64.obj

IF [%1]==[ldr32] cl /O2 /Zi /c /Foldr32.obj /Tp ldr.c
IF [%1]==[ldr32] link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:ldr32.exe ldr32.obj

REM IF [%1]==[shackle64] cl /O2 /Zi /c /EHsc /Fovehdebug64.obj /Tp vehdebug.c
IF [%1]==[shackle64] cl /O2 /Zi /c /EHsc /Fosearch64.obj /Tp search.c
IF [%1]==[shackle64] cl /D ARCHI_64 /O2 /Zi /c /I lua53 /I beainclude /EHsc /Foshackle64.obj /Tp shackle.c
IF [%1]==[shackle64] link /DLL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:shackle64.dll shackle64.obj beasrc/BeaEngine64.obj lua64/*.obj user32.lib psapi.lib xed64/*.obj search64.obj xedparse/xed2/lib/libxed_x64.lib imagehlp.lib

REM IF [%1]==[shackle32] cl /O2 /Zi /c /EHsc /Fovehdebug32.obj /Tp vehdebug.c
IF [%1]==[shackle32] cl /O2 /Zi /c /EHsc /Fosearch32.obj /Tp search.c
IF [%1]==[shackle32] cl /O2 /Zi /c /I lua53 /I beainclude /EHsc /Foshackle32.obj /Tp shackle.c
IF [%1]==[shackle32] link /DLL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:shackle32.dll shackle32.obj beasrc/BeaEngine32.obj lua32/*.obj user32.lib psapi.lib xed32/*.obj search32.obj xedparse/xed2/lib/libxed_x86.lib imagehlp.lib

IF [%1]==[bea32] cd beasrc
IF [%1]==[bea32] cl /O2 /Zi /c /I ../beainclude /FoBeaEngine32.obj /Tp BeaEngine.c
IF [%1]==[bea32] cd ..

IF [%1]==[lua32] cd lua53 
IF [%1]==[lua32] cl /D LUA_COMPAT_5_2 /D LUA_BUILD_AS_DLL /O2 /c /EHsc /TP *.c
IF [%1]==[lua32] del lua.obj
IF [%1]==[lua32] del luac.obj
IF [%1]==[lua32] cd ..
IF [%1]==[lua32] move lua53\*.obj lua32\

IF [%1]==[lua64] cd lua53 
IF [%1]==[lua64] cl /D LUA_COMPAT_5_2 /D LUA_BUILD_AS_DLL /O2 /c /EHsc /TP *.c
IF [%1]==[lua64] del lua.obj
IF [%1]==[lua64] del luac.obj
IF [%1]==[lua64] cd ..
IF [%1]==[lua64] move lua53\*.obj lua64\

IF [%1]==[bea64] cd beasrc
IF [%1]==[bea64] cl /O2 /Zi /c /I ../beainclude /FoBeaEngine64.obj /Tp BeaEngine.c
IF [%1]==[bea64] cd ..

IF [%1]==[test64] cl /O2 /Zi /c /Tp test64.c
IF [%1]==[test64] link /out:test64.exe test64.obj user32.lib

IF [%1]==[test32] cl /O2 /Zi /c /Tp test64.c
IF [%1]==[test32] link /out:test32.exe test64.obj user32.lib

IF [%1]==[test64] cl /O2 /Zi /c /Tp test64.c
IF [%1]==[test64] link /out:test64.exe test64.obj user32.lib

IF [%1]==[xed32] del xed32\*.*
IF [%1]==[xed32] cd xedparse\src
IF [%1]==[xed32] cl /D XEDPARSE_STATIC /O2 /Zi /c /Tp *.cpp
IF [%1]==[xed32] cd ..
IF [%1]==[xed32] cd ..
IF [%1]==[xed32] move xedparse\src\*.obj xed32\

IF [%1]==[xed64] del xed64\*.*
IF [%1]==[xed64] cd xedparse\src
IF [%1]==[xed64] cl /D XEDPARSE_STATIC /O2 /Zi /c /Tp *.cpp
IF [%1]==[xed64] cd ..
IF [%1]==[xed64] cd ..
IF [%1]==[xed64] move xedparse\src\*.obj xed64\

IF [%1]==[peek] cl /O2 /Zi /c /Tp peek.c
IF [%1]==[peek] link /out:peek.exe peek.obj

IF [%1] EQU [] ECHO build {target}. Valid targets are:
IF [%1] EQU [] ECHO ++ bea32
IF [%1] EQU [] ECHO ++ bea64
IF [%1] EQU [] ECHO ++ shackle32
IF [%1] EQU [] ECHO ++ shackle64
IF [%1] EQU [] ECHO ++ ldr32
IF [%1] EQU [] ECHO ++ ldr64
IF [%1] EQU [] ECHO ++ peek
IF [%1] EQU [] ECHO if you get something about x86 vs x64, ensure you've recompiled bea for your target architecture.