@echo off

del *.obj
del lua53\*.obj

IF [%1]==[ldr64] cl /D ARCHI_64 /O2 /Zi /c /Foldr64.obj /Tp ldr.c
IF [%1]==[ldr64] link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:ldr64.exe ldr64.obj

IF [%1]==[ldr32] cl /O2 /Zi /c /Foldr32.obj /Tp ldr.c
IF [%1]==[ldr32] link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:ldr32.exe ldr32.obj

REM IF [%1]==[shackle64] cd lua53
REM IF [%1]==[shackle64] cl /D ARCHI_64 /O2 /Zi /c /Tp *.c
REM IF [%1]==[shackle64] cd ..
IF [%1]==[shackle64] cl /D ARCHI_64 /O2 /Zi /c /I beainclude /Foshackle64.obj /Tp shackle.c
IF [%1]==[shackle64] link /DLL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:shackle64.dll shackle64.obj beasrc/BeaEngine64.obj

REM IF [%1]==[shackle32] cd lua53
REM IF [%1]==[shackle32] cl /D ARCHI_64 /O2 /Zi /c /Tp *.c
REM IF [%1]==[shackle32] cd ..
IF [%1]==[shackle32] cl /O2 /Zi /c /I beainclude /Foshackle32.obj /Tp shackle.c
IF [%1]==[shackle32] link /DLL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:shackle32.dll shackle32.obj beasrc/BeaEngine32.obj

IF [%1]==[bea32] cd beasrc
IF [%1]==[bea32] cl /O2 /Zi /c /I ../beainclude /FoBeaEngine32.obj /Tp BeaEngine.c
IF [%1]==[bea32] cd ..

IF [%1]==[bea64] cd beasrc
IF [%1]==[bea64] cl /O2 /Zi /c /I ../beainclude /FoBeaEngine64.obj /Tp BeaEngine.c
IF [%1]==[bea64] cd ..

IF [%1]==[test64] cl /O2 /Zi /c /Tp test64.c
IF [%1]==[test64] link /out:test64.exe test64.obj user32.lib

IF [%1]==[test32] cl /O2 /Zi /c /Tp test64.c
IF [%1]==[test32] link /out:test32.exe test64.obj user32.lib

IF [%1]==[peek] cl /O2 /Zi /c /Tp peek.c
IF [%1]==[peek] link /out:peek.exe peek.obj

IF [%1] EQU [] ECHO build {target}. Valid targets are:
IF [%1] EQU [] ECHO ++ bea32
IF [%1] EQU [] ECHO ++ bea64
IF [%1] EQU [] ECHO ++ shackle32
IF [%1] EQU [] ECHO ++ shackle64
IF [%1] EQU [] ECHO ++ ldr32
IF [%1] EQU [] ECHO ++ ldr64
IF [%1] EQU [] ECHO if you get something about x86 vs x64, ensure you've recompiled bea for your target architecture.