@echo off

del *.obj

IF [%1]==[64] cl /D ARCHI_64 /O2 /Zi /c /I beainclude /Foshackle64.obj /Tp shackle.c
IF [%1]==[64] link /DLL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:shackle64.dll shackle64.obj beasrc/BeaEngine64.obj

IF [%1]==[32] cl /O2 /Zi /c /I beainclude /Foshackle32.obj /Tp shackle.c
IF [%1]==[32] link /DLL /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:shackle32.dll shackle32.obj beasrc/BeaEngine32.obj

IF [%1]==[bea32] cd beasrc
IF [%1]==[bea32] cl /O2 /Zi /c /I ../beainclude /FoBeaEngine32.obj /Tp BeaEngine.c
IF [%1]==[bea32] cd ..

IF [%1]==[bea64] cd beasrc
IF [%1]==[bea64] cl /O2 /Zi /c /I ../beainclude /FoBeaEngine64.obj /Tp BeaEngine.c
IF [%1]==[bea64] cd ..

IF [%1] EQU [] ECHO build {target}. Valid targets are "64", "32", "bea32" and "bea64"
IF [%1] EQU [] ECHO if you get something about x86 vs x64, ensure you've recompiled bea for your target architecture.