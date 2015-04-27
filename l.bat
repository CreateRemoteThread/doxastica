@echo off


IF "%1"=="ldr" link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:ldr.exe ldr.obj libdis/*.obj dbghelp.lib user32.lib

IF "%1"=="dll" link /DLL /OPT:REF /OPT:ICF /EXPORT:newSend /EXPORT:newRecv /EXPORT:newMessageBox /INCREMENTAL:NO /DEBUG /out:shackle.dll shackle.obj libdis/*.obj dbghelp.lib user32.lib

IF "%1"=="dllempty" link /DLL /OPT:REF /OPT:ICF /EXPORT:newSend /EXPORT:newRecv /INCREMENTAL:NO /DEBUG /out:shackle.dll shackle_empty.obj libdis/*.obj dbghelp.lib user32.lib

IF "%1"=="test3" link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:test3.exe test3.obj user32.lib
