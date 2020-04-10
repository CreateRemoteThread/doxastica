@echo off

IF "%1"=="1" ldr -dll shackle32.dll -exe testcase1.exe -wdir c:\projects\elegurawolfe

IF "%1"=="2" ldr -dll shackle32.dll -exe testcase2.exe -wdir c:\projects\elegurawolfe

IF "%1"=="3" ldr -dll shackle32.dll -exe testcase3.exe -wdir c:\projects\elegurawolfe

IF "%1"=="1w" ldr -dll shackle32.dll -exe testcase1.exe -wdir c:\projects\elegurawolfe -wait