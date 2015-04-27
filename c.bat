@echo off

IF %1==test C:\masm32\bin\bldall.bat c:\projects\elegurawolfe\test
IF %1==test exit

cl /O2 /Zi /c /TP %1
