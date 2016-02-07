@echo off

del /q binz/*.*

copy ldr32.exe binz
copy ldr64.exe binz
copy shackle32.dll binz
copy shackle64.dll binz
copy peek.exe binz
