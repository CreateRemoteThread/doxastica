@echo off

IF [%1]==[ipcserver] cl /Tp ipcserver.c

IF [%1]==[dx11] cl /c /Tp dx11zbuf.c
IF [%1]==[dx11] link /dll /out:dx11zbuf.dll dx11zbuf.obj

IF [%1]==[dx11] cl /c /Tp certexporter.c
IF [%1]==[dx11] link /dll /out:certexporter.dll certexporter.obj
