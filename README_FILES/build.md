doxastica - build guide
=======================

doxastica is written in C/C++: it's built for compilation by CL.exe and LINK.exe
from the windows platform SDK. to build doxastica, use the provided "build.bat".

invoke this as follows:

- build clean:
  clean up all binaries
- build prereqs32 / build prereqs64
  build xed, lua5.3 and beaengine in 32 or 64 bit
- build bins32 / build bins64 (requires prereqs32/prereqs64)
  build shackle32/shackle64.dll, peek.exe and ldr32/ldr64.exe
- bincommit
  copy all executable files to binz/

additionally, you can build individual modules, as thus:

- build xed32/xed64
- build bea32/bea64
- build lua32/lua64
- build shackle32/shackle64
- build peek
- build ldr32/ldr64