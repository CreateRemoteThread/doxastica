elegurawolfe
============

elegurawolfe is a generic api hooking framework, designed to make interacting
with game processes easier. it contains two primary components:

- a dll loader, which allows us to inject any dll into another process' memory
space
- "shackle.dll", which acts like a mini-debugger which you can use almost like
windbg inside memory. this opens up an ipc server at \\.\pipe\shackle-%d, where
%d is the host process id. this server accepts ipc connections, and treats input
as lua to be interpreted by an embedded lua 5p3 engine
- "peek", which acts as an ipc client (to communicate with the shackle library)

this project does not use any debug functionality - shackle runs as it's own
collection of threads within the host process.

## example: pwn adventure 3

pwn adventure 3 (http://pwnadventure.com/) is a part of ghost in the shellcode
2015, and consists of an mmorpg style game. for our adventure, we will be looking
at the windows version of the game, and modifying the player's running speed!

PWNADVENTURES\PwnAdventure3_Data\PwnAdventure3\PwnAdventure3\Binaries\Win32\PwnAdventure3-Win32-Shipping.exe
(md5sum 51b53981e188d4e54f6e69079f924a08)

## dragons below etc

### building

```
build shackle32
build shackle64
build ldr32
build ldr64
build peek
````

### injecting into stuff

to inject "shackle64.dll" into calc.exe on a 64-bit system: `ldr64 -fastinject calc.exe -dll shackle64.dll`

to inject "shackle32.dll" into a new 32-bit test.exe: `ldr32 -inject test.exe -dll shackle32.dll`

same as above, but hold the process in a EB FE loop first: `ldr32 -inject test.exe -dll shackle32.dll -wait`

ldr can inject anything, but it's up to you to make sure the dll you're injecting is the correct architecture.
shackle comes with a pre-built 'hook' function based off beaengine - debug via OutputDebugString.

this is super WIP, doesn't yet validate architecture - shit will break if you inject a 64-bit process into a 32-bit process

glhf lol


## credits

this code borrows heavily from other sources. these are listed below:

- https://github.com/DarthTon/Blackbone
- http://www.lua.org/pil/24.html
- https://gist.github.com/randrews/939029
- http://pastebin.com/HbWNAV99
- beatrix2004.free.fr