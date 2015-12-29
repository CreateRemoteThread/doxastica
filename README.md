elegurawolfe
============

elegurawolfe is a generic api hooking framework, designed to work with
a minimum of effort on the programmer's part.

this is a port of old code, there's probably a lot of bugs here. use
at your own risk

## usage

### building

```
build shackle32
build shackle64
build ldr32
build ldr64
build bea32
build bea64
````

### injecting into stuff

to inject "shackle64.dll" into calc.exe on a 64-bit system: `ldr64 -fastinject calc.exe -dll shackle64.dll`
to inject "shackle32.dll" into a new 32-bit test.exe: `ldr32 -inject test.exe -dll shackle32.dll`
same as above, but hold the process in a EB FE loop first: `ldr32 -inject test.exe -dll shackle32.dll -wait`

ldr can inject anything, but it's up to you to make sure the dll you're injecting is the correct architecture.
shackle comes with a pre-built 'hook' function based off beaengine - debug via OutputDebugString.

this is super WIP, doesn't yet validate architecture - shit will break if you inject a 64-bit process into a 32-bit process

glhf lol
