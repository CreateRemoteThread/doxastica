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

### the "short cave" hack

i've tried to make patching clean with a disassembler engine:

```
address_from = user32!MessageBoxA
address_to = shackle64!newMessageBoxA

code_cave = malloc(some bytes)
copy(code_cave,address_from[0:14]) // prologue
write(address_from[0:14],"JMP [RIP+0]; DQ ADDRESS_TO") // patch
write(code_cave[14:],"JMP [RIP+0]; DQ ADDRESS_FROM + TOTALSIZE")
```

but we encounter a problem when we run into instructions which accept a dword-length relative offset that exists within the prologue; for example:

`cmp [32-bits],r11d`

i don't think we can patch this: the 32-bits parameter relies on the code executing in the right place, and it's too far from our new location to adjust the offset. HOWEVER, this is unlikely to happen within the first 5 bytes of an instruction (typically, this will still be the stack prologue)

to counter this, we do two things:

- try to patch to a short cave within the dll, that's after a "ret" instruction.
