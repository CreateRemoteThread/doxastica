doxastica
=========

doxastica is a generic api hooking framework, designed to make interacting
with game processes easier. it contains two primary components:

- a dll loader, which allows us to inject any dll into another process' memory
space
- "shackle.dll", which is a lua interpreter to be injected into a target
process. upon loading, this dll opens up an ipc server, which you can talk to
with the "peek" client.
- "peek", basically an ipc telnet

this project does not use any debug functionality - shackle runs as it's own
collection of threads within the host process.

## quickstart: hacking unreal tournament 99

the goal of our quickstart tutorial will be the hack the unral tournament goty
edition from steam (http://store.steampowered.com/app/13240/). we will try to
edit the game's memory so that a player can have 200 health.

firstly, start the game, and then run the following command:

    ldr32 -fastinject UnrealTournament.exe -dll shackle32.dll

this should provide an output like the following:

![ldr32 command output](/README_FILES/Untitled.png)

then, within the game, start a match. lose at least one hitpoint and pause. 
now, back to our desktop. notice the end of the "ldr32" command output, see 
how it specifies a command to use to connect to the game process?

use this command to connect to the ipc server, and create a new search object
via the following:

    > a = search_new(SEARCH_DWORD, 93)

where 93 is the value of the current player's health. this should return a large
number of results, we need to filter the possible results. return to the game,
and play until your health changes, and pause again. now, use the following
command to check which of the previously identified values have the new value:

    > search_filter(a,87)

this should return <5 results. repeat this process until you have one result.
copy this result down.

now, use the "ed" command to edit the DWORD at this location to a higher value,
and check our work with "hexdump":

![patching player hp](/README_FILES/hexdump_stage2.png)

return to our game, your health should be much higher :)

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
- https://github.com/x64dbg/XEDParse/
