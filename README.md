doxastica
=========

doxastica is an injectable lua interpreter, designed to make interacting
with game processes easier. it contains two^H^H^Hthree primary components:

- "ldr32"/"ldr64", a dll loader, which allows us to inject any dll into 
another process' memory space
- "shackle.dll", which is a lua interpreter to be injected into a target
process. upon loading, this dll opens up an ipc server, which you can talk to
with the "peek" client.
- "peek", basically an ipc telnet. invoke it with 

this project does not use any debug functionality - shackle runs as it's own
collection of threads within the host process.

## what's the difference between this and cheatengine/tsearch

- this doesn't rely on debugger functionality at all, so anti-debug checks 
have nothing to catch: this means a lower chance for you to get banned.

- it's hard for games to ban you on the grounds of a loaded dll. lots of things
load dlls (but things like battleeye will pick this up - but this is a policy
thing).

- compared to a debugger, you're inside a process' memory. this means you are
fast as shit for certain operations (but crippled in others).

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

return to our game, your health should be much higher (this should be 500 but
i'm not too great at this game so it's less):

![increased hp in unreal tournament](/README_FILES/ingame_morehp.png)

this isn't enough. let's bind an unused hotkey so we can build our health with
our 

![bind hotkey](/README_FILES/new_hotkey.png)

now, by pressing "p" for half a second, your health will be restored to 500 :)

## lua commands listing

the following additional lua functions are supported as part of doxastica. many
of these were inspired by functionality in cheat engine:

- void hexdump(address,{size}):
  generates a number of 

- void memcpy(addrto,addrfrom,{size}):
  like c, writes a block of memory at addrto, from addrfrom. if addrfrom is an
  address, this requires the "size" parameter. if it's a string (i.e. a lua binary
  string", size is ignored).

- void memset(addrto,char,size):
  fills a block of memory with a given byte value, like it's c equivalent

- int malloc(size):
  allocates a new block of memory. returns an integer pointing to the newly
  allocated memory buffer

- int mprotect(addr,size,mprotect_const):
  proxies a call to VirtualProtect, setting the address of one or more memory
  pages. mprotect_const uses the windows memory protection constants. returns
  the old memory protection value

- string memread(addr,size):
  reads a block of memory, returns it as a string

- void disasm(addr,lines) / disassemble(addr,lines):
  prints out a disassembly starting at eip, going for lines number of instructions

### assembler

doxastica uses the xedparse assembler library to provide both 32-bit and 64-bit
assembly. note that this is a SINGLE-LINE assembler, so does not support features
such as labels. sorry =(

- asmobject asm_new(address,architecture):
  creates a new asembly buffer object, starting at "address". architecture, which
  must be either 32 or 64, specifies whether we're assembling for x32 or x64. this
  returns an "asm object", which can be used in further assembler-related calls.

- void asm_add(asmobject,"ASSEMBLY"):
  adds a single line of assembly to an asm object. note that this is NOT compiled
  yet.

- void asm_commit(asmobject):
  commits changes to memory: assembles instructions in an asm buffer and writes
  them to the process.

- void asm_free(asmobject):
  frees an asm object. future attempts to use the freed asm object should fail
  a validation check.

### memory search

- searchobj search_new(search_type,value,start,end):
  attempts to search a memory type

- int search_filter(searchobj,newvalue):
  attempts to filter a previously identified list of values to a newvalue. note
  that this cannot change the TYPE of search: that is, if the search was created
  looking for dwords, this will only look for dwords.

- int search_fetch(searchobj,index):
  this returns the n'th search result (as specified by "index") in a given search
  object, such that 

- void search_free(searchobj):
  frees a search object. future attempts to use the freed search object should
  fail a validation check.

### fast edit

- void e{b/w/d}(address, {byte/word/dword}):
  writes a single byte/word/dword to the given address

- void d{b/w/d}(address):
  display a single {byte/word/dword} at the given address

## credits

this code borrows heavily from other sources. these are listed below:

- https://github.com/DarthTon/Blackbone
- http://www.lua.org/pil/24.html
- https://gist.github.com/randrews/939029
- http://pastebin.com/HbWNAV99
- beatrix2004.free.fr
- https://github.com/x64dbg/XEDParse/
