

* [Introduction](#intro)
* [Quickstart Tutorials](#quickstart)
  * [tutorial: ut99](#ut99)
  * [tutorial: save to disk](#save)
* [Lua Engine](#luaengine)
  * [lua default variables](#luavars)
  * [lua commands listing](docs/luaref.md)
* [Development](docs/build.md)
* [Credits](#credits)

Introduction <a name="intro"></a>
============

doxastica is an injectable lua interpreter, designed to make interacting
with game processes easier. it contains two^H^H^Hthree primary components:

- "ldr32"/"ldr64", a dll loader, which allows us to inject any dll into 
another process' memory space
- "shackle.dll", which is a lua interpreter to be injected into a target
process. upon loading, this dll opens up an ipc server, which you can talk to
with the "peek" client.
- "peek", basically an ipc telnet. invoke it with a pid as argument - a
full command-line will be supplied by ldr32/ldr64 on a successful inject

this project does not use any debug functionality - shackle runs as it's
own collection of threads within the host process.

[+] installs it's own veh handler to catch guard page exceptions

## what's the difference between this and cheatengine/tsearch

- this doesn't rely on debugger functionality at all, so anti-debug checks 
have nothing to catch: this means a lower chance for you to get banned.

- it's hard for games to ban you on the grounds of a loaded dll. lots of things
load dlls (but things like battleeye will pick this up - but this is a policy
thing).

- compared to a debugger, you're inside a process' memory. this means you are
fast as shit for certain operations (but crippled in others).

Quickstart Tutorials <a name="quickstart"></a>
====================

ut99 <a name="ut99"></a>
----

the goal of our quickstart tutorial will be the hack the unral tournament goty
edition from steam (http://store.steampowered.com/app/13240/). we will try to
edit the game's memory so that a player can have 200 health.

firstly, start the game, and then run the following command:

    ldr32 -fastinject UnrealTournament.exe -dll shackle32.dll

this should provide an output like the following:

![ldr32 command output](/docs/Untitled.png)

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

![patching player hp](/docs/hexdump_stage2.png)

return to our game, your health should be much higher (this should be 500 but
i'm not too great at this game so it's less):

![increased hp in unreal tournament](/docs/ingame_morehp.png)

this isn't enough. let's bind an unused hotkey so we can go to 500 health every
time we hit a key.

![bind hotkey](/docs/new_hotkey.png)

now, by pressing "p" for half a second, your health will be restored to 500 :)

save to disk <a name="save"></a>
------------

sometimes, you want to wait for something to unpack in memory and then save it
to disk. currently, you can do this with lua's file api:

    file = io.open("out.bin","w")
    data = memread(0x00401000,0x101010)
    io.output(file)
    io.write(data)
    io.close(file)

Lua Engine <a name="luaengine"></a>
==========

lua default variables <a name="luavars"></a>
---------------------

upon starting a lua instance, several default variables are initialized. these
are:

- window memory protection constances: PAGE_* are defined as integers corresponding
  to their values as defined in msdn

- SEARCH_DWORD, SEARCH_WORD, SEARCH_BYTE for specifying types of value searches

- module start and size. let's say you've loaded "ati_d3d11.dll", the following
  values will be automatically defined:

  - ati_d3d11_dll.start
  - ati_d3d11_dll.size

lua commands listing
--------------------

[Click here for a reference of lua commands supported by doxastica](docs/luaref.md)

Credits <a name="credits"></a>
=======

this code borrows heavily from other sources. these are listed below:

- https://github.com/DarthTon/Blackbone
- http://www.lua.org/pil/24.html
- https://gist.github.com/randrews/939029
- http://pastebin.com/HbWNAV99
- beatrix2004.free.fr
- https://github.com/x64dbg/XEDParse/
- https://github.com/stephenfewer/ReflectiveDLLInjection