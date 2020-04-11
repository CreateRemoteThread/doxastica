Quickstart Tutorials
====================

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

save to disk
------------

sometimes, you want to wait for something to unpack in memory and then save it
to disk. currently, you can do this with lua's file api:

    file = io.open("out.bin","w")
    data = memread(0x00401000,0x101010)
    io.output(file)
    io.write(data)
    io.close(file)