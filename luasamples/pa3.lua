loadlibrary("c:/projects/doxastica/pwnadventure3.dll")
oldsend = resolve("ws2_32.dll!send")
oldrecv = resolve("ws2_32.dll!recv")

newsend = resolve("pwnadventure3.dll!newSend")
newrecv = resolve("pwnadventure3.dll!newRecv")

pa3_cb = resolve("pwnadventure3.dll!callback")

hook(oldsend,newsend,pa3_cb)
hook(oldrecv,newrecv,pa3_cb)

ps_ptr = resolve("pwnadventure3.dll!proxySend")
--[[
packet_fireball =  "\x2a\x69\x10\x00\x47\x72\x65\x61\x74\x42\x61\x6c\x6c\x73\x4f\x66\x46\x69\x72\x65\x70\xa2\x07\xc2\x62\x03\x82\x41\x00\x00\x00\x00\x6d\x76\xd2\xcd\x4f\xc7\x3c\x61\x23\xc7\x08\x06\x09\x44\xe3\xe7\x8e\x0b\x00\x00\x00\x00"
packet_jump = "\x6a\x70\x01\x6d\x76\x6f\xb9\x25\xc7\x87\x4e\x05\xc7\x21\x9d\x99\x44\xf0\xfcx02\x5f\x00\x00\x7f\x00"

packet_gunshop = "\x65\x65\x07\x00\x00\x00\x6d\x76\xb8\x0d\x13\xc7\xed\x6f\x8d\xc6\x66\x22\x1d\x45\xaf\xf4\x35\x0c\x00\x00\x00\x00"

packet_buy = "\x24\x62\x07\x00\x00\x00\x06\x00\x50\x69\x73\x74\x6f\x6c\x01\x00\x00\x00\x6d\x76\xd8\xc3\x11\xc7\xbf\x2f\x8d\xc6\x66\x22\x1d\x45\x28\xfb\x16\x7d\x00\x00\x00\x00\x09\x00\x47\x31\x37\x50\x69\x73\x74\x6f\x6c"
]]

clientworld_tick = resolve("GameLogic.dll") + 0xCAE0
saveaddr_fn = resolve("pwnadventure3.dll!getSaveAddr")
iclientworld_ptr = call(saveaddr_fn)
print("pointer to iclientworld buffer: ")
print(iclientworld_ptr)
print("\n");

catchthis(clientworld_tick,iclientworld_ptr)

print("ok, setting up functions...\n")

function patch_walk_speed()
iclientworld = deref(iclientworld_ptr)
iplayer = deref(iclientworld + 0x2c)
player_base = iplayer - 0x70 -- from windbg dt GameLogic!Player
ed(player_base + 0x190,0xFFFF0000)
-- ed(player_base + 0x194,0x8FFF0000) 
end

ll_ptr = resolve("pwnadventure3.dll!lockLocation")
function lockz(i)
call(ll_ptr,i)
end

-- teleport(toVector3(260255.0,-249336.0,1476.0)) will teleport you to cow island.
tp_ptr = resolve("GameLogic.dll") + 0x1C80 -- Actor::SetLocation
function teleport(v3loc)
iclientworld = deref(iclientworld_ptr)
iplayer = deref(iclientworld + 0x2c)
thiscall(tp_ptr,iplayer - 0x70,v3loc)
end
