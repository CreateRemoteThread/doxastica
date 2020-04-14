loadlibrary("c:/projects/doxastica/pwnadventure3.dll")
oldsend = resolve("ws2_32.dll!send")
oldrecv = resolve("ws2_32.dll!recv")

newsend = resolve("pwnadventure3.dll!newSend")
newrecv = resolve("pwnadventure3.dll!newRecv")

pa3_cb = resolve("pwnadventure3.dll!callback")

hook(oldsend,newsend,pa3_cb)
hook(oldrecv,newrecv,pa3_cb)
print("ok, we're good!\n")