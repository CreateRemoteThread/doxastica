loadlibrary("c:/projects/doxastica/pwnadventure3.dll")
func_ptr = resolve("pwnadventure3.dll!test2")
call(func_ptr,"pewpewpew\x00abcd",0x2222)
call(func_ptr,0x1234,0x5678)
