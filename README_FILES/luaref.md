doxastica - lua functions reference
===================================

the following additional lua functions are supported as part of doxastica. many
of these were inspired by functionality in cheat engine:

- void hexdump(address,{size}):
  dumps memory in hex and ascii if printable

- void dd/dw/db(address,{size}):
  dumps memory, grouped in dword/word/byte, as well as ascii translation if
  printable.

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

- void run(addr):
  runs whatever code is at addr in a new thread. addr must be a number. can be
  used to call existing code, or new code in a malloc shell

- void who_writes_to(addr,size) / void finish_who_writes_to():
  sets up a PAGE_EXECUTE_READ permission on the page[s] covering addr,size, and
  then sets up a vectored exception handler to catch writes to this memory address.
  at each write, a stack trace will be performed - only unique stack traces / unique
  code paths wil be recorded. ~super unstable.~

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
  attempts to search mapped memory for a value of a given size
  (i.e. SEARCH_DWORD, SEARCH_WORD, SEARCH_BYTE, SEARCH_PATTERN)

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

### memory breakpointing

- m_who_writes_to(location):
  stops all threads, then in each thread that's not "ours", sets one of the
  debug registers to location and activates DR7 (only one supported, too lazy
  to do the others). a VEH handler is then set up, which then logs each instance
  of the breakpoint being triggered.

- m_finish_who_writes_to():
  stops all threads, then unsets all breakpoints and removes the VEH handler.
  then, lists up to 1024 code instances which were found to write to a given
  location, along with a one-line disassembly.

### automation / scripting

- bind(hotkeychar,command):
  executes lua_command when hotkeychar is pressed. note that this is done using
  a GetAsyncKeyState every 500ms, so there may be a slight delay. adjustable
  during compile.

- fetch_byte/word/dword(location):
  retrieves and silently returns a byte/word/dword from a given location

### fast edit

- void e{b/w/d}(address, {byte/word/dword}):
  writes a single byte/word/dword to the given address

- void d{b/w/d}(address):
  display a single {byte/word/dword} at the given address
