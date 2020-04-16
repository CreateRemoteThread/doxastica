# lua engine

upon starting a lua instance, several default variables are initialized. these
are:

- window memory protection constances: PAGE_* are defined as integers corresponding
  to their values as defined in msdn

- SEARCH_DWORD, SEARCH_WORD, SEARCH_BYTE for specifying types of value searches

- module start and size. let's say you've loaded "ati_d3d11.dll", the following
  values will be automatically defined:

  - ati_d3d11_dll.start
  - ati_d3d11_dll.size

# functions ref

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
  
- void free(ptr):
  frees a block of memory (created by malloc);

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

- void dump_all(_directory):
  dumps entire memory space into a new directory named _directory. this will not
  write to existing directories. remember that the current directory will be
  based on the target process' executable (aka specify a full path you lazy fuck)

- void dump_module(module,save):
  dumps a single module to disk in a single contiguous file.
  
- int resolve(module):
  resolves the function specified as an argument, and returns it as an integer.
  the argument should be dllname.dll!function. error will be printed in peek if
  the function can't be resolved. no output probably means you didn't print the
  result.
  
- void loadlibrary(libname):
  does what the box says, loads the library into the current memory space (just
  calls loadlibrary with what you pass it)
  
- void hook(target_func_addr,hook_func_addr,callback)
  exposes the internal hook function, inserting a jump to hook_func_addr at the
  start of target_func_addr, then calls (Stdcall) to "callback", with the address
  of the old function. see luasamples/pa3.lua for usage example.

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

- m_who_accesses(location):
  stops all threads, then in each thread that's not "ours", sets one of the
  debug registers to location and activates DR7 (only one supported, too lazy
  to do the others). a VEH handler is then set up, which then logs each instance
  of the breakpoint being triggered.

- m_finish():
  stops all threads, then unsets all breakpoints and removes the VEH handler.
  then, lists up to 1024 code instances which were found to write to a given
  location, along with a one-line disassembly.

### fast edit

- void e{b/w/d}(address, {byte/word/dword}):
  writes a single byte/word/dword to the given address

- void d{b/w/d}(address):
  display a single {byte/word/dword} at the given address
  
### sockets

- sock ls_connect(host,port)
  this creates a socket, temporarily sets it to nonblocking so connect can have
  a non-ridiculous timeout, and ioctl's it to blocking again.

- int ls_closesocket(sock)
- void ls_send(sock,data);
- size ls_recv(sock,size);

### handy lua stuff

- dofile(filename) can load and execute a (lua) file

- call(func_addr,args...) can call any arbitrary address as if it were a function, and
  pass any number of arbitrary arguments
  
- catchthis(func_addr,save_loc) can steal the "this" pointer out of a C++ function call
  by crafting a thread-safe code cave (jmp->mov loc,ecx->push/ret). the original use case
  was to provide a "this" pointer to a patch dll, so pass this over.
  
- deref(data_addr) can derefernce a UINT_PTR, returning the data at data_addr. this does
  exception handle...
