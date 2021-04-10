# function hooks (quickstart)

## procedure

doxastica can be used to create arbitrary function hooks. some test code is provided
for this in the utils directory. To compile the test files, use cl and link.exe:

    REM start by compiling the test exe
    cd utils
    cl /c testing.c
    link /out:testing.exe testing.obj user32.lib
    REM now compile the test dll
    cl /c testdll.c
    link /out:testdll.dll /dll /def:testdll.def testdll.obj

Now, load up the target executable (assuming 32-bit):

    ldr32 -exe utils/testing.exe -dll shackle32.dll -wdir .
    peek <pid>

We can use the native loadlibrary() function to load our target hook dll into the testexe
process:

    loadlibrary("utils/testdll.dll")
    resolve("testdll.dll")

If the library loads successfully, you should be able to resolve the library itself (and
any functions within it). Now, hook the MessageBoxA function as follows:

    hook(resolve("user32.dll!MessageBoxA"),resolve("testdll.dll!NewMsgBox"),resolve("testdll!callback"))
    \[NFO] resolving 'user32.dll!MessageBoxA'
    \[NFO] resolving 'testdll.dll!NewMsgBox'
    \[NFO] resolving 'testdll!callback'
    \[NFO] hooking 76EFEE90 with 7A271030
    \[NFO] pinging callback with old address 007D0000

Now, hit enter in testing.exe, and watch the modified messagebox pop up!

## development

API hooks are implemented using a thread-safe (except during installation) code trampoline
implemented in shackle.c (see the "hook" function). Two functions are required in the target
dll:

- NewMsgBox is our hooking target. This will be called instead of the original function, and
controls both it's paramters and return value. It may, but does not have to, interact with the
original function.
- callback is required - shackle will call this function with one argument, the original address
of whatever function was hooked. The hook dll may, but does not have to, use this information.
