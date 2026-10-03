rem End to end test build for the reflective loader shellcode.
rem Run build.cmd in the parent directory first (it produces loader.bin).
rem Must be started from a VS developer command prompt (vcvars64.bat applied).
cl /nologo /O2 /MT /LD /Fe:target.dll target_dll.c /link /DYNAMICBASE /INCREMENTAL:NO || exit /b 1
cl /nologo /O2 /MT /LD /Fe:fail.dll fail_dll.c /link /DYNAMICBASE /INCREMENTAL:NO || exit /b 1
cl /nologo /O2 /MT /Fe:host.exe host.c || exit /b 1
rem host.exe ..\loader.bin target.dll fail.dll
