@echo off
setlocal

rem Two blobs are produced from the same object files:
rem   loader.bin         entrypoint        (RCX = dll base, RDX = size)
rem   loader_packed.bin  entrypoint_packed (no arguments, self locating)
rem Each blob is linked separately because objcopy keeps only .text and the
rem entry point called by the client has to sit at offset 0 of the file.

set CFLAGS=/c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT

rem Every step is checked: without this a compile error would be ignored and the
rem link would quietly reuse a stale object file from an earlier run.
cl %CFLAGS% /Fo:loader.obj loader.c || exit /b 1
cl %CFLAGS% /Fo:loader_packed.obj loader_packed.c || exit /b 1
cl %CFLAGS% /Fo:pe_loader.obj pe_loader.c || exit /b 1
cl %CFLAGS% /Fo:rc4.obj rc4.c || exit /b 1
cl %CFLAGS% /Fo:misc.obj misc.c || exit /b 1
cl %CFLAGS% /Fo:ldr.obj ldr.c || exit /b 1
ml64.exe  /Fo get_peb.obj /c get_peb.asm || exit /b 1
ml64.exe  /Fo get_rip.obj /c get_rip.asm || exit /b 1

set COMMON=pe_loader.obj rc4.obj misc.obj ldr.obj get_peb.obj get_rip.obj

link /SUBSYSTEM:WINDOWS /ENTRY:entrypoint /NODEFAULTLIB /DYNAMICBASE:NO /NXCOMPAT:NO /ALIGN:16 /OUT:loader.exe loader.obj %COMMON%
if errorlevel 1 exit /b 1
objcopy -O binary -j .text loader.exe loader.bin
if errorlevel 1 exit /b 1

link /SUBSYSTEM:WINDOWS /ENTRY:entrypoint_packed /NODEFAULTLIB /DYNAMICBASE:NO /NXCOMPAT:NO /ALIGN:16 /OUT:loader_packed.exe loader_packed.obj %COMMON%
if errorlevel 1 exit /b 1
objcopy -O binary -j .text loader_packed.exe loader_packed.bin
if errorlevel 1 exit /b 1

endlocal
