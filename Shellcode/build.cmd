cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:http.obj http.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:Shellcode.obj Shellcode.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:pe_parser.obj pe_parser.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:misc.obj misc.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:ldr.obj ldr.c
ml64.exe  /Fo get_peb.obj /c get_peb.asm
link /SUBSYSTEM:WINDOWS /ENTRY:entrypoint /NODEFAULTLIB /DYNAMICBASE:NO /NXCOMPAT:NO /ALIGN:16 /OUT:shellcode.exe Shellcode.obj http.obj pe_parser.obj misc.obj ldr.obj get_peb.obj
objcopy -O binary -j .text shellcode.exe shellcode.bin

