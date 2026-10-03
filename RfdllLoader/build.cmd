cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:loader.obj loader.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:pe_loader.obj pe_loader.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:rc4.obj rc4.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:misc.obj misc.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:ldr.obj ldr.c
ml64.exe  /Fo get_peb.obj /c get_peb.asm
ml64.exe  /Fo get_rip.obj /c get_rip.asm
link /SUBSYSTEM:WINDOWS /ENTRY:entrypoint /NODEFAULTLIB /DYNAMICBASE:NO /NXCOMPAT:NO /ALIGN:16 /OUT:loader.exe loader.obj pe_loader.obj rc4.obj misc.obj ldr.obj get_peb.obj get_rip.obj
objcopy -O binary -j .text loader.exe loader.bin
