cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:loader.obj loader.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:pe_loader.obj pe_loader.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:misc.obj misc.c
cl /c /Od /GS- /Gs9999999 /Gy- /GR- /EHs-c- /MT /Fo:ldr.obj ldr.c
ml64.exe  /Fo get_peb.obj /c get_peb.asm
link /SUBSYSTEM:WINDOWS /ENTRY:entrypoint /NODEFAULTLIB /DYNAMICBASE:NO /NXCOMPAT:NO /ALIGN:16 /OUT:loader.exe loader.obj pe_loader.obj misc.obj ldr.obj get_peb.obj
objcopy -O binary -j .text loader.exe loader.bin
