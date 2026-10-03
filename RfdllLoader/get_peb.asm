; get_peb_x64.asm
; Returns the x64 PEB address.
; Assemble with: ml64 /c /Fo:get_peb_x64.obj get_peb_x64.asm

.code
PUBLIC get_peb_x64

; void* get_peb_x64(void);
get_peb_x64 PROC
    mov     rax, qword ptr gs:[60h]   ; x64 TEB offset 0x60 holds the PEB pointer
    ret
get_peb_x64 ENDP

END