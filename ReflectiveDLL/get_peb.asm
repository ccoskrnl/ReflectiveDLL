.code
PUBLIC get_peb_x64

; void* get_peb_x64(void);
get_peb_x64 PROC
    mov     rax, qword ptr gs:[60h]   ; x64 TEB 偏移 0x60 处存放 PEB 指针
    ret
get_peb_x64 ENDP

END