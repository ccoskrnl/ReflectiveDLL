; tail_jump.asm
; Leaves the loader for good and enters the mapped image entry point.
;
; The packed executing entry point uses this instead of calling the image: a
; call made from the shellcode would push a return address pointing into the
; payload region, which the loader has just wiped. The trampoline below lives in
; this same code, so returning from the image lands somewhere valid.
;
; The image entry point is DllMain shaped and follows the Microsoft x64 calling
; convention, so it wants:
;   RCX = image base (the HINSTANCE DllMain sees)
;   RDX = DLL_PROCESS_ATTACH
;   R8  = lpReserved (the payload info pointer)
;
; The caller passes the entry point in R9, which the DllMain contract does not
; use, and the stack pointer the payload's caller had on entry.
;
; That stack pointer must be restored exactly, and must not be guessed: the
; compiler decides the shellcode's frame size, and an earlier attempt assumed
; 0x78 while the real frame was 0x118. The result was an RSP that was 8 bytes
; out, which faulted later inside ntdll on a movaps.
;
; Assemble with: ml64 /c /Fo:tail_jump.obj tail_jump.asm

.code
PUBLIC rfdll_tail_jump

; void rfdll_tail_jump(void* image_base, void* lp_reserved, void* entry, void* caller_stack);
;   RCX = image base
;   RDX = lpReserved
;   R8  = entry point inside the mapped image
;   R9  = stack pointer as it was when the payload was entered
rfdll_tail_jump PROC
    ; Back to the stack the payload's caller left behind. RSP now points at the
    ; return address that caller pushed, which is where this stub's own return
    ; will eventually go.
    mov     rsp, r9

    ; Make the image entry point see a proper call frame: the trampoline address
    ; becomes the return address its ret will use, and the shadow space below it
    ; is the 32 bytes the ABI requires at a call site. RSP ends up 16 byte
    ; aligned minus 8, exactly as at a normal call.
    lea     rax, rfdll_tail_return
    push    rax                     ; return address for the image entry point
    sub     rsp, 20h                ; shadow space

    ; Fill in the DllMain arguments. R8 holds the entry point, so move it out of
    ; the way first. RSP is not touched again before the jump.
    mov     r9, r8                  ; r9 = entry point
    mov     r8, rdx                 ; r8 = lpReserved
    mov     rdx, 1                  ; rdx = DLL_PROCESS_ATTACH
    jmp     r9                      ; rcx is already the image base

; Reached when the image entry point returns. Its ret has already popped the
; return address pushed above, so RSP points exactly at the return address the
; payload's caller pushed. One ret hands control back to that caller.
rfdll_tail_return:
    ret
rfdll_tail_jump ENDP

END
