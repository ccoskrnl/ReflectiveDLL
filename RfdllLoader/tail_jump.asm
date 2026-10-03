; tail_jump.asm
; Leaves the loader for good and enters the mapped image entry point.
;
; The packed executing entry point does this instead of calling the image: a
; call would push a return address that points back into the payload region,
; which the loader has just wiped. A jump leaves nothing behind.
;
; The image entry point is DllMain shaped and follows the Microsoft x64 calling
; convention, so it wants:
;   RCX = image base (the HINSTANCE DllMain sees)
;   RDX = DLL_PROCESS_ATTACH
;   R8  = lpReserved (the payload info pointer)
;
; The caller therefore passes the entry point in R9, which the DllMain contract
; does not use, and this stub moves the three arguments into place and jumps.
;
; Assemble with: ml64 /c /Fo:tail_jump.obj tail_jump.asm

.code
PUBLIC rfdll_tail_jump

; void rfdll_tail_jump(void* image_base, void* lp_reserved, void* entry);
;   RCX = image base
;   RDX = lpReserved
;   R8  = entry point inside the mapped image
rfdll_tail_jump PROC
    ; The shellcode opened its own frame ("sub rsp, 78h"). The image entry point
    ; has its own prologue and expects to start at a normal function entry, so
    ; drop that frame first. RSP then points at whatever return address the
    ; payload's caller pushed, which is what the image unwinds into when it
    ; eventually returns: nothing in the payload is left on the stack.
    add     rsp, 78h

    ; Build the DllMain arguments. R8 already holds the entry point, so move it
    ; to a scratch register that the argument setup does not need, then fill in
    ; the three registers the callee reads.
    mov     r9, r8                  ; r9 = entry point
    mov     r8, rdx                 ; r8 = lpReserved
    mov     rdx, 1                  ; rdx = DLL_PROCESS_ATTACH
    jmp     r9                      ; rcx is already the image base

rfdll_tail_jump ENDP

END
