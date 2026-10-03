; tail_jump.asm
; Leaves the loader for good and enters the mapped image entry point.
;
; The packed executing entry point uses this instead of calling the image: a call
; made from the shellcode would push a return address pointing into the payload
; region, which the loader has just wiped. The trampoline below lives in this same
; code, so a return from the image lands somewhere valid.
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
; That stack pointer must be restored exactly and must not be guessed. Two
; separate mistakes were made here and are worth remembering:
;   1. assuming a fixed shellcode frame size (0x78 against a real 0x118), which
;      left RSP 8 bytes out;
;   2. reserving the wrong amount for the call frame, which left the image entry
;      point 16 byte misaligned. The fault did not show up in the loader at all;
;      it appeared much later inside ntdll on a movaps while the image's CRT was
;      resolving its own imports.
;
; STATUS: the jump into the image works (the image maps, DllMain runs, the payload
; info arrives and the payload frees its own region), but the return path from the
; image back to the caller is NOT solved. The trampoline below is never reached:
; the image's _DllMainCRTStartup releases its own frame and tail-jumps into
; DllMain rather than returning through the pushed address, so the final ret does
; not land here. Treat this entry point as "runs the payload and does not come
; back" until that is worked out.
;
; Assemble with: ml64 /c /Fo:tail_jump.obj tail_jump.asm

.code
PUBLIC rfdll_tail_jump

; void rfdll_tail_jump(void* image_base, void* lp_reserved, void* entry, void* caller_stack);
;   RCX = image base
;   RDX = lpReserved
;   R8  = entry point inside the mapped image
;   R9  = the address of the return address the payload's caller pushed
rfdll_tail_jump PROC
    ; Back to the stack the payload's caller left behind. R9 points at the return
    ; address that caller pushed, so RSP is 8 modulo 16 here.
    mov     rsp, r9

    ; Build the frame the image entry point will see. The trampoline address is
    ; pushed as its return address, and 28h is reserved: 20h of shadow space plus
    ; one slot, which is what makes the entry point see RSP 8 modulo 16 the way a
    ; call would have left it. Reserving 20h instead left it 16 byte misaligned.
    lea     rax, rfdll_tail_return
    push    rax
    sub     rsp, 28h

    ; Fill in the DllMain arguments. R8 holds the entry point, so move it out of
    ; the way first. RSP is not touched again before the jump.
    mov     r9, r8                  ; r9 = entry point
    mov     r8, rdx                 ; r8 = lpReserved
    mov     rdx, 1                  ; rdx = DLL_PROCESS_ATTACH
    jmp     r9                      ; rcx is already the image base

; Never reached with the current image entry point; kept as the intended landing
; point for the return path once that is solved. If the image's CRT returned
; through the address pushed above, RSP would be back at the caller's return slot
; and a single ret would hand control back to that caller.
rfdll_tail_return:
    ret
rfdll_tail_jump ENDP

END
