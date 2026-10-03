; tail_jump.asm
; Leaves the loader for good and enters the mapped image entry point.
;
; The packed executing entry point uses this instead of calling the image: a call
; made from the shellcode would push a return address pointing into the payload
; region, which the loader has just wiped.
;
; The image entry point is DllMain shaped and follows the Microsoft x64 calling
; convention, so it wants:
;   RCX = image base (the HINSTANCE DllMain sees)
;   RDX = DLL_PROCESS_ATTACH
;   R8  = lpReserved (the payload info pointer)
;
; STATUS: the jump into the image is verified working. DllMain runs to completion,
; the payload info arrives through both channels (lpReserved and the copy at
; image+0x40) and the payload frees the loader's own region. The trampoline below
; is NOT reached.
;
; What the measurements established
; ---------------------------------
; The host prints the stack pointer at its call site (H), and dumping the live
; frame at the fault identifies E, the RSP the image entry point is entered with,
; from DllMain's four argument spills (image base, reason code, info pointer,
; payload size) which appear at E+8..E+0x20. In one run that gave:
;
;   H = 0x4BDA12F7D0      host RSP at its call
;   E = 0x4BDA12F7A8      H - E = 0x28, and E is 8 modulo 16 as the ABI requires
;   R9 = E + 0x20 = H - 8 so the caller return address sits at E+0x28
;
; So the frame placement and the offsets are consistent, and the trampoline is
; stored exactly at [E], which is the slot the entry point is handed.
;
; What is still unresolved
; ------------------------
; An int3 placed at the trampoline never trips even though DllMain logs all of its
; lines, so the ret that ends the image does not arrive at [E]. Statically the
; payload says it should: _DllMainCRTStartup sits at AddressOfEntryPoint, releases
; its own frame and tail-jumps into DllMain, whose single epilogue ret reads the
; slot it was entered with. The two observations disagree and nothing measured so
; far explains why, so the next step is to break inside the image at its ret
; rather than keep adjusting this stub.
;
; Until then, treat this entry point as "runs the payload and does not come back".
; The 20h reservation stays: it keeps the entry point 8 modulo 16, and reserving
; only shadow space for a call left it misaligned, which faulted much later inside
; ntdll on a movaps during import resolution, nowhere near this code.
;
; Assemble with: ml64 /c /Fo:tail_jump.obj tail_jump.asm

.code
PUBLIC rfdll_tail_jump

; void rfdll_tail_jump(void* image_base, void* lp_reserved, void* entry, void* caller_stack);
;   RCX = image base
;   RDX = lpReserved
;   R8  = entry point inside the mapped image
;   R9  = the stack pointer the payload entry point was called with
rfdll_tail_jump PROC
    mov     rsp, r9
    sub     rsp, 20h
    lea     rax, rfdll_tail_return
    mov     qword ptr [rsp], rax

    ; Fill in the DllMain arguments. R8 holds the entry point, so move it out of
    ; the way first. RSP is not touched again before the jump.
    mov     r9, r8                  ; r9 = entry point
    mov     r8, rdx                 ; r8 = lpReserved
    mov     rdx, 1                  ; rdx = DLL_PROCESS_ATTACH
    jmp     r9                      ; rcx is already the image base

; Reached when the image returns, by the ret described above.
;
; That ret popped [E] and left RSP at E+8, while the return address the payload's
; caller pushed sits at H = E+0x28, so RSP rises by 0x20 before the final ret.
;
; Every number here is measured, not derived. The host prints the stack pointer at
; its own call site (call it H) and the debugger dumps the frame at the fault:
; DllMain's four argument spills show up at E+8..E+0x20, which identifies E, and
; H - E comes out as exactly 0x28 in that same run. E is also 8 modulo 16, which
; is what the ABI requires of the entry point.
rfdll_tail_return:
    add     rsp, 20h
    ret
rfdll_tail_jump ENDP

END
