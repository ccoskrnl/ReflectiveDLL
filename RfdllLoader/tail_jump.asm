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
; STATUS: the jump into the image is verified working and the trampoline below is
; NOT reached. What the code does now is described first, then what is known about
; the return path and why it is still open.
;
; What is verified: the image maps, its CRT resolves imports, DllMain runs to
; completion, the payload info arrives through both channels (lpReserved and the
; copy at image+0x40) and the payload frees the loader's own region.
;
; The return path, and where it stands
; ------------------------------------
; The shape of a normally built payload was established by reading its
; disassembly: _DllMainCRTStartup sits at AddressOfEntryPoint, releases its own
; frame and tail-jumps into DllMain, so DllMain is entered with exactly the RSP
; the entry point was handed and its epilogue's ret reads that same slot. So the
; trampoline has to be stored AT that slot. A "push" cannot do it (push writes to
; rsp-8 while the entry point is handed the rsp that follows), which is why the
; store below is a plain store.
;
; Dumping the live stack at the fault then showed why it still does not work. The
; frame at the crash reads:
;
;   [E+8]  image base          } these four are DllMain's own argument spills,
;   [E+10] DLL_PROCESS_ATTACH  } which is how E was identified
;   [E+18] image base + 0x40
;   [E+20] payload size
;   [E]    a payload-region address, not the trampoline
;
; E is where the shellcode rebuilt the frame, and R9 - from entry_exec.asm - is
; the RSP the payload entry point was called with. That RSP lives inside the
; region the host allocated for the payload, so building a frame downward from it
; writes into payload memory rather than into the caller's stack frame. Whatever
; lands at [E] is therefore not read back as the caller intended, and DllMain
; returns to a payload address that has already been wiped.
;
; The open question is consequently not a frame size but where the caller's return
; address actually is relative to what entry_exec.asm can see. Settling it needs
; evidence from the host side (the stack as case_exec sees it around its call),
; which has not been done yet.
;
; Until then, treat this entry point as "runs the payload and does not come back".
; The reserved 20h keeps the entry point 8 modulo 16, which is required: reserving
; only shadow space for a call left it misaligned and the fault surfaced much later
; inside ntdll on a movaps during import resolution, far from this code.
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

; Intended landing point for the return path; never reached today. See the note at
; the top of this file.
rfdll_tail_return:
    ret
rfdll_tail_jump ENDP

END
