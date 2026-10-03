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
; The caller passes the entry point in R9, which the DllMain contract does not
; use, and the stack pointer the payload's caller had on entry, so this stub can
; hand the image the same stack the payload itself was given.
;
; What is verified: the image is mapped, its CRT resolves imports, DllMain runs to
; completion, the payload info arrives through both channels, and the payload
; frees the loader's own region.
;
; What is NOT solved: returning from the image to the payload's caller. The reason
; is concrete and was established from the disassembly of a normally built payload.
; _DllMainCRTStartup sits at AddressOfEntryPoint, releases its own frame with
; "add rsp,20h ; pop rdi" and then TAIL-JUMPS into DllMain. It never pushes a
; return address for DllMain, so DllMain's ret does not read anything this stub
; controls at the top of the frame; it reads a fixed 0x58 bytes above wherever the
; entry point was entered (0x40 for DllMain's own frame, 0x18 for the three
; registers it pops, 8 for the return slot).
;
; Two ways to reach the caller were tried and both are wrong: entering at
; (caller slot - 0x58) hits the caller's return slot exactly but leaves the entry
; point 16 byte misaligned, which faults inside ntdll; placing a trampoline at
; entry + 0x58 keeps the alignment but writes into the caller's live frame. The
; remaining options all involve either not returning (accept that the payload owns
; the thread) or having the payload itself arrange the continuation, so this is
; left as an open item rather than guessed at further.
;
; Treat this entry point as "runs the payload and does not come back".
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
    ; Back to the stack the payload's caller left behind. R9 is 8 modulo 16, and
    ; the 28h reserved below keeps the entry point there: 20h is the shadow space
    ; the ABI requires at a call site and the extra 8 keeps a callee's expectation
    ; of 8 modulo 16. Reserving only 20h left it 16 byte misaligned, and that fault
    ; surfaced much later inside ntdll on a movaps during import resolution rather
    ; than anywhere near this code.
    mov     rsp, r9
    lea     rax, rfdll_tail_return
    push    rax
    sub     rsp, 28h

    ; Fill in the DllMain arguments. R8 holds the entry point, so move it out of
    ; the way first. RSP is not touched again before the jump.
    mov     r9, r8                  ; r9 = entry point
    mov     r8, rdx                 ; r8 = lpReserved
    mov     rdx, 1                  ; rdx = DLL_PROCESS_ATTACH
    jmp     r9                      ; rcx is already the image base

; Intended landing point for the return path, kept so the frame has a return
; address. Never reached with the current image entry point; see the note at the
; top of this file for why.
rfdll_tail_return:
    ret
rfdll_tail_jump ENDP

END
