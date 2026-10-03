; entry_exec.asm
; The entry point of the executing payload, at offset 0 of loader_exec.bin.
;
; It exists in assembly for one reason: the stack pointer of the payload's caller
; has to be read before any compiler generated prologue moves it. The value is
; passed to the C part, which restores it in the tail jump so the mapped image
; runs on the caller's stack and returns to that caller.
;
; Reading it inside the C function instead would be off by whatever frame the
; compiler chose, which is not something assembly should assume.
;
; Assemble with: ml64 /c /Fo:entry_exec.obj entry_exec.asm

.code
EXTERN rfdll_exec_run:PROC
PUBLIC entrypoint_exec

; void entrypoint_exec(void);
;   RCX = stack pointer of the payload's caller, i.e. the address of the return
;         address that call pushed. The C part needs exactly this value.
entrypoint_exec PROC
    mov     rcx, rsp            ; RSP here points at our own return address,
    add     rcx, 8              ; so the caller's RSP was one slot above it
    sub     rsp, 28h            ; shadow space for the call below
    call    rfdll_exec_run
    add     rsp, 28h            ; only reached when the C part fails and returns
    ret
entrypoint_exec ENDP

END
