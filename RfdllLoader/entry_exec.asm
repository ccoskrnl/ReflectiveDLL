; entry_exec.asm
; The entry point of the executing payload, at offset 0 of loader_exec.bin.
;
; It exists in assembly for one reason: the stack pointer of the payload's caller
; has to be read before any compiler generated prologue moves it, and it has to
; reach the C part without a frame being added on the way. Adding one (an asm
; stub that "call"s the C part) is what broke this before: the image mapping then
; ran with a stack the C code did not expect, and the fault surfaced much later
; inside ntdll on a movaps while imports were being resolved.
;
; So this entry calls nothing. It puts the incoming stack pointer into RCX, where
; the C part expects its only argument, and jumps. The C part then sees exactly
; the stack a normal call site would have produced.
;
; Assemble with: ml64 /c /Fo:entry_exec.obj entry_exec.asm

.code
EXTERN rfdll_exec_run:PROC
PUBLIC entrypoint_exec

; void entrypoint_exec(void);
;   RCX = the address of the return address the payload's caller pushed. On entry
;         RSP points exactly at it. The C part restores this value in the tail
;         jump, which is what makes the mapped image run on the caller's stack
;         and return to that caller instead of into the wiped payload.
entrypoint_exec PROC
    mov     rcx, rsp
    jmp     rfdll_exec_run
entrypoint_exec ENDP

END
