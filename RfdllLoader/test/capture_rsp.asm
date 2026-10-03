; capture_rsp.asm
; Reads the stack pointer of the caller. Used by the end to end test host to
; observe its own frame around the call it makes into the executing payload, so
; the payload's return path can be reasoned about from measured values.
;
; This is test scaffolding only; it is not part of any shellcode blob.
;
; Assemble with: ml64 /c /Fo:capture_rsp.obj capture_rsp.asm

.code
PUBLIC capture_rsp

; void* capture_rsp(void);
capture_rsp PROC
    mov     rax, rsp
    add     rax, 8              ; the caller's rsp at the call site
    ret
capture_rsp ENDP

END
