; get_rip.asm
; Returns an address inside the caller, which the loader uses as an anchor to
; find its own metadata trailer without knowing its own entry point (the payload
; is entered with no arguments, so nothing tells it where it starts).
; Assemble with: ml64 /c /Fo:get_rip.obj get_rip.asm

.code
PUBLIC rfdll_get_rip

; void* rfdll_get_rip(void);
rfdll_get_rip PROC
    call    rfdll_get_rip_here
rfdll_get_rip_here:
    pop     rax                 ; rax = address of the pop, inside the loader
    ret
rfdll_get_rip ENDP

END
