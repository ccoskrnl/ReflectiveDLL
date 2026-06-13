; ══════════════════════════════════════════════════════════════
;   Windows Native API Syscall Stubs (x64, User Mode → Kernel)
; ══════════════════════════════════════════════════════════════

PUBLIC ZwFlushInstructionCache
PUBLIC ZwCreateSection
PUBLIC ZwMapViewOfSection
PUBLIC ZwUnmapViewOfSection
PUBLIC ZwQuerySystemInformation
PUBLIC ZwDuplicateObject
PUBLIC ZwQueryObject
PUBLIC ZwOpenProcess
PUBLIC ZwCreateThreadEx
PUBLIC ZwSetContextThread
PUBLIC ZwGetContextThread
PUBLIC ZwReadVirtualMemory
PUBLIC ZwWriteVirtualMemory
PUBLIC ZwAllocateVirtualMemory
PUBLIC ZwProtectVirtualMemory
PUBLIC ZwQueryVirtualMemory
PUBLIC ZwFreeVirtualMemory
PUBLIC ZwOpenProcessToken
PUBLIC ZwAdjustPrivilegesToken

.code _text


; ═══════════════════════════════════════════════════
; ZwFlushInstructionCache
; ═══════════════════════════════════════════════════
ZwFlushInstructionCache PROC
    mov r10, rcx
    mov rax, r9                     ; System service number
    jmp qword ptr [rsp + 40]
ZwFlushInstructionCache ENDP





; ═══════════════════════════════════════════════════
; ZwCreateSection
; ═══════════════════════════════════════════════════
ZwCreateSection PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 64]   ; System service number
    jmp qword ptr [rsp + 72]
ZwCreateSection ENDP


; ═══════════════════════════════════════════════════
; ZwMapViewOfSection
; ═══════════════════════════════════════════════════
ZwMapViewOfSection PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 88]   ; System service number
    jmp qword ptr [rsp + 96]
ZwMapViewOfSection ENDP


; ═══════════════════════════════════════════════════
; ZwUnmapViewOfSection
; ═══════════════════════════════════════════════════
ZwUnmapViewOfSection PROC
    mov r10, rcx
    mov eax, r8d                    ; System service number
    jmp r9
ZwUnmapViewOfSection ENDP


; ═══════════════════════════════════════════════════
; ZwQuerySystemInformation
; ═══════════════════════════════════════════════════
ZwQuerySystemInformation PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 40]   ; System service number
    jmp qword ptr [rsp + 48]
ZwQuerySystemInformation ENDP


; ═══════════════════════════════════════════════════
; ZwQueryObject
; ═══════════════════════════════════════════════════
ZwQueryObject PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 48]   ; System service number
    jmp qword ptr [rsp + 56]
ZwQueryObject ENDP


; ═══════════════════════════════════════════════════
; ZwDuplicateObject
; ═══════════════════════════════════════════════════
ZwDuplicateObject PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [rsp + 64]   ; System service number
    jmp qword ptr [rsp + 72]
ZwDuplicateObject ENDP





; ═══════════════════════════════════════════════════
; ZwOpenProcess
; ═══════════════════════════════════════════════════
ZwOpenProcess PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 40]   ; System service number
    jmp qword ptr [rsp + 48]
ZwOpenProcess ENDP


; ═══════════════════════════════════════════════════
; ZwCreateThreadEx
; ═══════════════════════════════════════════════════
ZwCreateThreadEx PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 96]   ; System service number
    jmp qword ptr [rsp + 104]
ZwCreateThreadEx ENDP


; ═══════════════════════════════════════════════════
; ZwSetContextThread
; ═══════════════════════════════════════════════════
ZwSetContextThread PROC
    mov r10, rcx
    mov eax, r8d                    ; System service number
    jmp r9
ZwSetContextThread ENDP


; ═══════════════════════════════════════════════════
; ZwGetContextThread
; ═══════════════════════════════════════════════════
ZwGetContextThread PROC
    mov r10, rcx
    mov eax, r8d                    ; System service number
    jmp r9
ZwGetContextThread ENDP





; ═══════════════════════════════════════════════════
; ZwReadVirtualMemory
; ═══════════════════════════════════════════════════
ZwReadVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 48]   ; System service number
    jmp qword ptr [rsp + 56]
ZwReadVirtualMemory ENDP


; ═══════════════════════════════════════════════════
; ZwWriteVirtualMemory
; ═══════════════════════════════════════════════════
ZwWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 48]   ; System service number
    jmp qword ptr [rsp + 56]
ZwWriteVirtualMemory ENDP


; ═══════════════════════════════════════════════════
; ZwAllocateVirtualMemory
; ═══════════════════════════════════════════════════
ZwAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 56]   ; System service number
    jmp qword ptr [rsp + 64]
ZwAllocateVirtualMemory ENDP


; ═══════════════════════════════════════════════════
; ZwProtectVirtualMemory
; ═══════════════════════════════════════════════════
ZwProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 48]   ; System service number
    jmp qword ptr [rsp + 56]
ZwProtectVirtualMemory ENDP


; ═══════════════════════════════════════════════════
; ZwQueryVirtualMemory
; ═══════════════════════════════════════════════════
ZwQueryVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 56]   ; System service number
    jmp qword ptr [rsp + 64]
ZwQueryVirtualMemory ENDP


; ═══════════════════════════════════════════════════
; ZwFreeVirtualMemory
; ═══════════════════════════════════════════════════
ZwFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp + 40]   ; System service number
    jmp qword ptr [rsp + 48]
ZwFreeVirtualMemory ENDP




; ═══════════════════════════════════════════════════
; ZwOpenProcessToken
; ═══════════════════════════════════════════════════
ZwOpenProcessToken PROC PUBLIC
    mov r10, rcx
    mov eax, r9d                    ; System service number
    jmp qword ptr [rsp + 40]
ZwOpenProcessToken ENDP


; ═══════════════════════════════════════════════════
; ZwAdjustPrivilegesToken
; ═══════════════════════════════════════════════════
ZwAdjustPrivilegesToken PROC PUBLIC
    mov r10, rcx
    mov eax, dword ptr [rsp + 56]   ; System service number
    jmp qword ptr [rsp + 64]
ZwAdjustPrivilegesToken ENDP


END