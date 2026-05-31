PUBLIC Syscall_NtOpenProcessToken
PUBLIC Syscall_NtAdjustPrivilegesToken

.code _text
Syscall_NtOpenProcessToken PROC PUBLIC
	mov r10, rcx
	mov eax, r9d
	jmp qword ptr [rsp + 40]

Syscall_NtOpenProcessToken ENDP


Syscall_NtAdjustPrivilegesToken PROC PUBLIC
	mov r10, rcx
	mov eax, dword ptr [rsp + 56]
	jmp qword ptr [rsp + 64]
Syscall_NtAdjustPrivilegesToken ENDP

END
