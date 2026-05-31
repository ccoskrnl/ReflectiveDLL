#pragma once

#include <Windows.h>
#include <winternl.h>



typedef int syscall_ssn_t;
typedef void* syscall_addr_t;



#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS
NTAPI
Syscall_NtOpenProcessToken(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle,
	syscall_ssn_t ssn,
	syscall_addr_t syscall_addr
);

NTSTATUS
NTAPI
Syscall_NtAdjustPrivilegesToken(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES NewState,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
    _Out_opt_ PULONG ReturnLength,
	syscall_ssn_t ssn,
	syscall_addr_t syscall_addr
);

#ifdef __cplusplus
}
#endif

typedef struct _ntapi_syscall_ssn
{
    syscall_ssn_t ssn;
	syscall_addr_t addr;
}ntapi_syscall_ssn_t;

typedef enum _ntapi_syscall_index
{
    NtOpenProcessTokenIndex = 0,
    NtAdjustPrivilegesTokenIndex = 1,
} ntapi_syscall_index_t;

#define NT_API_SYSCALL_COUNT 2

bool nt_api_init(HMODULE hm_ntdll, ntapi_syscall_ssn_t* syscall);
