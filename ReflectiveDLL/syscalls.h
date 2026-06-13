#pragma once

#include "pch.h"
#include "framework.h"
#include "headers.h"
#include "misc.h"


typedef struct _SYSCALL_ENTRY {

    FARPROC funcAddr;
    PBYTE sysretAddr;
    int SSN;

} SYSCALL_ENTRY, * PSYSCALL_ENTRY;


typedef enum _INDIRECT_SYSCALL_FUNC
{
    ZwFlushInstructionCacheF,

    ZwCreateSectionF,
    ZwMapViewOfSectionF,
    ZwUnmapViewOfSectionF,

    ZwQuerySystemInformationF,
    ZwQueryObjectF,
    ZwDuplicateObjectF,

    ZwOpenProcessF,
    ZwCreateThreadExF,
    ZwSetContextThreadF,
    ZwGetContextThreadF,

    ZwReadVirtualMemoryF,
    ZwWriteVirtualMemoryF,
    ZwAllocateVirtualMemoryF,
    ZwProtectVirtualMemoryF,
    ZwQueryVirtualMemoryF,
    ZwFreeVirtualMemoryF,

    ZwOpenProcessTokenF,
    ZwAdjustPrivilegesTokenF,

    AmountofSyscalls

} INDIRECT_SYSCALL_FUNC;



EXTERN_C NTSTATUS ZwFlushInstructionCache(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN ULONG NumberOfBytesToFlush,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN SIZE_T ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwQueryObject(
    IN HANDLE Handle,
    IN ULONG ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle OPTIONAL,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Options,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwSetContextThread(
    IN HANDLE ThreadHandle,
    OUT PCONTEXT Context,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwGetContextThread(
    IN HANDLE ThreadHandle,
    OUT PCONTEXT Context,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T BytesRead OPTIONAL,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T BytesWritten OPTIONAL,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwAdjustPrivilegesToken(
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES NewState OPTIONAL,
    IN ULONG BufferLength,
    OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    OUT PULONG ReturnLength,
    IN DWORD ssn,
    IN PBYTE syscallret
);



bool retrieve_zw_func_s(IN HMODULE hm, IN PSYSCALL_ENTRY syscalls);
