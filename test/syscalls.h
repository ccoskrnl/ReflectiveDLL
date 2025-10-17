#pragma once
#include <Windows.h>
#include "headers.h"

extern "C" NTSTATUS NTAPI NtCreateSection(
    PHANDLE SectionHandle,
    ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG PageAttributess,
    ULONG SectionAttributes,
    HANDLE FileHandle);

extern "C" NTSTATUS NTAPI NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

extern "C" NTSTATUS NTAPI NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress);

#pragma comment(lib, "ntdll.lib")


EXTERN_C NTSTATUS ZwAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN DWORD ssn,
    IN PBYTE syscallret);

EXTERN_C NTSTATUS ZwProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect,
    IN DWORD ssn,
    IN PBYTE syscallret);

EXTERN_C NTSTATUS ZwFlushInstructionCache(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN ULONG NumberOfBytesToFlush,
    IN DWORD ssn,
    IN PBYTE syscallret);

EXTERN_C NTSTATUS ZwCreateSection(
    OUT PHANDLE	SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN  HANDLE FileHandle,
    IN DWORD ssn, //8
    IN PBYTE syscallret //9
);

EXTERN_C NTSTATUS ZwMapViewOfSection(

    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT	PVOID* BaseAddress,
    IN SIZE_T ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT	PLARGE_INTEGER	SectionOffset,
    IN OUT	PSIZE_T	ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN DWORD ssn, //11
    IN PBYTE syscallret //12
);

EXTERN_C NTSTATUS ZwUnmapViewOfSection(
    IN HANDLE ProcessHandle, //RCX
    IN PVOID BaseAddress, //RDX
    IN DWORD ssn, //R8
    IN PBYTE syscallret); //R9

EXTERN_C NTSTATUS ZwQuerySystemInformation(
    IN ULONG SystemInformationClass, //RCX
    OUT PVOID SystemInformation, //RDX
    IN ULONG SystemInformationLength, //R8
    OUT PULONG ReturnLength, //R9
    IN DWORD ssn, //RSP + 40
    IN PBYTE syscallret //RSP + 48
);

EXTERN_C NTSTATUS ZwQueryObject(
    IN HANDLE Handle,
    IN ULONG ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength,
    IN DWORD ssn,
    IN PBYTE syscallret);

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
    IN HANDLE  ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG   FreeType,
    IN DWORD ssn, //RSP + 40
    IN PBYTE syscallret //RSP + 48
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



