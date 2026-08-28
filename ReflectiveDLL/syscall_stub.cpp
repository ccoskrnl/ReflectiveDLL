#include "pch.h"
#include "misc.h"
#include "headers.h"
#include "syscalls.h"
#include "api_hash.h"


SYSCALL_ENTRY g_zw_functions[AmountofSyscalls] = { 0 };

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

bool retrieve_zw_func_s(IN HMODULE hm, IN PSYSCALL_ENTRY syscalls)
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


    PBYTE func_addr = 0;
    uintptr_t func_addr_value = 0;

    int syscall_entries = 0;
    int zw_func_counter = 0;




    for (DWORD i = 0; i < p_img_export_dir->NumberOfFunctions; i++)
    {
        CHAR* func_name = (CHAR*)(lib_base + func_name_array[i]);

        if (func_name[0] != 'Z' || func_name[1] != 'w')
            continue;

        DWORD name_hash = HashStringA(func_name);

        func_addr = (PBYTE)(lib_base + func_addr_array[func_ordinal_array[i]]);
        func_addr_value = (uintptr_t)func_addr;

        if (name_hash == HASH_ZWFLUSHINSTRUCTIONCACHE) {
            syscalls[ZwFlushInstructionCacheF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwFlushInstructionCacheF].SSN,
                (uintptr_t*)&syscalls[ZwFlushInstructionCacheF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWCREATESECTION) {
            syscalls[ZwCreateSectionF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwCreateSectionF].SSN,
                (uintptr_t*)&syscalls[ZwCreateSectionF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWMAPVIEWOFSECTION) {
            syscalls[ZwMapViewOfSectionF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwMapViewOfSectionF].SSN,
                (uintptr_t*)&syscalls[ZwMapViewOfSectionF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWUNMAPVIEWOFSECTION) {
            syscalls[ZwUnmapViewOfSectionF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwUnmapViewOfSectionF].SSN,
                (uintptr_t*)&syscalls[ZwUnmapViewOfSectionF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWQUERYSYSTEMINFORMATION) {
            syscalls[ZwQuerySystemInformationF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwQuerySystemInformationF].SSN,
                (uintptr_t*)&syscalls[ZwQuerySystemInformationF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWQUERYOBJECT) {
            syscalls[ZwQueryObjectF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwQueryObjectF].SSN,
                (uintptr_t*)&syscalls[ZwQueryObjectF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWDUPLICATEOBJECT) {
            syscalls[ZwDuplicateObjectF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwDuplicateObjectF].SSN,
                (uintptr_t*)&syscalls[ZwDuplicateObjectF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWOPENPROCESS) {
            syscalls[ZwOpenProcessF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwOpenProcessF].SSN,
                (uintptr_t*)&syscalls[ZwOpenProcessF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWCREATETHREADEX) {
            syscalls[ZwCreateThreadExF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwCreateThreadExF].SSN,
                (uintptr_t*)&syscalls[ZwCreateThreadExF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWSETCONTEXTTHREAD) {
            syscalls[ZwSetContextThreadF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwSetContextThreadF].SSN,
                (uintptr_t*)&syscalls[ZwSetContextThreadF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWGETCONTEXTTHREAD) {
            syscalls[ZwGetContextThreadF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwGetContextThreadF].SSN,
                (uintptr_t*)&syscalls[ZwGetContextThreadF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWREADVIRTUALMEMORY) {
            syscalls[ZwReadVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwReadVirtualMemoryF].SSN,
                (uintptr_t*)&syscalls[ZwReadVirtualMemoryF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWWRITEVIRTUALMEMORY) {
            syscalls[ZwWriteVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwWriteVirtualMemoryF].SSN,
                (uintptr_t*)&syscalls[ZwWriteVirtualMemoryF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWALLOCATEVIRTUALMEMORY) {
            syscalls[ZwAllocateVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwAllocateVirtualMemoryF].SSN,
                (uintptr_t*)&syscalls[ZwAllocateVirtualMemoryF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWPROTECTVIRTUALMEMORY) {
            syscalls[ZwProtectVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwProtectVirtualMemoryF].SSN,
                (uintptr_t*)&syscalls[ZwProtectVirtualMemoryF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWQUERYVIRTUALMEMORY) {
            syscalls[ZwQueryVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwQueryVirtualMemoryF].SSN,
                (uintptr_t*)&syscalls[ZwQueryVirtualMemoryF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWFREEVIRTUALMEMORY) {
            syscalls[ZwFreeVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwFreeVirtualMemoryF].SSN,
                (uintptr_t*)&syscalls[ZwFreeVirtualMemoryF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWOPENPROCESSTOKEN) {
            syscalls[ZwOpenProcessTokenF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwOpenProcessTokenF].SSN,
                (uintptr_t*)&syscalls[ZwOpenProcessTokenF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
        else if (name_hash == HASH_ZWADJUSTPRIVILEGESTOKEN) {
            syscalls[ZwAdjustPrivilegesTokenF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr,
                (PDWORD)&syscalls[ZwAdjustPrivilegesTokenF].SSN,
                (uintptr_t*)&syscalls[ZwAdjustPrivilegesTokenF].sysretAddr);
            if (!result) return false;
            syscall_entries++;
        }
    }

    return result;

}

