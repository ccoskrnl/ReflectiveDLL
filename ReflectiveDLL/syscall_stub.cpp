#include "pch.h"
#include "misc.h"
#include "headers.h"
#include "syscalls.h"


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

    //variables for syscall
    CHAR str_zw[] = { 'Z','w' };

    CHAR str_ZwFlushInstructionCache[] = { 'Z','w','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e','\0' };

    CHAR str_ZwCreateSection[] = { 'Z', 'w', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR str_ZwMapViewOfSection[] = { 'Z', 'w', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR str_ZwUnmapViewOfSection[] = { 'Z', 'w', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };

    CHAR str_ZwQuerySystemInformation[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', '\0' };
    CHAR str_ZwQueryObject[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0' };
    CHAR str_ZwDuplicateObject[] = { 'Z', 'w', 'D', 'u', 'p', 'l', 'i', 'c', 'a', 't', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0' };

    CHAR str_ZwOpenProcess[] = { 'Z', 'w', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    CHAR str_ZwCreateThreadEx[] = { 'Z', 'w', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '\0' };
    CHAR str_ZwSetContextThread[] = { 'Z', 'w', 'S', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
    CHAR str_ZwGetContextThread[] = { 'Z', 'w', 'G', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };

    CHAR str_ZwReadVirtualMemory[] = { 'Z', 'w', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwWriteVirtualMemory[] = { 'Z', 'w', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwAllocateVirtualMemory[] = { 'Z', 'w', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwProtectVirtualMemory[] = { 'Z', 'w', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwQueryVirtualMemory[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR str_ZwFreeVirtualMemory[] = { 'Z', 'w', 'F', 'r', 'e', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };

    CHAR str_ZwOpenProcessToken[] = { 'Z', 'w', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 'T', 'o', 'k', 'e', 'n', '\0' };
    CHAR str_ZwAdjustPrivilegesToken[] = { 'Z', 'w', 'A', 'd', 'j', 'u', 's', 't', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', 's', 'T', 'o', 'k', 'e', 'n', '\0' };


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

        if (CompareStringASCII(str_ZwFlushInstructionCache, func_name)) {
            syscalls[ZwFlushInstructionCacheF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwFlushInstructionCacheF].SSN, (uintptr_t*)&syscalls[ZwFlushInstructionCacheF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwFlushInstructionCacheF].sysretAddr = NULL;
            //syscalls[ZwFlushInstructionCacheF].SSN = 0;
            syscall_entries++;
        }



        if (CompareStringASCII(str_ZwCreateSection, func_name)) {
            syscalls[ZwCreateSectionF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwCreateSectionF].SSN, (uintptr_t*)&syscalls[ZwCreateSectionF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwCreateSectionF].sysretAddr = NULL;
            //syscalls[ZwCreateSectionF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwMapViewOfSection, func_name)) {
            syscalls[ZwMapViewOfSectionF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwMapViewOfSectionF].SSN, (uintptr_t*)&syscalls[ZwMapViewOfSectionF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwMapViewOfSectionF].sysretAddr = NULL;
            //syscalls[ZwMapViewOfSectionF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwUnmapViewOfSection, func_name)) {
            syscalls[ZwUnmapViewOfSectionF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwUnmapViewOfSectionF].SSN, (uintptr_t*)&syscalls[ZwUnmapViewOfSectionF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwUnmapViewOfSectionF].sysretAddr = NULL;
            //syscalls[ZwUnmapViewOfSectionF].SSN = 0;
            syscall_entries++;
        }




        if (CompareStringASCII(str_ZwQuerySystemInformation, func_name)) {
            syscalls[ZwQuerySystemInformationF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwQuerySystemInformationF].SSN, (uintptr_t*)&syscalls[ZwQuerySystemInformationF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwQuerySystemInformationF].sysretAddr = NULL;
            //syscalls[ZwQuerySystemInformationF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwQueryObject, func_name)) {
            syscalls[ZwQueryObjectF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwQueryObjectF].SSN, (uintptr_t*)&syscalls[ZwQueryObjectF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwQueryObjectF].sysretAddr = NULL;
            //syscalls[ZwQueryObjectF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwDuplicateObject, func_name)) {
            syscalls[ZwDuplicateObjectF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwDuplicateObjectF].SSN, (uintptr_t*)&syscalls[ZwDuplicateObjectF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwDuplicateObjectF].sysretAddr = NULL;
            //syscalls[ZwDuplicateObjectF].SSN = 0;
            syscall_entries++;
        }





        if (CompareStringASCII(str_ZwOpenProcess, func_name)) {
            syscalls[ZwOpenProcessF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwOpenProcessF].SSN, (uintptr_t*)&syscalls[ZwOpenProcessF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwOpenProcessF].sysretAddr = NULL;
            //syscalls[ZwOpenProcessF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwCreateThreadEx, func_name)) {
            syscalls[ZwCreateThreadExF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwCreateThreadExF].SSN, (uintptr_t*)&syscalls[ZwCreateThreadExF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwCreateThreadExF].sysretAddr = NULL;
            //syscalls[ZwCreateThreadExF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwSetContextThread, func_name)) {
            syscalls[ZwSetContextThreadF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwSetContextThreadF].SSN, (uintptr_t*)&syscalls[ZwSetContextThreadF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwSetContextThreadF].sysretAddr = NULL;
            //syscalls[ZwSetContextThreadF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwGetContextThread, func_name)) {
            syscalls[ZwGetContextThreadF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwGetContextThreadF].SSN, (uintptr_t*)&syscalls[ZwGetContextThreadF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwGetContextThreadF].sysretAddr = NULL;
            //syscalls[ZwGetContextThreadF].SSN = 0;
            syscall_entries++;
        }





        if (CompareStringASCII(str_ZwReadVirtualMemory, func_name)) {
            syscalls[ZwReadVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwReadVirtualMemoryF].SSN, (uintptr_t*)&syscalls[ZwReadVirtualMemoryF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwReadVirtualMemoryF].sysretAddr = NULL;
            //syscalls[ZwReadVirtualMemoryF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwWriteVirtualMemory, func_name)) {
            syscalls[ZwWriteVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwWriteVirtualMemoryF].SSN, (uintptr_t*)&syscalls[ZwWriteVirtualMemoryF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwWriteVirtualMemoryF].sysretAddr = NULL;
            //syscalls[ZwWriteVirtualMemoryF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwAllocateVirtualMemory, func_name)) {
            syscalls[ZwAllocateVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwAllocateVirtualMemoryF].SSN, (uintptr_t*)&syscalls[ZwAllocateVirtualMemoryF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwAllocateVirtualMemoryF].sysretAddr = NULL;
            //syscalls[ZwAllocateVirtualMemoryF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwProtectVirtualMemory, func_name)) {
            syscalls[ZwProtectVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwProtectVirtualMemoryF].SSN, (uintptr_t*)&syscalls[ZwProtectVirtualMemoryF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwProtectVirtualMemoryF].sysretAddr = NULL;
            //syscalls[ZwProtectVirtualMemoryF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwQueryVirtualMemory, func_name)) {
            syscalls[ZwQueryVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwQueryVirtualMemoryF].SSN, (uintptr_t*)&syscalls[ZwQueryVirtualMemoryF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwQueryVirtualMemoryF].sysretAddr = NULL;
            //syscalls[ZwQueryVirtualMemoryF].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwFreeVirtualMemory, func_name)) {
            syscalls[ZwFreeVirtualMemoryF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwFreeVirtualMemoryF].SSN, (uintptr_t*)&syscalls[ZwFreeVirtualMemoryF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwFreeVirtualMemoryF].sysretAddr = NULL;
            //syscalls[ZwFreeVirtualMemoryF].SSN = 0;
            syscall_entries++;
        }





        if (CompareStringASCII(str_ZwOpenProcessToken, func_name)) {
            syscalls[ZwOpenProcessTokenF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwOpenProcessTokenF].SSN, (uintptr_t*)&syscalls[ZwOpenProcessTokenF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwOpenProcessToken].sysretAddr = NULL;
            //syscalls[ZwOpenProcessToken].SSN = 0;
            syscall_entries++;
        }

        if (CompareStringASCII(str_ZwAdjustPrivilegesToken, func_name)) {
            syscalls[ZwAdjustPrivilegesTokenF].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[ZwAdjustPrivilegesTokenF].SSN, (uintptr_t*)&syscalls[ZwAdjustPrivilegesTokenF].sysretAddr);
            if (!result) return result;
            //syscalls[ZwAdjustPrivilegesToken].sysretAddr = NULL;
            //syscalls[ZwAdjustPrivilegesToken].SSN = 0;
            syscall_entries++;
        }

    }

    return result;

}

