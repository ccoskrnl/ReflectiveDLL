#include "ntapi.h"
#include <Windows.h>

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


bool nt_api_init(HMODULE hm_ntdll, ntapi_syscall_ssn_t* syscall)
{

	bool result = false;
	PBYTE lib_base = (PBYTE)hm_ntdll;

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

	int zw_func_counter = 0;


	for (DWORD i = 0; i < p_img_export_dir->NumberOfFunctions; i++)
	{
        if (zw_func_counter >= NT_API_SYSCALL_COUNT)
            break;

		CHAR* func_name = (CHAR*)(lib_base + func_name_array[i]);
		if (strcmp(func_name, "NtOpenProcessToken") == 0) {
			PBYTE func_addr = (lib_base + func_addr_array[func_ordinal_array[i]]);
			result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscall[NtOpenProcessTokenIndex].ssn, (uintptr_t*)&syscall[NtOpenProcessTokenIndex].addr);
			if (!result) return false;
			else zw_func_counter++;
		}
		//else if (strcmp(func_name, "LsaLookupPrivilegeValue") == 0) {
		//	PBYTE func_addr = (lib_base + func_addr_array[func_ordinal_array[i]]);
		//	result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscall[LsaLookupPrivilegeValueIndex].ssn, (uintptr_t*)&syscall[LsaLookupPrivilegeValueIndex].addr);
		//	if (!result) return false;
		//	else zw_func_counter++;
		//}
		else if (strcmp(func_name, "NtAdjustPrivilegesToken") == 0) {
			PBYTE func_addr = (lib_base + func_addr_array[func_ordinal_array[i]]);
			result = extract_ssn_ret_addr(func_addr, (PDWORD)&syscall[NtAdjustPrivilegesTokenIndex].ssn, (uintptr_t*)&syscall[NtAdjustPrivilegesTokenIndex].addr);
			if (!result) return false;
			else zw_func_counter++;
		}
	}

    return true;
}