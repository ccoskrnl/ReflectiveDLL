#include "framework.h"
#include "misc.h"

DWORD rva2raw(DWORD rva, PIMAGE_FILE_HEADER file_header, PIMAGE_SECTION_HEADER* pe_sections) {

	for (int i = 0; i < file_header->NumberOfSections; i++)
	{
		if (rva >= pe_sections[i]->VirtualAddress && rva < (unsigned long long)(pe_sections[i]->VirtualAddress) + pe_sections[i]->Misc.VirtualSize)
		{
			return (rva - pe_sections[i]->VirtualAddress) + pe_sections[i]->PointerToRawData;
		}

	}

	return 0;
}

/*
	If the first instruction of the exported function is jmp, the function will parse the address of
	the jmp instruction and return the true address of the function. Otherwise, it will directly return
	the function address.
*/
uintptr_t resolve_jmp_to_actual_function(uintptr_t func_addr, const char* pebase)
{
	if (!func_addr) return 0;

	BYTE* code = (BYTE*)(func_addr + (uintptr_t)pebase);

	// relative jmp
	if (code[0] == 0xE9)
	{
		int32_t relative_offset = *(int32_t*)(code + 1);

		uintptr_t next_instruction = ((uintptr_t)func_addr + 5);
		uintptr_t real_func_addr = ((uintptr_t)next_instruction + relative_offset);

		return real_func_addr;
	}

	// indirect jmp
	if (code[0] == 0xff && code[1] == 0x25)
	{
		// x64: FF 25 [32bits relative offset]
		uint32_t relative_offset = *(int32_t*)(code + 2);
		// 6 = FF25(2) + offset(4)
		uintptr_t next_inst = func_addr + 6;
		uintptr_t real_func_addr = next_inst + relative_offset;

		return real_func_addr;
	}

	return (uintptr_t)func_addr;

}

DWORD get_rva_of_actual_export_func(DWORD func_raw, DWORD func_rva, const char* pebase) {
	if (!func_raw) return 0;
	BYTE* code = (BYTE*)(func_raw + (uintptr_t)pebase);
	// relative jmp
	if (code[0] == 0xE9)
	{
		int32_t relative_offset = *(int32_t*)(code + 1);

		uintptr_t next_instruction = ((uintptr_t)func_rva + 5);
		uintptr_t real_func_addr = ((uintptr_t)next_instruction + relative_offset);

		return real_func_addr;
	}

	// indirect jmp
	if (code[0] == 0xff && code[1] == 0x25)
	{
		// x64: FF 25 [32bits relative offset]
		uint32_t relative_offset = *(int32_t*)(code + 2);
		// 6 = FF25(2) + offset(4)
		uintptr_t next_inst = func_rva + 6;
		uintptr_t real_func_addr = next_inst + relative_offset;

		return real_func_addr;
	}
	return func_rva;
}

DWORD64 get_raw_and_size(const char* pebase)
{

	if (!pebase)
	{
		return 0;
	}

	PIMAGE_DOS_HEADER p_dos_header = NULL;
	PIMAGE_NT_HEADERS p_nt_header = NULL;
	PIMAGE_SECTION_HEADER pe_sections[20];
	IMAGE_FILE_HEADER file_header;
	IMAGE_OPTIONAL_HEADER optional_header;

	PIMAGE_EXPORT_DIRECTORY p_export_dict = NULL;
	DWORD* func_name_array = NULL;
	DWORD* func_addr_array = NULL;
	WORD* func_ordinal_array = NULL;

	p_dos_header = (PIMAGE_DOS_HEADER)pebase;
	if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	p_nt_header = (PIMAGE_NT_HEADERS)(pebase + p_dos_header->e_lfanew);
	if (p_nt_header->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	file_header = p_nt_header->FileHeader;
	optional_header = p_nt_header->OptionalHeader;

	if (file_header.NumberOfSections >= 20)
		return 0;

	for (int i = 0; i < file_header.NumberOfSections; i++)
	{
		/*
			Starting from the pointer to NT header + 4(signature) + 20(file header) + size of optional
			= pointer to first section header.

			to get to the next i multiply the index running through the number of sections multiplied
			by the size of section header.
		*/
		pe_sections[i] = ((PIMAGE_SECTION_HEADER)(
			((PBYTE)(p_nt_header)) + 4 + 20 + file_header.SizeOfOptionalHeader + (i * IMAGE_SIZEOF_SECTION_HEADER)));

	}

	p_export_dict = (PIMAGE_EXPORT_DIRECTORY)(pebase + rva2raw(optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &file_header, pe_sections));
	func_name_array = (DWORD*)(pebase + rva2raw(p_export_dict->AddressOfNames, &file_header, pe_sections));
	func_addr_array = (DWORD*)(pebase + rva2raw(p_export_dict->AddressOfFunctions, &file_header, pe_sections));
	func_ordinal_array = (WORD*)(pebase + rva2raw(p_export_dict->AddressOfNameOrdinals, &file_header, pe_sections));



	// Get yolo' raw
	CHAR str_yolo[] = { 'y', 'o', 'l', 'o', '\0' };

	DWORD wrapper_func_rva = 0;
	DWORD actual_func_rva = 0;
	char* cfn = NULL;
	for (DWORD i = 0; i < p_export_dict->NumberOfFunctions; i++)
	{
		cfn = (char*)(pebase + rva2raw(func_name_array[i], &file_header, pe_sections));
		if (custom_strcmp(cfn, str_yolo) == 0) {
			wrapper_func_rva = func_addr_array[i];
			break;
		}
	}
	
	if (wrapper_func_rva == 0)
		return 0;
	DWORD wrapper_func_raw = rva2raw(wrapper_func_rva, &file_header, pe_sections);
	DWORD actual_func_raw = resolve_jmp_to_actual_function(wrapper_func_raw, pebase);
	actual_func_rva = get_rva_of_actual_export_func(wrapper_func_raw, wrapper_func_rva, pebase);



	// Get yolo' size
	DWORD target_func_rva = actual_func_rva;
	DWORD target_func_end_rva = 0;
	DWORD target_func_size = 0;

	PRUNTIME_FUNCTION p_runtime_func = (PRUNTIME_FUNCTION)(pebase + rva2raw(optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, &file_header, pe_sections));
	for (size_t i = 0; i < optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION); i++)
	{
		// Access the fields of each RUNTIME_FUNCTION structure
		if (p_runtime_func[i].BeginAddress == 0 && p_runtime_func[i].EndAddress == 0 && p_runtime_func[i].UnwindData == 0)
			continue;

		if (p_runtime_func[i].BeginAddress == target_func_rva) {

			target_func_end_rva = p_runtime_func[i].EndAddress;
			break;
		}

	}
	if (target_func_end_rva == 0)
		return 0;

	target_func_size = target_func_end_rva - target_func_rva;

	return (DWORD64)(((DWORD64)target_func_size << 32) | ((DWORD)actual_func_raw));

}