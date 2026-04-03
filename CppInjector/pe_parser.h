#pragma once

#include <Windows.h>
#include <vector>

constexpr auto NT_HEADER_SIGNATURE_SIZE = 4;
constexpr auto FILE_HEADER_SIZE = 20;

class pe_parser
{

private:

	PIMAGE_DOS_HEADER p_dos_header = nullptr;
	PIMAGE_NT_HEADERS p_nt_header = nullptr;
	PIMAGE_SECTION_HEADER* pe_sections = nullptr;
	IMAGE_FILE_HEADER file_header{};
	IMAGE_OPTIONAL_HEADER optional_header{};

	PIMAGE_EXPORT_DIRECTORY p_export_dict = nullptr;
	DWORD* func_name_array = nullptr;
	DWORD* func_addr_array = nullptr;
	WORD* func_ordinal_array = nullptr;

	const char* base = nullptr;
	size_t size = 0;


public:

	pe_parser() = default;
	~pe_parser()
	{
		if (pe_sections != NULL)
			free(pe_sections);
	}

	bool initialize(const char* pebase, const size_t size)
	{
		if (!pebase)
		{
			return false;
		}

		this->base = pebase;
		this->size = size;

		this->p_dos_header = (PIMAGE_DOS_HEADER)(base);
		if (this->p_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			return false;
		}

		this->p_nt_header = (PIMAGE_NT_HEADERS)(base + p_dos_header->e_lfanew);
		if (this->p_nt_header->Signature != IMAGE_NT_SIGNATURE) {
			return false;
		}

		file_header = p_nt_header->FileHeader;
		optional_header = p_nt_header->OptionalHeader;
		pe_sections = (PIMAGE_SECTION_HEADER*)malloc(sizeof(PIMAGE_SECTION_HEADER) * file_header.NumberOfSections);
		if (pe_sections == NULL)
			return false;

		for (int i = 0; i < file_header.NumberOfSections; i++)
		{
			/*
				Starting from the pointer to NT header + 4(signature) + 20(file header) + size of optional
				= pointer to first section header.

				to get to the next i multiply the index running through the number of sections multiplied
				by the size of section header.
			*/
			pe_sections[i] = ((PIMAGE_SECTION_HEADER)(
				((PBYTE)(p_nt_header)) + NT_HEADER_SIGNATURE_SIZE + FILE_HEADER_SIZE + file_header.SizeOfOptionalHeader
				+ (i * IMAGE_SIZEOF_SECTION_HEADER)));

		}

		p_export_dict = (PIMAGE_EXPORT_DIRECTORY)(base + rva2raw(optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));


		func_name_array = (DWORD*)(base + rva2raw(p_export_dict->AddressOfNames));
		func_addr_array = (DWORD*)(base + rva2raw(p_export_dict->AddressOfFunctions));
		func_ordinal_array = (WORD*)(base + rva2raw(p_export_dict->AddressOfNameOrdinals));

		return true;
	}

	uintptr_t rva2raw(uintptr_t rva) {

		for (int i = 0; i < file_header.NumberOfSections; i++) {
			// sections might have different offset, so we need to find the one where our RVA is falling into

			if (rva >= pe_sections[i]->VirtualAddress && rva < (static_cast<unsigned long long>(pe_sections[i]->VirtualAddress) + pe_sections[i]->Misc.VirtualSize)) {
				// so computing first the "distance" between the virtual beginning of the virtual section to the RVA
				// then adding that to the beginning of the same section but raw
				return (rva - pe_sections[i]->VirtualAddress) + pe_sections[i]->PointerToRawData;
			}

		}

		return NULL;
	}

	uintptr_t get_func_rva(const char* func_name)
	{
		uintptr_t exported_func_addr_rva = 0; 
		char* cfn = nullptr;

		for (DWORD i = 0; i < p_export_dict->NumberOfFunctions; i++)
		{
			cfn = (char*)(base + rva2raw(func_name_array[i]));
			if (strcmp(cfn, func_name) == 0) {
				exported_func_addr_rva = func_addr_array[i];
				break;
			}
		}

		return exported_func_addr_rva;
	}

	uintptr_t get_func_raw(const char* func_name)
	{
		uintptr_t func_raw = 0;
		uintptr_t func_rva = 0;
		func_rva = get_func_rva(func_name);
		if (func_rva == 0)
			return 0;
		func_raw = rva2raw(func_rva);
		return resolve_jmp_to_actual_function(func_raw);
	}


	/*
		If the first instruction of the exported function is jmp, the function will parse the address of 
		the jmp instruction and return the true address of the function. Otherwise, it will directly return 
		the function address.
	*/
	uintptr_t resolve_jmp_to_actual_function(uintptr_t func_addr)
	{
		if (!func_addr) return 0;

		BYTE* code = (BYTE*)(func_addr + (uintptr_t)base);

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

	DWORD get_func_size(const char* func_name)
	{
		uintptr_t func_rva = get_func_rva(func_name);
		uintptr_t func_end_rva = 0;

		PRUNTIME_FUNCTION p_runtime_func = (PRUNTIME_FUNCTION)(base + rva2raw(optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress));

		for (size_t i = 0; i < optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION); i++)
		{
			// Access the fields of each RUNTIME_FUNCTION structure
			if (p_runtime_func[i].BeginAddress == 0 && p_runtime_func[i].EndAddress == 0 && p_runtime_func[i].UnwindData == 0)
				continue;

			if (p_runtime_func[i].BeginAddress == func_rva) {

				func_end_rva = p_runtime_func[i].EndAddress;
				break;
			}

		}
		if (func_end_rva == 0)
			return 0;

		return (DWORD)(func_end_rva - func_rva);

	}


	BYTE* get_base() { return (BYTE*)base; }
	size_t get_size() const { return size; }


};
