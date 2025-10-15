#include "framework.h"
#include "dll.h"

static dword_t rva2raw(dword_t rva, const std::vector<PIMAGE_SECTION_HEADER>& pe_sections, int num_of_secs) {

	for (int i = 0; i < num_of_secs; i++) {
		// sections might have different offset, so we need to find the one where our RVA is falling into

		if (rva >= pe_sections[i]->VirtualAddress && rva < (static_cast<unsigned long long>(pe_sections[i]->VirtualAddress) + pe_sections[i]->Misc.VirtualSize)) {
			// so computing first the "distance" between the virtual beginning of the virtual section to the RVA
			// then adding that to the beginning of the same section but raw
			return (rva - pe_sections[i]->VirtualAddress) + pe_sections[i]->PointerToRawData;
		}

	}

	return NULL;
}

bool DLLParser::initialize(const char* pebase, const size_t size)
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


	for (int i = 0; i < file_header.NumberOfSections; i++)
	{
		/* 
			Starting from the pointer to NT header + 4(signature) + 20(file header) + size of optional
			= pointer to first section header.

			to get to the next i multiply the index running through the number of sections multiplied 
			by the size of section header.
		*/

		pe_sections.push_back(
			(PIMAGE_SECTION_HEADER)(
				((PBYTE)(p_nt_header)) + NT_HEADER_SIGNATURE_SIZE + FILE_HEADER_SIZE + file_header.SizeOfOptionalHeader
				+ (i * IMAGE_SIZEOF_SECTION_HEADER))
		);

	}

	p_export_dict = (PIMAGE_EXPORT_DIRECTORY)(base + rva2raw(
		optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
		pe_sections,
		(int)file_header.NumberOfSections
	));


	func_name_array = (dword_t*)(base + rva2raw(p_export_dict->AddressOfNames, pe_sections, (int)file_header.NumberOfSections));
	func_addr_array = (dword_t*)(base + rva2raw(p_export_dict->AddressOfFunctions, pe_sections, (int)file_header.NumberOfSections));
	func_ordinal_array = (word_t*)(base + rva2raw(p_export_dict->AddressOfNameOrdinals, pe_sections, (int)file_header.NumberOfSections));

	return true;
}

void* DLLParser::retrieve_func_raw_ptr(const char* func_name)
{

	void* exported_func_addr_rva = nullptr;

	char* cfn = nullptr;

	for (dword_t i = 0; i < p_export_dict->NumberOfFunctions; i++)
	{
		cfn = (char*)(base + rva2raw(func_name_array[i], pe_sections, (int)file_header.NumberOfSections));
		if (strcmp(cfn, func_name) == 0) {
			exported_func_addr_rva = (void*)rva2raw(func_addr_array[i], pe_sections, (int)file_header.NumberOfSections);
			break;
		}
	}

	return (void*)(resolve_jmp_to_actual_function((void*)((uintptr_t)base + (uintptr_t)exported_func_addr_rva)) - (uintptr_t)base);
}

uintptr_t DLLParser::resolve_jmp_to_actual_function(void* func_addr)
{
	if (!func_addr) return 0;

	byte_t* code = (byte_t*)func_addr;

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

byte_t* DLLParser::find_func_end(byte_t* func_raw_ptr)
{

	PRUNTIME_FUNCTION p_runtime_func = (PRUNTIME_FUNCTION)(
		base + 
		rva2raw(optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress
			, pe_sections
			, (int)file_header.NumberOfSections));

	for (size_t i = 0; i < optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION); i++)
	{
		// Access the fields of each RUNTIME_FUNCTION structure
		if (p_runtime_func[i].BeginAddress == 0 && p_runtime_func[i].EndAddress == 0 && p_runtime_func[i].UnwindData == 0)
			continue;

		if ((byte_t*)rva2raw(p_runtime_func[i].BeginAddress, pe_sections, (int)file_header.NumberOfSections) == func_raw_ptr) {

			return (byte_t*)(rva2raw(p_runtime_func[i].EndAddress - 1, pe_sections, (int)file_header.NumberOfSections));
		}

	}

	return nullptr;
}


