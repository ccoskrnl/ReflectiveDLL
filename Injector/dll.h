#pragma once
#include "framework.h"
#include <Windows.h>
#include <vector>

constexpr auto NT_HEADER_SIGNATURE_SIZE = 4;
constexpr auto FILE_HEADER_SIZE = 20;

class DLLParser
{
public:

	DLLParser() = default;
	//~DLLParser() = default;
	~DLLParser()
	{
		if (pe_sections != NULL)
			free(pe_sections);
	}

	bool initialize(const char* pebase, const size_t size);
	void* retrieve_func_raw_ptr(const char* func_name);
	uintptr_t resolve_jmp_to_actual_function(void* func_addr);
	byte_t* find_func_end(byte_t* func_raw_ptr);
	byte_t* get_base() { return (byte_t*)base; }
	size_t get_size() const { return size; }


private:

	PIMAGE_DOS_HEADER p_dos_header = nullptr;
	PIMAGE_NT_HEADERS p_nt_header = nullptr;
	//std::vector<PIMAGE_SECTION_HEADER> pe_sections;
	PIMAGE_SECTION_HEADER* pe_sections = nullptr;
	IMAGE_FILE_HEADER file_header{};
	IMAGE_OPTIONAL_HEADER optional_header{};

	PIMAGE_EXPORT_DIRECTORY p_export_dict = nullptr;
	dword_t* func_name_array = nullptr;
	dword_t* func_addr_array = nullptr;
	word_t* func_ordinal_array = nullptr;

	const char* base = nullptr;
	size_t size = 0;

};

