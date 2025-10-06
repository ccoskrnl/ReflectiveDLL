#pragma once
#include "framework.h"
#include <Windows.h>
#include <vector>

constexpr auto NT_HEADER_SIGNATURE_SIZE = 4;
constexpr auto FILE_HEADER_SIZE = 20;

class DLLParser
{
public:

	PIMAGE_DOS_HEADER p_dos_header = nullptr;
	PIMAGE_NT_HEADERS p_nt_header = nullptr;
	std::vector<PIMAGE_SECTION_HEADER> pe_sections;
	IMAGE_FILE_HEADER file_header;
	IMAGE_OPTIONAL_HEADER optional_header;

	PIMAGE_EXPORT_DIRECTORY p_export_dict = nullptr;
	dword_t* func_name_array = nullptr;
	dword_t* func_addr_array = nullptr;
	word_t* func_ordinal_array = nullptr;


	DLLParser() = default;
	~DLLParser() = default;

	bool initialize(const char* bytes);
	void* retrieve_func_raw_ptr(const char* func_name);


private:

	const char* base = nullptr;

};

