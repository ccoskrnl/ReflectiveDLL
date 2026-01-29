#include "pch.h"
#include "framework.h"
#include "headers.h"
#include "dll_headers.h"
#include <stdlib.h>
#include <stdint.h>

bool load_nt_functions(PNT_FUNCTIONS nt)
{

	if (nt == NULL)
	{
		return false;
	}

	// Load the ntdll.dll library
	HMODULE hm_ntdll = GetModuleHandleA("ntdll.dll");
	if (hm_ntdll == NULL)
	{

		return false;
	}

	nt->NtWaitForSingleObject = (NtWaitForSingleObjectFunc)GetProcAddress(hm_ntdll, "NtWaitForSingleObject");//
	nt->NtQueueApcThread = (NtQueueApcThreadFunc)GetProcAddress(hm_ntdll, "NtQueueApcThread");//
	nt->NtGetContextThread = (NtGetContextThreadFunc)GetProcAddress(hm_ntdll, "NtGetContextThread");//
	nt->NtSetContextThread = (NtSetContextThreadFunc)GetProcAddress(hm_ntdll, "NtSetContextThread");//
	nt->NtCreateThreadEx = (NtCreateThreadExFunc)GetProcAddress(hm_ntdll, "NtCreateThreadEx"); // Added
	nt->NtCreateEvent = (NtCreateEventFunc)GetProcAddress(hm_ntdll, "NtCreateEvent");
	nt->NtResumeThread = (NtResumeThreadFunc)GetProcAddress(hm_ntdll, "NtResumeThread");//
	nt->NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hm_ntdll, "NtQuerySystemInformation");
	nt->NtQueryObject = (NtQueryObjectFunc)GetProcAddress(hm_ntdll, "NtQueryObject");
	nt->NtQueryInformationWorkerFactory = (NtQueryInformationWorkerFactoryFunc)GetProcAddress(hm_ntdll, "NtQueryInformationWorkerFactory");
	nt->NtTestAlert = (NtTestAlertFunc)GetProcAddress(hm_ntdll, "NtTestAlert");

	// Check if all function addresses were retrieved successfully
	if (!nt->NtResumeThread || !nt->NtWaitForSingleObject || !nt->NtQueueApcThread ||
		!nt->NtGetContextThread || !nt->NtSetContextThread || !nt->NtCreateThreadEx || !nt->NtCreateEvent
		|| !nt->NtQueryInformationWorkerFactory || !nt->NtQueryObject || !nt->NtQuerySystemInformation || !nt->NtTestAlert) // Modified
	{

		return false;
	}

	return true;

}


// ==================== GDI32 函数加载 ====================
bool load_gdi32_functions(gdi32_functions_t* gdi32)
{
	if (gdi32 == NULL)
	{
		return false;
	}

	// 加载 gdi32.dll
	gdi32->hGDI32 = LoadLibraryA("gdi32.dll");

	if (gdi32->hGDI32 == NULL)
	{
		return false;
	}

	// 获取函数地址
	gdi32->CreateCompatibleDC = (CREATECOMPATIBLEDC_FN)GetProcAddress(gdi32->hGDI32, "CreateCompatibleDC");
	gdi32->DeleteDC = (DELETEDC_FN)GetProcAddress(gdi32->hGDI32, "DeleteDC");
	gdi32->CreateCompatibleBitmap = (CREATECOMPATIBLEBITMAP_FN)GetProcAddress(gdi32->hGDI32, "CreateCompatibleBitmap");
	gdi32->SelectObject = (SELECTOBJECT_FN)GetProcAddress(gdi32->hGDI32, "SelectObject");
	gdi32->BitBlt = (BITBLT_FN)GetProcAddress(gdi32->hGDI32, "BitBlt");
	gdi32->GetDIBits = (GETDIBITS_FN)GetProcAddress(gdi32->hGDI32, "GetDIBits");
	gdi32->DeleteObject = (DELETEOBJECT_FN)GetProcAddress(gdi32->hGDI32, "DeleteObject");


	uint64_t* funcs_start = (uint64_t*)gdi32;
	int num = sizeof(*gdi32) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			unload_gdi32_functions(gdi32);
			return false;
		}
	}

	return true;
}

void unload_gdi32_functions(gdi32_functions_t* gdi32)
{
	if (gdi32 != NULL)
	{
		if (gdi32->hGDI32 != NULL)
		{
			FreeLibrary(gdi32->hGDI32);
			gdi32->hGDI32 = NULL;
		}

		// 清空所有函数指针
		gdi32->CreateCompatibleDC = NULL;
		gdi32->DeleteDC = NULL;
		gdi32->CreateCompatibleBitmap = NULL;
		gdi32->SelectObject = NULL;
		gdi32->BitBlt = NULL;
		gdi32->GetDIBits = NULL;
		gdi32->DeleteObject = NULL;
	}
}


// ==================== USER32 函数加载 ====================
bool load_user32_functions(user32_functions_t* user32)
{
	if (user32 == NULL)
	{
		return false;
	}

	// 加载 user32.dll
	user32->hUser32 = LoadLibraryA("user32.dll");
	if (user32->hUser32 == NULL)
	{
		return false;
	}

	// 获取函数地址
	user32->GetDC = (GETDC_FN)GetProcAddress(user32->hUser32, "GetDC");
	user32->ReleaseDC = (RELEASEDC_FN)GetProcAddress(user32->hUser32, "ReleaseDC");
	user32->GetSystemMetrics = (GETSYSTEMMETRICS_FN)GetProcAddress(user32->hUser32, "GetSystemMetrics");
	user32->GetCursorPos = (GETCURSORPOS_FN)GetProcAddress(user32->hUser32, "GetCursorPos");
	user32->GetWindowRect = (GETWINDOWRECT_FN)GetProcAddress(user32->hUser32, "GetWindowRect");
	user32->GetDesktopWindow = (GETDESKTOPWINDOW_FN)GetProcAddress(user32->hUser32, "GetDesktopWindow");
	user32->GetForegroundWindow = (GETFOREGROUNDWINDOW_FN)GetProcAddress(user32->hUser32, "GetForegroundWindow");


	uint64_t* funcs_start = (uint64_t*)user32;
	int num = sizeof(*user32) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			unload_user32_functions(user32);
			return false;
		}
	}

	return true;
}

void unload_user32_functions(user32_functions_t* user32)
{
	if (user32 != NULL)
	{
		if (user32->hUser32 != NULL)
		{
			FreeLibrary(user32->hUser32);
			user32->hUser32 = NULL;
		}

		// 清空所有函数指针
		user32->GetDC = NULL;
		user32->ReleaseDC = NULL;
		user32->GetSystemMetrics = NULL;
		user32->GetCursorPos = NULL;
		user32->GetWindowRect = NULL;
		user32->GetDesktopWindow = NULL;
		user32->GetForegroundWindow = NULL;
	}
}


// ==================== KERNEL32 函数加载 ====================
bool load_kernel32_functions(kernel32_functions_t* kernel32)
{
	if (kernel32 == NULL)
	{
		return false;
	}

	// 加载 kernel32.dll
	kernel32->hKernel32 = LoadLibraryA("kernel32.dll");
	if (kernel32->hKernel32 == NULL)
	{
		return false;
	}

	kernel32->GetLastError = (GETLASTERROR_FN)GetProcAddress(kernel32->hKernel32, "GetLastError");

	// 获取基础函数地址
	kernel32->Sleep = (SLEEP_FN)GetProcAddress(kernel32->hKernel32, "Sleep");
	kernel32->GetTickCount = (GETTICKCOUNT_FN)GetProcAddress(kernel32->hKernel32, "GetTickCount");
	kernel32->QueryPerformanceCounter = (QUERYPERFORMANCECOUNTER_FN)GetProcAddress(kernel32->hKernel32, "QueryPerformanceCounter");
	kernel32->QueryPerformanceFrequency = (QUERYPERFORMANCEFREQUENCY_FN)GetProcAddress(kernel32->hKernel32, "QueryPerformanceFrequency");
	kernel32->LocalLock = (LOCALLOCK_FN)GetProcAddress(kernel32->hKernel32, "LocalLock");
	kernel32->LocalUnlock = (LOCALUNLOCK_FN)GetProcAddress(kernel32->hKernel32, "LocalUnlock");
	kernel32->LocalFree = (LOCALFREE_FN)GetProcAddress(kernel32->hKernel32, "LocalFree");

	// 获取文件操作函数地址
	kernel32->CreateFileA = (CREATEFILE_FN)GetProcAddress(kernel32->hKernel32, "CreateFileA");
	kernel32->WriteFile = (WRITEFILE_FN)GetProcAddress(kernel32->hKernel32, "WriteFile");
	kernel32->ReadFile = (READFILE_FN)GetProcAddress(kernel32->hKernel32, "ReadFile");
	kernel32->CloseHandle = (CLOSEHANDLE_FN)GetProcAddress(kernel32->hKernel32, "CloseHandle");
	kernel32->GetFileSize = (GETFILESIZE_FN)GetProcAddress(kernel32->hKernel32, "GetFileSize");
	kernel32->SetFilePointer = (SETFILEPOINTER_FN)GetProcAddress(kernel32->hKernel32, "SetFilePointer");
	kernel32->FlushFileBuffers = (FLUSHFILEBUFFERS_FN)GetProcAddress(kernel32->hKernel32, "FlushFileBuffers");

	kernel32->GetTempPathA = (GETTEMPPATHA_FN)GetProcAddress(kernel32->hKernel32, "GetTempPathA");
	kernel32->DeleteFileA = (DELETEFILEA_FN)GetProcAddress(kernel32->hKernel32, "DeleteFileA");

	uint64_t* funcs_start = (uint64_t*)kernel32;
	int num = sizeof(*kernel32) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			unload_kernel32_functions(kernel32);
			return false;
		}
	}

	return true;
}

void unload_kernel32_functions(kernel32_functions_t* kernel32)
{
	if (kernel32 != NULL)
	{
		if (kernel32->hKernel32 != NULL)
		{
			FreeLibrary(kernel32->hKernel32);
			kernel32->hKernel32 = NULL;
		}

		kernel32->GetLastError = NULL;

		// 清空所有函数指针
		kernel32->Sleep = NULL;
		kernel32->GetTickCount = NULL;
		kernel32->QueryPerformanceCounter = NULL;
		kernel32->QueryPerformanceFrequency = NULL;
		kernel32->LocalLock = NULL;
		kernel32->LocalUnlock = NULL;
		kernel32->LocalFree = NULL;

		kernel32->CreateFileA = NULL;
		kernel32->WriteFile = NULL;
		kernel32->ReadFile = NULL;
		kernel32->CloseHandle = NULL;
		kernel32->GetFileSize = NULL;
		kernel32->SetFilePointer = NULL;
		kernel32->FlushFileBuffers = NULL;

		kernel32->GetTempPathA = NULL;
		kernel32->DeleteFileA = NULL;
	}
}


// ==================== Winsock 函数加载 ====================
bool load_winsock_functions(winsock_functions_t* ws2)
{
	if (ws2 == NULL)
	{
		return false;
	}

	HMODULE winsock_dll = NULL;
	winsock_dll = LoadLibraryA("ws2_32.dll");
	if (winsock_dll == NULL)
	{
		return false;
	}
	ws2->hWinsock = winsock_dll;

	ws2->WSAGetLastError = (WSAGetLastError_FN)GetProcAddress(winsock_dll, "WSAGetLastError");
	ws2->WSAStartup = (WSAStartup_FN)GetProcAddress(winsock_dll, "WSAStartup");
	ws2->WSACleanup = (WSACLEANUP_FN)GetProcAddress(winsock_dll, "WSACleanup");
	ws2->WSASend = (WSASend_FN)GetProcAddress(winsock_dll, "WSASend");
	ws2->WSASocketA = (WSASocketA_FN)GetProcAddress(winsock_dll, "WSASocketA");
	ws2->WSARecv = (WSARecv_FN)GetProcAddress(winsock_dll, "WSARecv");
	ws2->WSAConnect = (WSAConnect_FN)GetProcAddress(winsock_dll, "WSAConnect");

	ws2->Socket = (SOCKET_FN)GetProcAddress(winsock_dll, "socket");
	ws2->Connect = (CONNECT_FN)GetProcAddress(winsock_dll, "connect");
	ws2->Send = (SEND_FN)GetProcAddress(winsock_dll, "send");
	ws2->Recv = (RECV_FN)GetProcAddress(winsock_dll, "recv");
	ws2->CloseSocket = (CLOSESOCKET_FN)GetProcAddress(winsock_dll, "closesocket");
	ws2->Bind = (BIND_FN)GetProcAddress(winsock_dll, "bind");
	ws2->Listen = (LISTEN_FN)GetProcAddress(winsock_dll, "listen");
	ws2->Accept = (ACCEPT_FN)GetProcAddress(winsock_dll, "accept");
	ws2->Htons = (HTONS_FN)GetProcAddress(winsock_dll, "htons");
	ws2->Inet_pton = (INET_PTON_FN)GetProcAddress(winsock_dll, "inet_pton");
	ws2->ioctlsocket = (IOCTLSOCKET_FN)GetProcAddress(winsock_dll, "ioctlsocket");
	ws2->setsockopt = (SETSOCKOPT_FN)GetProcAddress(winsock_dll, "setsockopt");
	ws2->select = (SELECT_FN)GetProcAddress(winsock_dll, "select");

	uint64_t* funcs_start = (uint64_t*)ws2;
	int num = sizeof(*ws2) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			unload_winsock_functions(ws2);
			return false;
		}
	}

	return true;
}

void unload_winsock_functions(winsock_functions_t* ws)
{
	if (ws != NULL)
	{
		if (ws->hWinsock != NULL)
		{
			FreeLibrary(ws->hWinsock);
			ws->hWinsock = NULL;
		}

		// 清空所有函数指针
		ws->WSAGetLastError = NULL;
		ws->WSAStartup = NULL;
		ws->WSACleanup = NULL;
		ws->WSAConnect = NULL;
		ws->WSARecv = NULL;
		ws->WSASend = NULL;
		ws->WSASocketA = NULL;

		ws->Socket = NULL;
		ws->Connect = NULL;
		ws->Send = NULL;
		ws->Recv = NULL;
		ws->CloseSocket = NULL;
		ws->Bind = NULL;
		ws->Listen = NULL;
		ws->Accept = NULL;
		ws->Htons = NULL;
		ws->Inet_pton = NULL;

		ws->setsockopt = NULL;
		ws->ioctlsocket = NULL;
		ws->select = NULL;
	}
}
