#include "framework.h"
#include "pch.h"
#include "utils.h"
#include "utils_headers.h"
#include "headers.h"
#include "sleaping.h"
#include <stdlib.h>
#include <stdint.h>

bool load_nt_functions(PNT_FUNCTIONS nt_funcs)
{

	if (nt_funcs == NULL)
	{
		return false;
	}

	// Load the ntdll.dll library
	HMODULE hm_ntdll = GetModuleHandleA("ntdll.dll");
	if (hm_ntdll == NULL)
	{

		return false;
	}

	nt_funcs->NtWaitForSingleObject = (NtWaitForSingleObjectFunc)GetProcAddress(hm_ntdll, "NtWaitForSingleObject");//
	nt_funcs->NtQueueApcThread = (NtQueueApcThreadFunc)GetProcAddress(hm_ntdll, "NtQueueApcThread");//
	nt_funcs->NtGetContextThread = (NtGetContextThreadFunc)GetProcAddress(hm_ntdll, "NtGetContextThread");//
	nt_funcs->NtSetContextThread = (NtSetContextThreadFunc)GetProcAddress(hm_ntdll, "NtSetContextThread");//
	nt_funcs->NtCreateThreadEx = (NtCreateThreadExFunc)GetProcAddress(hm_ntdll, "NtCreateThreadEx"); // Added
	nt_funcs->NtCreateEvent = (NtCreateEventFunc)GetProcAddress(hm_ntdll, "NtCreateEvent");
	nt_funcs->NtResumeThread = (NtResumeThreadFunc)GetProcAddress(hm_ntdll, "NtResumeThread");//
	nt_funcs->NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hm_ntdll, "NtQuerySystemInformation");
	nt_funcs->NtQueryObject = (NtQueryObjectFunc)GetProcAddress(hm_ntdll, "NtQueryObject");
	nt_funcs->NtQueryInformationWorkerFactory = (NtQueryInformationWorkerFactoryFunc)GetProcAddress(hm_ntdll, "NtQueryInformationWorkerFactory");
	nt_funcs->NtTestAlert = (NtTestAlertFunc)GetProcAddress(hm_ntdll, "NtTestAlert");

	// Check if all function addresses were retrieved successfully
	if (!nt_funcs->NtResumeThread || !nt_funcs->NtWaitForSingleObject || !nt_funcs->NtQueueApcThread ||
		!nt_funcs->NtGetContextThread || !nt_funcs->NtSetContextThread || !nt_funcs->NtCreateThreadEx || !nt_funcs->NtCreateEvent
		|| !nt_funcs->NtQueryInformationWorkerFactory || !nt_funcs->NtQueryObject || !nt_funcs->NtQuerySystemInformation || !nt_funcs->NtTestAlert) // Modified
	{

		return false;
	}

	return true;

}


// ==================== GDI32 函数加载 ====================
bool load_gdi32_functions(gdi32_functions_t* gdi_funcs)
{
	if (gdi_funcs == NULL)
	{
		return false;
	}

	// 加载 gdi32.dll
	gdi_funcs->hGDI32 = LoadLibraryA("gdi32.dll");

	if (gdi_funcs->hGDI32 == NULL)
	{
		return false;
	}

	// 获取函数地址
	gdi_funcs->CreateCompatibleDC = (CREATECOMPATIBLEDC_FN)GetProcAddress(gdi_funcs->hGDI32, "CreateCompatibleDC");
	gdi_funcs->DeleteDC = (DELETEDC_FN)GetProcAddress(gdi_funcs->hGDI32, "DeleteDC");
	gdi_funcs->CreateCompatibleBitmap = (CREATECOMPATIBLEBITMAP_FN)GetProcAddress(gdi_funcs->hGDI32, "CreateCompatibleBitmap");
	gdi_funcs->SelectObject = (SELECTOBJECT_FN)GetProcAddress(gdi_funcs->hGDI32, "SelectObject");
	gdi_funcs->BitBlt = (BITBLT_FN)GetProcAddress(gdi_funcs->hGDI32, "BitBlt");
	gdi_funcs->GetDIBits = (GETDIBITS_FN)GetProcAddress(gdi_funcs->hGDI32, "GetDIBits");
	gdi_funcs->DeleteObject = (DELETEOBJECT_FN)GetProcAddress(gdi_funcs->hGDI32, "DeleteObject");


	uint64_t* funcs_start = (uint64_t*)gdi_funcs;
	int num = sizeof(*gdi_funcs) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			unload_gdi32_functions(gdi_funcs);
			return false;
		}
	}

	return true;
}

void unload_gdi32_functions(gdi32_functions_t* gdi_funcs)
{
	if (gdi_funcs != NULL)
	{
		if (gdi_funcs->hGDI32 != NULL)
		{
			FreeLibrary(gdi_funcs->hGDI32);
			gdi_funcs->hGDI32 = NULL;
		}

		// 清空所有函数指针
		gdi_funcs->CreateCompatibleDC = NULL;
		gdi_funcs->DeleteDC = NULL;
		gdi_funcs->CreateCompatibleBitmap = NULL;
		gdi_funcs->SelectObject = NULL;
		gdi_funcs->BitBlt = NULL;
		gdi_funcs->GetDIBits = NULL;
		gdi_funcs->DeleteObject = NULL;
	}
}


// ==================== USER32 函数加载 ====================
bool load_user32_functions(user32_functions_t* user_funcs)
{
	if (user_funcs == NULL)
	{
		return false;
	}

	// 加载 user32.dll
	user_funcs->hUser32 = LoadLibraryA("user32.dll");
	if (user_funcs->hUser32 == NULL)
	{
		return false;
	}

	// 获取函数地址
	user_funcs->GetDC = (GETDC_FN)GetProcAddress(user_funcs->hUser32, "GetDC");
	user_funcs->ReleaseDC = (RELEASEDC_FN)GetProcAddress(user_funcs->hUser32, "ReleaseDC");
	user_funcs->GetSystemMetrics = (GETSYSTEMMETRICS_FN)GetProcAddress(user_funcs->hUser32, "GetSystemMetrics");
	user_funcs->GetCursorPos = (GETCURSORPOS_FN)GetProcAddress(user_funcs->hUser32, "GetCursorPos");
	user_funcs->GetWindowRect = (GETWINDOWRECT_FN)GetProcAddress(user_funcs->hUser32, "GetWindowRect");
	user_funcs->GetDesktopWindow = (GETDESKTOPWINDOW_FN)GetProcAddress(user_funcs->hUser32, "GetDesktopWindow");
	user_funcs->GetForegroundWindow = (GETFOREGROUNDWINDOW_FN)GetProcAddress(user_funcs->hUser32, "GetForegroundWindow");


	uint64_t* funcs_start = (uint64_t*)user_funcs;
	int num = sizeof(*user_funcs) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			unload_user32_functions(user_funcs);
			return false;
		}
	}

	return true;
}

void unload_user32_functions(user32_functions_t* user_funcs)
{
	if (user_funcs != NULL)
	{
		if (user_funcs->hUser32 != NULL)
		{
			FreeLibrary(user_funcs->hUser32);
			user_funcs->hUser32 = NULL;
		}

		// 清空所有函数指针
		user_funcs->GetDC = NULL;
		user_funcs->ReleaseDC = NULL;
		user_funcs->GetSystemMetrics = NULL;
		user_funcs->GetCursorPos = NULL;
		user_funcs->GetWindowRect = NULL;
		user_funcs->GetDesktopWindow = NULL;
		user_funcs->GetForegroundWindow = NULL;
	}
}


// ==================== KERNEL32 函数加载 ====================
bool load_kernel32_functions(kernel32_functions_t* kernel_funcs)
{
	if (kernel_funcs == NULL)
	{
		return false;
	}

	// 加载 kernel32.dll
	kernel_funcs->hKernel32 = LoadLibraryA("kernel32.dll");
	if (kernel_funcs->hKernel32 == NULL)
	{
		return false;
	}

	kernel_funcs->GetLastError = (GETLASTERROR_FN)GetProcAddress(kernel_funcs->hKernel32, "GetLastError");

	// 获取基础函数地址
	kernel_funcs->Sleep = (SLEEP_FN)GetProcAddress(kernel_funcs->hKernel32, "Sleep");
	kernel_funcs->GetTickCount = (GETTICKCOUNT_FN)GetProcAddress(kernel_funcs->hKernel32, "GetTickCount");
	kernel_funcs->QueryPerformanceCounter = (QUERYPERFORMANCECOUNTER_FN)GetProcAddress(kernel_funcs->hKernel32, "QueryPerformanceCounter");
	kernel_funcs->QueryPerformanceFrequency = (QUERYPERFORMANCEFREQUENCY_FN)GetProcAddress(kernel_funcs->hKernel32, "QueryPerformanceFrequency");
	kernel_funcs->LocalLock = (LOCALLOCK_FN)GetProcAddress(kernel_funcs->hKernel32, "LocalLock");
	kernel_funcs->LocalUnlock = (LOCALUNLOCK_FN)GetProcAddress(kernel_funcs->hKernel32, "LocalUnlock");
	kernel_funcs->LocalFree = (LOCALFREE_FN)GetProcAddress(kernel_funcs->hKernel32, "LocalFree");

	// 获取文件操作函数地址
	kernel_funcs->CreateFileA = (CREATEFILE_FN)GetProcAddress(kernel_funcs->hKernel32, "CreateFileA");
	kernel_funcs->WriteFile = (WRITEFILE_FN)GetProcAddress(kernel_funcs->hKernel32, "WriteFile");
	kernel_funcs->ReadFile = (READFILE_FN)GetProcAddress(kernel_funcs->hKernel32, "ReadFile");
	kernel_funcs->CloseHandle = (CLOSEHANDLE_FN)GetProcAddress(kernel_funcs->hKernel32, "CloseHandle");
	kernel_funcs->GetFileSize = (GETFILESIZE_FN)GetProcAddress(kernel_funcs->hKernel32, "GetFileSize");
	kernel_funcs->SetFilePointer = (SETFILEPOINTER_FN)GetProcAddress(kernel_funcs->hKernel32, "SetFilePointer");
	kernel_funcs->FlushFileBuffers = (FLUSHFILEBUFFERS_FN)GetProcAddress(kernel_funcs->hKernel32, "FlushFileBuffers");

	kernel_funcs->GetTempPathA = (GETTEMPPATHA_FN)GetProcAddress(kernel_funcs->hKernel32, "GetTempPathA");
	kernel_funcs->DeleteFileA = (DELETEFILEA_FN)GetProcAddress(kernel_funcs->hKernel32, "DeleteFileA");

	uint64_t* funcs_start = (uint64_t*)kernel_funcs;
	int num = sizeof(*kernel_funcs) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			unload_kernel32_functions(kernel_funcs);
			return false;
		}
	}

	return true;
}

void unload_kernel32_functions(kernel32_functions_t* kernel_funcs)
{
	if (kernel_funcs != NULL)
	{
		if (kernel_funcs->hKernel32 != NULL)
		{
			FreeLibrary(kernel_funcs->hKernel32);
			kernel_funcs->hKernel32 = NULL;
		}

		kernel_funcs->GetLastError = NULL;

		// 清空所有函数指针
		kernel_funcs->Sleep = NULL;
		kernel_funcs->GetTickCount = NULL;
		kernel_funcs->QueryPerformanceCounter = NULL;
		kernel_funcs->QueryPerformanceFrequency = NULL;
		kernel_funcs->LocalLock = NULL;
		kernel_funcs->LocalUnlock = NULL;
		kernel_funcs->LocalFree = NULL;

		kernel_funcs->CreateFileA = NULL;
		kernel_funcs->WriteFile = NULL;
		kernel_funcs->ReadFile = NULL;
		kernel_funcs->CloseHandle = NULL;
		kernel_funcs->GetFileSize = NULL;
		kernel_funcs->SetFilePointer = NULL;
		kernel_funcs->FlushFileBuffers = NULL;

		kernel_funcs->GetTempPathA = NULL;
		kernel_funcs->DeleteFileA = NULL;
	}
}


// ==================== Winsock 函数加载 ====================
bool load_winsock_functions(winsock_functions_t* ws_funcs)
{
	if (ws_funcs == NULL)
	{
		return false;
	}

	HMODULE winsock_dll = NULL;
	winsock_dll = LoadLibraryA("ws2_32.dll");
	if (winsock_dll == NULL)
	{
		return false;
	}
	ws_funcs->hWinsock = winsock_dll;

	ws_funcs->WSAGetLastError = (WSAGETLASTERROR_FN)GetProcAddress(winsock_dll, "WSAGetLastError");
	ws_funcs->WSAStartup = (WSASTARTUP_FN)GetProcAddress(winsock_dll, "WSAStartup");
	ws_funcs->Socket = (SOCKET_FN)GetProcAddress(winsock_dll, "socket");
	ws_funcs->Connect = (CONNECT_FN)GetProcAddress(winsock_dll, "connect");
	ws_funcs->Send = (SEND_FN)GetProcAddress(winsock_dll, "send");
	ws_funcs->Recv = (RECV_FN)GetProcAddress(winsock_dll, "recv");
	ws_funcs->CloseSocket = (CLOSESOCKET_FN)GetProcAddress(winsock_dll, "closesocket");
	ws_funcs->WSACleanup = (WSACLEANUP_FN)GetProcAddress(winsock_dll, "WSACleanup");
	ws_funcs->Bind = (BIND_FN)GetProcAddress(winsock_dll, "bind");
	ws_funcs->Listen = (LISTEN_FN)GetProcAddress(winsock_dll, "listen");
	ws_funcs->Accept = (ACCEPT_FN)GetProcAddress(winsock_dll, "accept");
	ws_funcs->Htons = (HTONS_FN)GetProcAddress(winsock_dll, "htons");
	ws_funcs->Inet_addr = (INET_ADDR_FN)GetProcAddress(winsock_dll, "inet_addr");
	ws_funcs->Inet_ntoa = (INET_NTOA_FN)GetProcAddress(winsock_dll, "inet_ntoa");
	ws_funcs->Inet_pton = (INET_PTON_FN)GetProcAddress(winsock_dll, "inet_pton");
	ws_funcs->ioctlsocket = (IOCTLSOCKET_FN)GetProcAddress(winsock_dll, "ioctlsocket");
	ws_funcs->setsockopt = (SETSOCKOPT_FN)GetProcAddress(winsock_dll, "setsockopt");
	ws_funcs->select = (SELECT_FN)GetProcAddress(winsock_dll, "select");

	uint64_t* funcs_start = (uint64_t*)ws_funcs;
	int num = sizeof(*ws_funcs) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			unload_winsock_functions(ws_funcs);
			return false;
		}
	}

	return true;
}

void unload_winsock_functions(winsock_functions_t* ws_funcs)
{
	if (ws_funcs != NULL)
	{
		if (ws_funcs->hWinsock != NULL)
		{
			FreeLibrary(ws_funcs->hWinsock);
			ws_funcs->hWinsock = NULL;
		}

		// 清空所有函数指针
		ws_funcs->WSAGetLastError = NULL;

		ws_funcs->WSAStartup = NULL;
		ws_funcs->Socket = NULL;
		ws_funcs->Connect = NULL;
		ws_funcs->Send = NULL;
		ws_funcs->Recv = NULL;
		ws_funcs->CloseSocket = NULL;
		ws_funcs->WSACleanup = NULL;
		ws_funcs->Bind = NULL;
		ws_funcs->Listen = NULL;
		ws_funcs->Accept = NULL;
		ws_funcs->Htons = NULL;
		ws_funcs->Inet_addr = NULL;
		ws_funcs->Inet_ntoa = NULL;
		ws_funcs->Inet_pton = NULL;

		ws_funcs->setsockopt = NULL;
		ws_funcs->ioctlsocket = NULL;
		ws_funcs->select = NULL;
	}
}
