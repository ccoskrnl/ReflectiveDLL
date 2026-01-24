#pragma once

#include "pch.h"
#include "framework.h"
#include <winternl.h>

typedef HDC(WINAPI* CREATECOMPATIBLEDC_FN)(HDC hDC);
typedef BOOL(WINAPI* DELETEDC_FN)(HDC hDC);
typedef HBITMAP(WINAPI* CREATECOMPATIBLEBITMAP_FN)(HDC hDC, int cx, int cy);
typedef HGDIOBJ(WINAPI* SELECTOBJECT_FN)(HDC hDC, HGDIOBJ h);
typedef BOOL(WINAPI* BITBLT_FN)(HDC hdcDest, int xDest, int yDest, int wDest, int hDest,
	HDC hdcSrc, int xSrc, int ySrc, DWORD rop);
typedef int (WINAPI* GETDIBITS_FN)(HDC hdc, HBITMAP hbmp, UINT start, UINT cLines,
	LPVOID lpvBits, LPBITMAPINFO lpbmi, UINT usage);
typedef BOOL(WINAPI* DELETEOBJECT_FN)(HGDIOBJ hObject);

typedef struct _gdi32_functions
{
	CREATECOMPATIBLEDC_FN CreateCompatibleDC = NULL;
	DELETEDC_FN DeleteDC = NULL;
	CREATECOMPATIBLEBITMAP_FN CreateCompatibleBitmap = NULL;
	SELECTOBJECT_FN SelectObject = NULL;
	BITBLT_FN BitBlt = NULL;
	GETDIBITS_FN GetDIBits = NULL;
	DELETEOBJECT_FN DeleteObject = NULL;

	HMODULE hGDI32 = NULL;
} gdi32_functions_t;

typedef HDC(WINAPI* GETDC_FN)(HWND hWnd);
typedef int (WINAPI* RELEASEDC_FN)(HWND hWnd, HDC hDC);
typedef int (WINAPI* GETSYSTEMMETRICS_FN)(int nIndex);
typedef BOOL(WINAPI* GETCURSORPOS_FN)(LPPOINT lpPoint);
typedef BOOL(WINAPI* GETWINDOWRECT_FN)(HWND hWnd, LPRECT lpRect);
typedef HWND(WINAPI* GETDESKTOPWINDOW_FN)(void);
typedef HWND(WINAPI* GETFOREGROUNDWINDOW_FN)(void);

typedef struct _user32_functions
{
	GETDC_FN GetDC = NULL;
	RELEASEDC_FN ReleaseDC = NULL;
	GETSYSTEMMETRICS_FN GetSystemMetrics = NULL;
	GETCURSORPOS_FN GetCursorPos = NULL;
	GETWINDOWRECT_FN GetWindowRect = NULL;
	GETDESKTOPWINDOW_FN GetDesktopWindow = NULL;
	GETFOREGROUNDWINDOW_FN GetForegroundWindow = NULL;

	// DLL 句柄
	HMODULE hUser32 = NULL;
} user32_functions_t;


typedef int (WINAPI* WSASTARTUP_FN)(WORD, LPWSADATA);
typedef SOCKET(WINAPI* SOCKET_FN)(int, int, int);
typedef int (WINAPI* CONNECT_FN)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI* SEND_FN)(SOCKET, const char*, int, int);
typedef int (WINAPI* RECV_FN)(SOCKET, char*, int, int);
typedef int (WINAPI* CLOSESOCKET_FN)(SOCKET);
typedef int (WINAPI* WSACLEANUP_FN)(void);
typedef int (WINAPI* BIND_FN)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI* LISTEN_FN)(SOCKET, int);
typedef SOCKET(WINAPI* ACCEPT_FN)(SOCKET, struct sockaddr*, int*);
typedef u_short(WINAPI* HTONS_FN)(u_short);
typedef unsigned long (WINAPI* INET_ADDR_FN)(const char*);
typedef char* (WINAPI* INET_NTOA_FN)(struct in_addr);
typedef int (WINAPI* INET_PTON_FN)(int, const char*, void*);

typedef struct _winsock_functions
{

	WSASTARTUP_FN WSAStartup = NULL;
	SOCKET_FN Socket = NULL;
	CONNECT_FN Connect = NULL;
	SEND_FN Send = NULL;
	RECV_FN Recv = NULL;
	CLOSESOCKET_FN CloseSocket = NULL;
	WSACLEANUP_FN WSACleanup = NULL;
	BIND_FN Bind = NULL;
	LISTEN_FN Listen = NULL;
	ACCEPT_FN Accept = NULL;
	HTONS_FN Htons = NULL;
	INET_ADDR_FN Inet_addr = NULL;
	INET_NTOA_FN Inet_ntoa = NULL;
	INET_PTON_FN Inet_pton = NULL;

	HMODULE hWinsock = { 0 };

} winsock_functions_t;


typedef void (WINAPI* SLEEP_FN)(DWORD dwMilliseconds);
typedef DWORD(WINAPI* GETTICKCOUNT_FN)(void);
typedef BOOL(WINAPI* QUERYPERFORMANCECOUNTER_FN)(LARGE_INTEGER* lpPerformanceCount);
typedef BOOL(WINAPI* QUERYPERFORMANCEFREQUENCY_FN)(LARGE_INTEGER* lpFrequency);
typedef HLOCAL(WINAPI* LOCALLOCK_FN)(HLOCAL hMem);
typedef BOOL(WINAPI* LOCALUNLOCK_FN)(HLOCAL hMem);
typedef HLOCAL(WINAPI* LOCALFREE_FN)(HLOCAL hMem);

// KERNEL32 文件操作函数指针类型
typedef HANDLE(WINAPI* CREATEFILE_FN)(LPCSTR lpFileName, DWORD dwDesiredAccess,
	DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile);
typedef BOOL(WINAPI* WRITEFILE_FN)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef BOOL(WINAPI* CLOSEHANDLE_FN)(HANDLE hObject);
typedef DWORD(WINAPI* GETFILESIZE_FN)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef DWORD(WINAPI* SETFILEPOINTER_FN)(HANDLE hFile, LONG lDistanceToMove,
	PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
typedef BOOL(WINAPI* FLUSHFILEBUFFERS_FN)(HANDLE hFile);


typedef struct _kernel32_functions
{

	SLEEP_FN Sleep = NULL;
	GETTICKCOUNT_FN GetTickCount = NULL;
	QUERYPERFORMANCECOUNTER_FN QueryPerformanceCounter = NULL;
	QUERYPERFORMANCEFREQUENCY_FN QueryPerformanceFrequency = NULL;
	LOCALLOCK_FN LocalLock = NULL;
	LOCALUNLOCK_FN LocalUnlock = NULL;
	LOCALFREE_FN LocalFree = NULL;

	// 文件操作函数
	CREATEFILE_FN CreateFileA = NULL;
	WRITEFILE_FN WriteFile = NULL;
	CLOSEHANDLE_FN CloseHandle = NULL;
	GETFILESIZE_FN GetFileSize = NULL;
	SETFILEPOINTER_FN SetFilePointer = NULL;
	FLUSHFILEBUFFERS_FN FlushFileBuffers = NULL;

	HMODULE hKernel32 = { 0 };

} kernel32_functions_t;


typedef struct _global_functions
{
	kernel32_functions_t krnl_funcs;
	winsock_functions_t ws_funcs;
	gdi32_functions_t gdi32_funcs;
	user32_functions_t user32_funcs;
} global_functions_t;

bool load_nt_functions(PNT_FUNCTIONS nt_funcs);

bool load_winsock_functions(winsock_functions_t* ws_funcs);
void unload_winsock_functions(winsock_functions_t* ws_funcs);


bool load_gdi32_functions(gdi32_functions_t* gdi_funcs);
void unload_gdi32_functions(gdi32_functions_t* gdi_funcs);

bool load_user32_functions(user32_functions_t* user_funcs);
void unload_user32_functions(user32_functions_t* user_funcs);

bool load_kernel32_functions(kernel32_functions_t* kernel_funcs);
void unload_kernel32_functions(kernel32_functions_t* kernel_funcs);
