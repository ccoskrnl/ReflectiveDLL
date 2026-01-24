#include "framework.h"
#include "pch.h"
#include "utils.h"
#include "utils_headers.h"
#include "headers.h"
#include "sleaping.h"
#include <stdlib.h>
#include <stdint.h>

BOOL load_winsock_functions(winsock_functions_t* ws_funcs)
{
	HMODULE winsock_dll = NULL;
	winsock_dll = LoadLibraryA("ws2_32.dll");
	if (winsock_dll == NULL)
	{
		return FALSE;
	}

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


	//uint64_t* funcs_start = (uint64_t*)winsock_dll;
	//int num = sizeof(*ws_funcs) / sizeof(void*);
	//for (int i = 0; i < num; i++, funcs_start++)
	//{
	//	if (*funcs_start == NULL)
	//	{
	//		FreeLibrary(winsock_dll);
	//		return FALSE;
	//	}
	//}

	return TRUE;
}

//int send_file(const char* filename, SOCKET sock)
//{
//	FILE* fp = NULL;
//	long file_size;
//	char* buffer = NULL;
//	size_t bytes_read;
//	int total_sent = 0;
//	int result;
//
//	// 打开文件
//	fp = fopen(filename, "rb");
//	if (!fp) {
//		//printf("无法打开文件: %s\n", filename);
//		return -1;
//	}
//
//	// 获取文件大小
//	fseek(fp, 0, SEEK_END);
//	file_size = ftell(fp);
//	fseek(fp, 0, SEEK_SET);
//
//	if (file_size <= 0) {
//		//printf("文件为空或无效\n");
//		fclose(fp);
//		return -1;
//	}
//
//	// 分配缓冲区
//	buffer = (char*)malloc(file_size);
//	if (!buffer) {
//		//printf("内存分配失败\n");
//		fclose(fp);
//		return -1;
//	}
//
//	// 读取文件
//	bytes_read = fread(buffer, 1, file_size, fp);
//	if (bytes_read != file_size) {
//		//printf("读取文件不完全\n");
//		free(buffer);
//		fclose(fp);
//		return -1;
//	}
//
//	fclose(fp);
//
//	// 发送文件大小（8字节，大端序）
//	uint64_t size_be = _byteswap_uint64((uint64_t)file_size);
//	result = send(sock, (char*)&size_be, sizeof(size_be), 0);
//	if (result == SOCKET_ERROR) {
//		int error = WSAGetLastError();
//		//printf("发送文件大小失败: %d\n", error);
//		free(buffer);
//		return -1;
//	}
//
//	// 发送文件数据
//	while (total_sent < file_size) {
//		int remaining = file_size - total_sent;
//		int to_send = remaining > 4096 ? 4096 : remaining;
//
//		result = send(sock, buffer + total_sent, to_send, 0);
//		if (result == SOCKET_ERROR) {
//			int error = WSAGetLastError();
//			//printf("发送数据失败: %d\n", error);
//			free(buffer);
//			return -1;
//		}
//
//		total_sent += result;
//	}
//
//	//printf("文件发送完成: %d 字节\n", total_sent);
//	free(buffer);
//	return 0;
//}
//
//int cleanup_temp_file(const char* filename)
//{
//	if (DeleteFileA(filename)) {
//		//printf("临时文件已删除\n");
//		return 0;
//	}
//	else {
//		DWORD error = GetLastError();
//		if (error != ERROR_FILE_NOT_FOUND) {
//			//printf("删除临时文件失败: %s (错误代码: %lu)\n", filename, error);
//		}
//		return -1;
//	}
//}
