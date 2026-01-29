#pragma once

#include "pch.h"
#include "framework.h"

#include "dll_headers.h"

#include "types.h"
#include <winsock2.h>
#include <windows.h>


status_t startup_wsa(winsock_functions_t* ws2);
void cleanup_wsa(winsock_functions_t*);
void close_socket(SOCKET socket, winsock_functions_t* ws2);

SOCKET init_connection(const char* hostname, int port, winsock_functions_t*);

status_t send_file(SOCKET socket, const char* filepath, winsock_functions_t* ws2);
status_t send_data(SOCKET socket, char* buf, SIZE_T size, DWORD* bytes_sent, winsock_functions_t* ws2);
status_t recv_data(SOCKET socket, char* buf, int len, DWORD* total_received, winsock_functions_t* ws2);
