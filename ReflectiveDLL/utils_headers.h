#pragma once

#include "pch.h"
#include "framework.h"
#include <winternl.h>


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

} winsock_functions_t;
