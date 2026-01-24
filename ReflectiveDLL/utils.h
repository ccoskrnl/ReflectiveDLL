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

#define SERVER_HOSTNAME "127.0.0.1"
#define SERVER_PORT 17888
#define INTERVAL_SECONDS 21
#define CONNECTION_TIMEOUT 30


BOOL load_winsock_functions(winsock_functions_t* ws_funcs);

//int send_file(const char* filename, SOCKET sock);
//
//int cleanup_temp_file(const char* filename);
