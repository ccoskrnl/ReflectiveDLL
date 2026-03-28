#pragma once
#include "pch.h"

#define SERVER_HOSTNAME "192.168.48.1"
//#define SERVER_HOSTNAME "127.0.0.1"
#define SERVER_PORT 17888
#define INTERVAL_SECONDS 21
#define CONNECTION_TIMEOUT 30

#define END_MARKER "<<<^^^^^^END_OF_DATA^^^^^^>>>"

#define MAX_NAME_LEN 1024
#define BUFSIZE 4096

typedef int status_t;

#define ST_SUCCESS										0
#define ST_ERROR										-1
#define ST_SOCKET_ERROR									-2
#define ST_MEM_ALLOC_ERROR								-3
#define ST_FAILED(status)								(status != ST_SUCCESS)
