#pragma once
#include "pch.h"
#include "framework.h"
#include "headers.h"


/*---------FUNCTIONS PROTOTYPES--------------*/
FARPROC GPARO(IN HMODULE hModule, IN int ordinal);

HMODULE GMHR(IN WCHAR szModuleName[]);

FARPROC GPAR(IN HMODULE hModule, IN CHAR lpApiName[]);

DWORD WINAPI ThreadProc(LPVOID lpParameter);
