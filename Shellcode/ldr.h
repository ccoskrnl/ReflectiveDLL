#pragma once
#include "framework.h"
#include "headers.h"

/*---------FUNCTIONS PROTOTYPES--------------*/
FARPROC GPARO(IN HMODULE hModule, IN int ordinal);

HMODULE GMHR(IN WCHAR szModuleName[]);
HMODULE GMHR_Hash(DWORD dwModuleHash);

FARPROC GPAR(IN HMODULE hModule, IN CHAR lpApiName[]);
FARPROC GPAR_Hash(IN HMODULE hModule, IN DWORD dwApiHash);
