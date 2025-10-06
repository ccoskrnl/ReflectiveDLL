#pragma once
#include <Windows.h>

typedef struct _DLL_HEADER {
    DWORD header; //4 bytes header
    DWORD key; //4 bytes encryption key
    SIZE_T funcSize; //8 bytes

} DLL_HEADER, * PDLL_HEADER;
