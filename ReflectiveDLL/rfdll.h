#pragma once

#include <windef.h>


typedef struct _DLL_HEADER {
    DWORD header; //4 bytes header
    DWORD key; //4 bytes encryption key
    SIZE_T funcSize; //8 bytes

} DLL_HEADER, * PDLL_HEADER;




typedef struct _FUNCTION_ADDRESSES {
    PVOID NtWaitForSingleObjectAddress;
    PVOID NtTestAlertAddress;
    PVOID MessageBoxAddress;
    PVOID ResumeThreadAddress;
} FUNCTION_ADDRESSES, * PFUNCTION_ADDRESSES;

typedef struct _CORE_ARGUMENTS {

    PBYTE myBase;
    HANDLE sacDLLHandle;
    HANDLE malDLLHandle;
    SIZE_T viewSize;

} CORE_ARGUMENTS, * PCORE_ARGUMENTS;



