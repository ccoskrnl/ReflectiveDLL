// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        PBYTE old_memory = NULL;

        // even if unmapped it's in the PEB
        PBYTE self_base = (PBYTE)GetModuleHandleA("SRH.dll");

        // retrieve the information left from the reflective loader
        PHANDLE p_handle = (PHANDLE)self_base;
        HANDLE sac_dll = *p_handle;



    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

