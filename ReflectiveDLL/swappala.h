#pragma once

#include <Windows.h>
#include "headers.h"
#include "syscalls.h"
#include "misc.h"


HANDLE find_SRH_DLL_section_handle(PSYSCALL_ENTRY zw_func_s, fnGetProcessId GPID)
{
    // 要匹配的对象类型名称：Section
    WCHAR wstr_section[] = { L'S', L'e', L'c', L't', L'i', L'o', L'n', L'\0' };
    // 要匹配的 DLL 文件名：SRH.dll
    WCHAR wstr_SRH[] = { L'S',L'R',L'H',L'.',L'd',L'l',L'l',L'\0' };

    NTSTATUS status = 0;


    // ------------------------------------------------------------
    // 1. 分配初始缓冲区，用于接收系统句柄信息
    // ------------------------------------------------------------
    PVOID buffer = NULL;
    SIZE_T buf_size = 0x10000;
    if ((status = ZwAllocateVirtualMemory(
        ((HANDLE)(LONG_PTR)-1),
        &buffer,
        0,
        &buf_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        zw_func_s[ZwAllocateVirtualMemoryF].SSN,
        zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
    )) != 0)
    {
        return FALSE;
    }

    // ------------------------------------------------------------
    // 2. 查询系统句柄信息，若缓冲区不足则动态扩大
    // ------------------------------------------------------------
    // 状态码 0xc0000004 = STATUS_INFO_LENGTH_MISMATCH，表示缓冲区太小
    while ((status = ZwQuerySystemInformation(
        16,                 // SystemHandleInformation = 16
        buffer,
        buf_size,
        NULL,
        zw_func_s[ZwQuerySystemInformationF].SSN,
        zw_func_s[ZwQuerySystemInformationF].sysretAddr))
        == 0xc0000004)
    {
        // 释放当前缓冲区
        if (status = ZwFreeVirtualMemory(
            ((HANDLE)(LONG_PTR)-1), &buffer, 0,
            MEM_RELEASE,
            zw_func_s[ZwFreeVirtualMemoryF].SSN,
            zw_func_s[ZwFreeVirtualMemoryF].sysretAddr) == 0)
        {
            return FALSE;
        }


        // 重置变量，缓冲区大小加倍后重新分
        buffer = NULL;
        buf_size *= 2;
        if ((status = ZwAllocateVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &buffer,
            0,
            &buf_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            zw_func_s[ZwAllocateVirtualMemoryF].SSN,
            zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
        )) != 0)
        {
            return FALSE;
        }

    }

    // 此时 buffer 指向 SYSTEM_HANDLE_INFORMATION 结构
    PSYSTEM_HANDLE_INFORMATION handle_info = (PSYSTEM_HANDLE_INFORMATION)buffer;

    // ------------------------------------------------------------
	// 3. 分配临时缓冲区，用于查询对象类型信息
	// ------------------------------------------------------------
    PVOID obj_type_info_tmp = NULL;
    SIZE_T obj_type_info_size = 0x1000;
    if ((status = ZwAllocateVirtualMemory(
        ((HANDLE)(LONG_PTR)-1),
        &obj_type_info_tmp,
        0,
        &obj_type_info_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        zw_func_s[ZwAllocateVirtualMemoryF].SSN,
        zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
    )) != 0)
    {
        return FALSE;
    }


    // ------------------------------------------------------------
    // 4. 分配缓冲区，用于查询内存映射文件名
    // ------------------------------------------------------------
    PVOID obj_name_info = NULL;
    SIZE_T obj_name_info_size = 0x1000;
    if ((status = ZwAllocateVirtualMemory(
        ((HANDLE)(LONG_PTR)-1),
        &obj_name_info,
        0,
        &obj_name_info_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        zw_func_s[ZwAllocateVirtualMemoryF].SSN,
        zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr
    )) != 0)
    {
        return FALSE;
    }

    POBJECT_TYPE_INFORMATION obj_type_info = (POBJECT_TYPE_INFORMATION)obj_type_info_tmp;

    SYSTEM_HANDLE handle = { 0 };
    // 获取当前进程 ID
    DWORD pid = GPID(((HANDLE)(LONG_PTR)-1));

    SIZE_T view_size = 0;
    PVOID view_base = NULL;


    UNICODE_STRING obj_name = { 0 };
    ULONG ret_length = 0;
    SIZE_T ret_length_size_t = 0;
    PVOID buf_mem_info = NULL;
    SIZE_T buf_mem_info_size = 0;
    SIZE_T ret_length_mem = 0;
    PUNICODE_STRING mem_info = NULL;

    // ------------------------------------------------------------
    // 5. 遍历所有句柄，查找目标 Section
    // ------------------------------------------------------------
    for (ULONG_PTR i = 0; i < handle_info->HandleCount; i++)
    {
        handle = handle_info->Handles[i];

        // 只处理属于当前进程的句柄
        if (handle.ProcessId != pid)
            continue;

        // 查询句柄的对象类型
        if ((status = ZwQueryObject(
            (void*)handle.Handle,               // 句柄值
            ObjectTypeInformation,              // 信息类 = 2，查询类型信息
            obj_type_info,
            0x1000,
            NULL,
            zw_func_s[ZwQueryObjectF].SSN,
            zw_func_s[ZwQueryObjectF].sysretAddr))
            != 0)
        {
            continue;
        }

        // 检查对象类型是否为 "Section"
        if (ComprareNStringWIDE(
            obj_type_info->Name.Buffer,
            wstr_section,
            (obj_type_info->Name.Length / sizeof(WCHAR)))
            != TRUE)
        {
            continue;
        }


        // ------------------------------------------------------------
        // 尝试映射该 Section 对象的一个视图
        // 若映射返回 STATUS_IMAGE_NOT_AT_BASE (0x40000003)，
        // 表示该 Section 是一个可执行映像（DLL/EXE）且未加载到首选基址，
        // 这正是我们需要的特征。
        // ------------------------------------------------------------
        if ((status = ZwMapViewOfSection(
            (void*)handle.Handle,
            ((HANDLE)(LONG_PTR)-1),
            &view_base,
            NULL, NULL, NULL,
            &view_size,
            ViewShare,
            0,
            PAGE_READONLY,
            zw_func_s[ZwMapViewOfSectionF].SSN,
            zw_func_s[ZwMapViewOfSectionF].sysretAddr))
            != 0x40000003)
        {

            // 如果映射成功（status == 0）但不是预期的状态，说明不是 DLL 映像，需要清理并继续
            if (status == 0)
            {
                if (status = ZwUnmapViewOfSection(
                    ((HANDLE)(LONG_PTR)-1), view_base,
                    zw_func_s[ZwUnmapViewOfSectionF].SSN,
                    zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
                ) != 0)
                {
                    return FALSE;
                }
            }

            view_base = NULL;
            continue;
        }

        if (view_base == NULL)
            continue;


        // ------------------------------------------------------------
        // 6. 查询映射视图对应的文件路径（MemoryMappedFilenameInformation）
        // ------------------------------------------------------------
        buf_mem_info = NULL;
        buf_mem_info_size = 0x100;

        if ((status = ZwAllocateVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &buf_mem_info,
            0,
            &buf_mem_info_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            zw_func_s[ZwAllocateVirtualMemoryF].SSN,
            zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr)) != 0)
        {

            return FALSE;
        }


        // 查询内存映射文件名（信息类 MemoryMappedFilenameInformation = 2）
        if ((status = ZwQueryVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            view_base,
            MemoryMappedFilenameInformation,
            buf_mem_info,
            buf_mem_info_size,
            &ret_length_mem,
            zw_func_s[ZwQueryVirtualMemoryF].SSN,
            zw_func_s[ZwQueryVirtualMemoryF].sysretAddr
        )) == 0x80000005)               // STATUS_BUFFER_OVERFLOW
        {


            // 缓冲区不足，释放后按需长度重新分配
            if ((status = ZwFreeVirtualMemory(
                ((HANDLE)(LONG_PTR)-1),
                &buf_mem_info,
                0,
                MEM_RELEASE,
                zw_func_s[ZwAllocateVirtualMemoryF].SSN,
                zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr)) == 0)
            {
                return FALSE;
            }

            // 重新分配，使用所需长度
            buf_mem_info_size = ret_length_mem;
            if ((status = ZwAllocateVirtualMemory(
                ((HANDLE)(LONG_PTR)-1),
                &buf_mem_info,
                0,
                &buf_mem_info_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
                zw_func_s[ZwAllocateVirtualMemoryF].SSN,
                zw_func_s[ZwAllocateVirtualMemoryF].sysretAddr)) != 0)
            {

                return FALSE;

            }

            // 再次查询
            if ((status = ZwQueryVirtualMemory(
                ((HANDLE)(LONG_PTR)-1),
                view_base,
                MemoryMappedFilenameInformation,
                buf_mem_info,
                buf_mem_info_size,
                &ret_length_mem,
                zw_func_s[ZwQueryVirtualMemoryF].SSN,
                zw_func_s[ZwQueryVirtualMemoryF].sysretAddr
            )) == 0x80000005)
            {
                return FALSE;
            }


        }
        else if (status != 0)
        {

            // 其他错误：卸载视图并跳过
            if (status = ZwUnmapViewOfSection(
                ((HANDLE)(LONG_PTR)-1), view_base,
                zw_func_s[ZwUnmapViewOfSectionF].SSN,
                zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
            ) != 0)
            {
                return FALSE;
            }

            view_base = NULL;
            continue;

        }

        mem_info = (PUNICODE_STRING)buf_mem_info;

        if (mem_info->Buffer == NULL)
            continue;

        // 检查文件路径是否包含 "SRH.dll"（不区分大小写，长度匹配）
        if (!containsSubstringUnicode(
            mem_info->Buffer,
            wstr_SRH,
            mem_info->Length / sizeof(WCHAR), 8))
            continue;

        // ------------------------------------------------------------
        // 找到目标：释放临时缓冲区，卸载视图，返回句柄
        // ------------------------------------------------------------
        if (status = ZwFreeVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &buf_mem_info,
            0,
            MEM_RELEASE,
            zw_func_s[ZwFreeVirtualMemoryF].SSN,
            zw_func_s[ZwFreeVirtualMemoryF].sysretAddr
        ) == 0)
        {

            return FALSE;

        }

        if ((status = ZwUnmapViewOfSection(
            ((HANDLE)(LONG_PTR)-1),
            view_base,
            zw_func_s[ZwUnmapViewOfSectionF].SSN,
            zw_func_s[ZwUnmapViewOfSectionF].sysretAddr
        )) != 0)
        {
            return FALSE;
        }

        return (void*)handle.Handle;

    }

    // 未找到任何匹配的 Section 句柄
    return (HANDLE)-1;
}

