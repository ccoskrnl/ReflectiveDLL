#pragma once

#include <Windows.h>
#include "headers.h"
#include "syscalls.h"
#include "misc.h"


HANDLE find_SRH_DLL_section_handle(PSYSCALL_ENTRY zw_func_s, fnGetProcessId GPID)
{
    WCHAR wstr_section[] = { L'S', L'e', L'c', L't', L'i', L'o', L'n', L'\0' };
    WCHAR wstr_SRH[] = { L'S',L'R',L'H',L'.',L'd',L'l',L'l',L'\0' };

    NTSTATUS status = 0;



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


    while ((status = ZwQuerySystemInformation(
        16, buffer, buf_size, NULL,
        zw_func_s[ZwQuerySystemInformationF].SSN,
        zw_func_s[ZwQuerySystemInformationF].sysretAddr))
        == 0xc0000004)
    {
        // free and re-allocate
        if (status = ZwFreeVirtualMemory(
            ((HANDLE)(LONG_PTR)-1), &buffer, 0,
            MEM_RELEASE,
            zw_func_s[ZwFreeVirtualMemoryF].SSN,
            zw_func_s[ZwFreeVirtualMemoryF].sysretAddr) == 0)
        {
            return FALSE;
        }


        // reset variables
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

    PSYSTEM_HANDLE_INFORMATION handle_info = (PSYSTEM_HANDLE_INFORMATION)buffer;

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


    for (ULONG_PTR i = 0; i < handle_info->HandleCount; i++)
    {
        handle = handle_info->Handles[i];

        if (handle.ProcessId != pid)
            continue;

        if ((status = ZwQueryObject(
            (void*)handle.Handle, ObjectTypeInformation,
            obj_type_info, 0x1000, NULL,
            zw_func_s[ZwQueryObjectF].SSN, zw_func_s[ZwQueryObjectF].sysretAddr))
            != 0)
        {
            continue;
        }

        // check if the handle is point to a section object.
        if (ComprareNStringWIDE(
            obj_type_info->Name.Buffer,
            wstr_section,
            (obj_type_info->Name.Length / sizeof(WCHAR)))
            != TRUE)
        {
            continue;
        }

        // comparing with IMAGE_NOT_AT_BASE because that is the
        // return value in status if i try to re-map the DLL,
        // but it is actually mapped.

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

            // if it actually was successfully but not for our
            // DLL, then we need to clean up and continue
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

        // here need to query the memory

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

            // free and re-allocate

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

            // re-allocate
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

            // query memory again
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

            // if it's not buffer overflow but actual error we need to unmap the dll and continue

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

        // if the path contains the SRH.dll
        if (!containsSubstringUnicode(
            mem_info->Buffer,
            wstr_SRH,
            mem_info->Length / sizeof(WCHAR), 8))
            continue;

        // free the buffer memory
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

        // I haven't found any match.
        if ((status = ZwFreeVirtualMemory(
            ((HANDLE)(LONG_PTR)-1),
            &buf_mem_info,
            0, MEM_RELEASE,
            zw_func_s[ZwFreeVirtualMemoryF].SSN,
            zw_func_s[ZwFreeVirtualMemoryF].sysretAddr)) == 0)
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



    }


    return (HANDLE)-1;
}

