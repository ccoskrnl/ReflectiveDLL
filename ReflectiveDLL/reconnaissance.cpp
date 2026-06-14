#include "pch.h"
#include "framework.h"
#include "types.h"
#include "rfdll.h"
#include "misc.h"
#include "ldr.h"
#include "syscalls.h"

bool enable_debug_privilege()
{
	HANDLE h_token = NULL;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!ZwOpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&h_token,
		g_zw_functions[ZwOpenProcessF].SSN,
		g_zw_functions[ZwOpenProcessF].sysretAddr
	))
		return false;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		CloseHandle(h_token);
		return false;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!ZwAdjustPrivilegesToken(
		h_token,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL,
		g_zw_functions[ZwAdjustPrivilegesTokenF].SSN,
		g_zw_functions[ZwAdjustPrivilegesTokenF].sysretAddr
		))
	{
		CloseHandle(h_token);
		return false;
	}
	CloseHandle(h_token);
	return true;
}


#include <ShlObj.h>
#include <TlHelp32.h>

typedef HANDLE(*CreateToolhelp32SnapshotFunc)(
    DWORD dwFlags,
    DWORD th32ProcessID
    );

typedef BOOL(*Process32FirstFunc)(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
    );

typedef BOOL(*Process32NextFunc)(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
    );

int ret_pid_by_proc_name(wchar_t* proc_name)
{
    HANDLE proc_snap;
    PROCESSENTRY32 pe32;

    ToLowerCaseWIDE(proc_name);

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
        ToLowerCaseWIDE(pe32.szExeFile);
        if (wcscmp((pe32.szExeFile), proc_name) == 0)
        {
            CloseHandle(proc_snap);
            return pe32.th32ProcessID;
        }

    } while (process32next(proc_snap, &pe32));

    CloseHandle(proc_snap);
    return 0;
}


int select_target_process(bool is_debug_privilege)
{
    return 4;
}
