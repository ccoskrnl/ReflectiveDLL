#pragma once
#include "framework.h"
#include "pch.h"

typedef HMODULE(*func_def_GetModuleHandle_t)(WCHAR wstr_module_name[]);
typedef FARPROC(*func_def_GetProcAddress_t)(HMODULE hm, CHAR func_name[]);
typedef void(*func_def_message_box_t)(void*, void*, void*, void*);
void test(func_def_GetModuleHandle_t func_get_module_handle, func_def_GetProcAddress_t func_get_proc_addr)
{

	WCHAR str_Kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
	WCHAR str_ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
	WCHAR str_user32[] = { L'U', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
	CHAR str_RtlAddFunctionTable[] = { 'R', 't', 'l', 'A', 'd', 'd', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'T', 'a', 'b', 'l', 'e', '\0' };
	CHAR str_MessageBoxA[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A','\0' };
	CHAR str_LoadLibraryExA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'E', 'x', 'A','\0' };
	CHAR str_GetProcessId[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd', '\0' };

	HMODULE hm_user32 = func_get_module_handle(str_user32);
	func_def_message_box_t func_message_box = (func_def_message_box_t)func_get_proc_addr(hm_user32, str_MessageBoxA);
	func_message_box(0, 0, 0, 0);


}
