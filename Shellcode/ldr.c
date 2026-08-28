#pragma once
#include "misc.h"
#include "api_hash.h"
#include "headers.h"

extern void *get_peb_x64(void);

DWORD HashStringW(const wchar_t *str)
{
    DWORD hash = 5381; // DJB2 初始值
    while (*str)
    {
        // 仅使用低字节（模块名通常为 ASCII）
        hash = ((hash << 5) + hash) + (unsigned char)(*str & 0xFF);
        str++;
    }
    return hash;
}
DWORD HashStringA(const char *str)
{
    DWORD hash = 5381;
    while (*str)
    {
        hash = ((hash << 5) + hash) + (unsigned char)(*str);
        str++;
    }
    return hash;
}

/*---------FUNCTIONS PROTOTYPES--------------*/
FARPROC GPARO(IN HMODULE hModule, IN int ordinal);





//----------------GET MODULE HANDLE---------------------
HMODULE GMHR(IN WCHAR szModuleName[]) {

    PPEBC					pPeb = (PEBC*)(__readgsqword(0x60));
    if (!pPeb)
        return NULL;

    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    ToLowerCaseWIDE(szModuleName);

    while (entry != head)
    {
        PLDR_DATA_TABLE_ENTRY pDte = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        UNICODE_STRING* BaseDllName = (UNICODE_STRING*)((UNICODE_STRING*)&pDte->FullDllName + 1);
        ToLowerCaseWIDE(BaseDllName->Buffer);
        if (BaseDllName->Length > 0 && BaseDllName->Buffer)
        {
            if (ComprareStringWIDE(BaseDllName->Buffer, szModuleName)) {

                return (HMODULE)(pDte->DllBase);

            }
        }

        entry = entry->Flink;

    }

    return NULL;

}



















HMODULE GMHR_Hash(DWORD dwModuleHash)
{
    // 获取 PEB（x64 使用 gs:[0x60]）
    PPEB pPeb = (PPEB)get_peb_x64();
    if (!pPeb)
        return NULL;

    // 获取模块加载顺序链表头
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    // 遍历所有模块
    while (entry != head)
    {
        // 通过 CONTAINING_RECORD 还原出 LDR_DATA_TABLE_ENTRY 结构
        PLDR_DATA_TABLE_ENTRY pDte = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // 检查 BaseDllName 是否有效
        UNICODE_STRING* BaseDllName = (UNICODE_STRING*)((UNICODE_STRING*)&pDte->FullDllName + 1);
        ToLowerCaseWIDE(BaseDllName->Buffer);
        if (BaseDllName->Length > 0 && BaseDllName->Buffer)
        {
            // 计算模块基本名称的哈希
            DWORD hash = HashStringW(BaseDllName->Buffer);
            if (hash == dwModuleHash)
            {
                // 返回模块加载基址
                return (HMODULE)pDte->DllBase;
            }
        }

        // 移动到下一个模块
        entry = entry->Flink;
    }

    return NULL; // 未找到匹配模块
}

/*-------------------PEB STOMPING---------------------------*/

/*----------------SUPPORT FUNCTIONS------------------------*/
static void ParseForwarder(CHAR forwarder[], CHAR dll[], CHAR function[])
{

    int i = 0;
    while (forwarder[i])
    {
        if (forwarder[i] == '.')
        {
            break;
        }
        i++;
    }
    for (int j = 0; j <= i; j++)
    {
        dll[j] = forwarder[j];
    }
    dll[i + 1] = 'd';
    dll[i + 2] = 'l';
    dll[i + 3] = 'l';
    dll[i + 4] = '\0';
    i++;
    int z = 0;
    while (forwarder[i])
    {
        function[z] = forwarder[i];
        i++;
        z++;
    }
    function[z + 1] = '\0';
}

static void ConvertPointerToString(LPVOID pointer, char *buffer, size_t bufferSize)
{
    const char hexDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    uintptr_t value = (uintptr_t)(pointer);

    // Add "0x" prefix
    buffer[0] = '0';
    buffer[1] = 'x';

    // Convert each nibble to a hexadecimal digit
    for (int i = 15; i >= 0; --i)
    {
        buffer[2 + (15 - i)] = hexDigits[(value >> (i * 4)) & 0xF];
    }

    // Null-terminate the string
    buffer[18] = '\n';
    buffer[19] = '\0';
}



FARPROC GPAR(IN HMODULE hModule, IN CHAR lpApiName[]) {


    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    //variables for forwarding
    WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR loadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    fnLoadLibraryA LLA = NULL;
    PBYTE functionAddress = NULL;
    CHAR forwarder[260] = { 0 };
    CHAR dll[260] = { 0 };
    CHAR function[260] = { 0 };



    // looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // getting the name of the function
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);



        // searching for the function specified
        if (CompareStringASCII(lpApiName, pFunctionName)) {
            WORD ordinal = FunctionOrdinalArray[i];
            DWORD funcRVA = FunctionAddressArray[ordinal - pImgExportDir->Base];
            functionAddress = (PBYTE)(pBase + funcRVA);

            if (functionAddress >= (PBYTE)pImgExportDir && functionAddress < (PBYTE)((PBYTE)pImgExportDir + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {

                //here i have to get a substring
                ParseForwarder((CHAR*)functionAddress, dll, function);
                if ((LLA = (fnLoadLibraryA)GPAR(GMHR(kernel32), loadLibraryA)) == NULL)
                    return NULL;
                if (function[0] == '#') {

                    return GPARO(LLA(dll), custom_stoi(&function[1]));
                }
                else {
                    return GPAR(LLA(dll), function);
                }

            }
            else {

                return (FARPROC)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

            }

        }

    }

    return NULL;
}




FARPROC GPAR_Hash(IN HMODULE hModule, IN DWORD dwApiHash)
{
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    // 用于转发器处理时动态获取 LoadLibraryA
    // 定义常量哈希值（由 Python 脚本计算）
    const DWORD LOADLIBRARYA_HASH = 0x5fbff0fb;
    const DWORD KERNEL32_HASH = 0x7040ee75;

    // 遍历所有导出函数（按名称）
    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++)
    {
        CHAR *pFunctionName = (CHAR *)(pBase + FunctionNameArray[i]);
        DWORD dwNameHash = HashStringA(pFunctionName);
        if (dwNameHash == dwApiHash)
        {
            // 找到匹配函数，获取地址
            PBYTE functionAddress = (PBYTE)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

            // 检查是否为转发器
            if (functionAddress >= (PBYTE)pImgExportDir &&
                functionAddress < (PBYTE)((PBYTE)pImgExportDir + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
            {
                // 是转发器，解析出 DLL 名和函数名
                CHAR forwarder[260];
                CHAR dll[260];
                CHAR function[260];
                // 手动复制转发字符串（避免使用标准库）
                // 此处假设已有自定义字符串处理函数，如 CustomStrCopy
                // 为简化，下面使用循环复制
                int j = 0;
                while (functionAddress[j] != '.')
                {
                    dll[j] = functionAddress[j];
                    j++;
                }
                dll[j] = 0;
                j++;
                int k = 0;
                while (functionAddress[j] != 0)
                {
                    function[k++] = functionAddress[j++];
                }
                function[k] = 0;

                // 动态获取 LoadLibraryA（通过哈希）
                fnLoadLibraryA LLA = (fnLoadLibraryA)GPAR_Hash(GMHR_Hash(KERNEL32_HASH), LOADLIBRARYA_HASH);
                if (!LLA)
                    return NULL;

                HMODULE hDll = LLA(dll);
                if (!hDll)
                    return NULL;

                if (function[0] == '#')
                {
                    return GPARO(LLA(dll), custom_stoi(function));
                }
                else
                {
                    // 按名称转发
                    return GPAR_Hash(hDll, HashStringA(function));
                }
            }
            else
            {
                // 非转发器，直接返回地址
                return (FARPROC)functionAddress;
            }
        }
    }
    return NULL;
}

FARPROC GPARO(IN HMODULE hModule, IN int ordinal)
{

    if (ordinal <= 0)
        return NULL;

    ordinal -= 1;
    
    // we do this to avoid casting at each time we use 'hModule'
    PBYTE pBase = (PBYTE)hModule;

    // getting the dos header and doing a signature check
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // getting the nt headers and doing a signature check
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // getting the optional header
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // we can get the optional header like this as well
    // PIMAGE_OPTIONAL_HEADER	pImgOptHdr	= (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

    // getting the image export table
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // getting the base = first ordinal value in the export table (DWORD 4 bytes)
    int base = (int)pImgExportDir->Base;
    int NumberOfFunctions = (int)pImgExportDir->NumberOfFunctions;

    // variables for forwarding
    fnLoadLibraryA LLA = NULL;
    PBYTE functionAddress = NULL;
    CHAR forwarder[260];
    CHAR dll[260];
    CHAR function[260];

    // check if the ordinal falls into the range of ordinals of functions exported by the DLL
    if (ordinal < base || ordinal >= base + NumberOfFunctions)
    {

        return NULL;
    }

    // getting the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    // getting the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    // getting the function's ordinal array pointer
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    // as specified here https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    // If the address specified is not within the export section (as defined by the address and length that are indicated
    // in the optional header), the field is an export RVA, which is an actual address in code or data. Otherwise, the field is a forwarder RVA,
    // // which names a symbol in another DLL.
    functionAddress = (PBYTE)(pBase + FunctionAddressArray[ordinal - base]);
    if (functionAddress >= (PBYTE)pImgExportDir && functionAddress < (PBYTE)((PBYTE)pImgExportDir + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
    {

        // here i have to get a substring
        ParseForwarder((CHAR *)functionAddress, dll, function);
        if ((LLA = (fnLoadLibraryA)GPAR_Hash(GMHR_Hash(HASH_KERNEL32), HASH_LOADLIBRARYA)) == NULL)
            return NULL;
        if (function[0] == '#')
        {

            return GPARO(LLA(dll), custom_stoi(function));
        }
        else
        {
            return GPAR_Hash(LLA(dll), HashStringA(function));
        }
    }

    return (FARPROC)(pBase + FunctionAddressArray[ordinal]);
}