#pragma once
#include "pch.h"
#include "framework.h"
#include "misc.h"
#include "headers.h"


/*---------FUNCTIONS PROTOTYPES--------------*/
FARPROC GPARO(IN HMODULE hModule, IN int ordinal);

//----------------GET MODULE HANDLE---------------------
HMODULE GMHR(IN WCHAR szModuleName[]) {

    PPEBC					pPeb = (PEBC*)(__readgsqword(0x60));


    // geting Ldr
    PPEBC_LDR_DATA			pLdr = (PPEBC_LDR_DATA)(pPeb->Ldr);
    // getting the first element in the linked list (contains information about the first module)
    PLDR_DATA_TABLE_ENTRYC	pDte = (PLDR_DATA_TABLE_ENTRYC)(pLdr->InMemoryOrderModuleList.Flink);


    while (pDte) {

        // if not null
        if (pDte->FullDllName.Length != NULL) {

            // check if both equal
            ToLowerCaseWIDE(pDte->FullDllName.Buffer);
            ToLowerCaseWIDE(szModuleName);
            if (ComprareStringWIDE(pDte->FullDllName.Buffer, szModuleName)) {

                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

            }
        }
        else {
            break;
        }

        // next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRYC*)(pDte);

    }

    return NULL;
}

/*-------------------PEB STOMPING---------------------------*/

/*----------------SUPPORT FUNCTIONS------------------------*/
static void ParseForwarder(CHAR forwarder[], CHAR dll[], CHAR function[]) {

    int i = 0;
    while (forwarder[i]) {
        if (forwarder[i] == '.') {
            break;
        }
        i++;
    }
    for (int j = 0; j <= i; j++) {
        dll[j] = forwarder[j];
    }
    dll[i + 1] = 'd';
    dll[i + 2] = 'l';
    dll[i + 3] = 'l';
    dll[i + 4] = '\0';
    i++;
    int z = 0;
    while (forwarder[i]) {
        function[z] = forwarder[i];
        i++;
        z++;
    }
    function[z + 1] = '\0';
}

static void ConvertPointerToString(LPVOID pointer, char* buffer, size_t bufferSize) {
    const char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    uintptr_t value = reinterpret_cast<uintptr_t>(pointer);



    // Add "0x" prefix
    buffer[0] = '0';
    buffer[1] = 'x';

    // Convert each nibble to a hexadecimal digit
    for (int i = 15; i >= 0; --i) {
        buffer[2 + (15 - i)] = hexDigits[(value >> (i * 4)) & 0xF];
    }

    // Null-terminate the string
    buffer[18] = '\n';
    buffer[19] = '\0';
}


/*------------------GET PROC ADDRESS-------------------*/

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
            functionAddress = (PBYTE)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

            if (functionAddress >= (PBYTE)pImgExportDir && functionAddress < (PBYTE)(pImgExportDir + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {

                //here i have to get a substring
                ParseForwarder((CHAR*)functionAddress, dll, function);
                if ((LLA = (fnLoadLibraryA)GPAR(GMHR(kernel32), loadLibraryA)) == NULL)
                    return NULL;
                if (function[0] == '#') {

                    return GPARO(LLA(dll), custom_stoi(function));
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






FARPROC GPARO(IN HMODULE hModule, IN int ordinal) {

    // we do this to avoid casting at each time we use 'hModule'
    PBYTE pBase = (PBYTE)hModule;

    // getting the dos header and doing a signature check
    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // getting the nt headers and doing a signature check
    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // getting the optional header
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // we can get the optional header like this as well																								
    // PIMAGE_OPTIONAL_HEADER	pImgOptHdr	= (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

    // getting the image export table
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //getting the base = first ordinal value in the export table (DWORD 4 bytes)
    int base = (int)pImgExportDir->Base;
    int NumberOfFunctions = (int)pImgExportDir->NumberOfFunctions;

    //variables for forwarding
    WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR loadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    fnLoadLibraryA LLA = NULL;
    PBYTE functionAddress = NULL;
    CHAR forwarder[260] = { 0 };
    CHAR dll[260] = { 0 };
    CHAR function[260] = { 0 };


    //check if the ordinal falls into the range of ordinals of functions exported by the DLL
    if (ordinal < base || ordinal >= base + NumberOfFunctions) {

        return NULL;
    }

    // getting the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    // getting the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    // getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    // as specified here https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    // If the address specified is not within the export section (as defined by the address and length that are indicated
    // in the optional header), the field is an export RVA, which is an actual address in code or data. Otherwise, the field is a forwarder RVA,
    // // which names a symbol in another DLL.
    functionAddress = (PBYTE)(pBase + FunctionAddressArray[ordinal]);
    if (functionAddress >= (PBYTE)pImgExportDir && functionAddress < (PBYTE)(pImgExportDir + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {

        //here i have to get a substring
        ParseForwarder((CHAR*)functionAddress, dll, function);
        if ((LLA = (fnLoadLibraryA)GPAR(GMHR(kernel32), loadLibraryA)) == NULL)
            return NULL;
        if (function[0] == '#') {

            return GPARO(LLA(dll), custom_stoi(function));
        }
        else {
            return GPAR(LLA(dll), function);
        }

    }

    return (FARPROC)(pBase + FunctionAddressArray[ordinal]);

}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {


    // Call DllMain with proper arguments
    WCHAR SRH[] = { L'S', L'R', L'H', L'.', L'd', L'l', L'l', L'\0' };
    fnDllMain pDllMain = NULL;
    PBYTE pebase = NULL;
    pDllMain = (fnDllMain)lpParameter;
    pebase = (PBYTE)GMHR(SRH);

    return pDllMain((HMODULE)pebase, DLL_PROCESS_ATTACH, NULL);


}

