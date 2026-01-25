#include "utils.h"
#include <iostream>
#include <urlmon.h>
#include <wininet.h>
#include <fstream>
#include <filesystem>
#include <TlHelp32.h>

std::vector<char> download_from_url(_in_ const char* url) 
{
    std::vector<char> buffer;
    IStream* stream = nullptr;

    DeleteUrlCacheEntryA(url);

    HRESULT hr = URLOpenBlockingStreamA(
        nullptr,           // nullptr
        url,               // URL
        &stream,           // IStream interface
        0,                 // Reserved
        nullptr            // IBindStatusCallback
    );

    if (SUCCEEDED(hr) && stream) {
        std::cout << "[+] Successfully connected to the URL: " << url << std::endl;

        char readBuffer[4096];
        DWORD bytesRead = 0;

        while (true) {
            hr = stream->Read(readBuffer, sizeof(readBuffer), &bytesRead);

            if (hr != S_OK && bytesRead == 0) {
                break;  // read successfully.
            }

            if (bytesRead > 0) {
                buffer.insert(buffer.end(), readBuffer, readBuffer + bytesRead);
            }

            if (hr != S_OK) {
                break;  // read failed. 
            }
        }

        stream->Release();

        if (!buffer.empty()) {
            std::cout << "[+] Download completed, size: " << buffer.size() << " ×Ö½Ú" << std::endl;
        }
        else {
            std::cout << "[-] Download completed, but the data is empty" << std::endl;
        }

    }
    else {
        std::cout << "[-] Connecting URL failed: " << url << std::endl;
        std::cout << "[-] HRESULT: 0x" << std::hex << hr << std::dec << std::endl;

        LPSTR errorMessage = nullptr;
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            hr,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&errorMessage,
            0,
            nullptr
        );

        if (errorMessage) {
            std::cout << "[-] Download Error: " << errorMessage << std::endl;
            LocalFree(errorMessage);
        }
    }

    return buffer;
}

std::vector<char> load_local_file(_in_ const std::string& file_path)
{
    std::vector<char> buffer;

    try
    {
        std::filesystem::path absolute_path = std::filesystem::absolute(file_path);
        std::ifstream file(absolute_path, std::ios::binary | std::ios::ate);
        if (!file)
        {
            std::cout << "[-] Cannot open file: " << absolute_path << std::endl;
            return buffer;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        buffer.resize(size);
        if (!file.read(buffer.data(), size)) {
            std::cout << "[-] Error reading file: " << absolute_path << std::endl;
            buffer.clear();
            return buffer;
        }

        std::cout << "[+] Successfully loaded " << size << " bytes from: " << absolute_path << std::endl;

    }
    catch (const std::exception& e)
    {
        std::cout << "[-] Exception: " << e.what() << std::endl;
    }

    return buffer;
}

static void ob_xor(byte_t* begin, const size_t size, const byte_t* key, const size_t key_size) 
{
    for (size_t i = 0, j = 0; i < size; i++, j++)
    {
        begin[i] = begin[i] ^ key[j % key_size];
    }
}

void encrypt_data(byte_t* begin, size_t size)
{

    ob_xor(begin, size, Key::OB_XOR_KEY, Key::OB_XOR_KEY_SIZE);

}

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

wchar_t* get_wc(char* c_str)
{
    if (!c_str) return nullptr;

    const size_t c_size = strlen(c_str) + 1;
    wchar_t* wc = new (std::nothrow) wchar_t[c_size];
    if (!wc) return nullptr;  // Memory allocation failed

    size_t converted_chars = 0;
    errno_t err = mbstowcs_s(&converted_chars, wc, c_size, c_str, _TRUNCATE);

    if (err != 0) {
        delete[] wc;
        return nullptr;
    }

    return wc;
}

int ret_pid_by_name(wchar_t* proc_name)
{
    HANDLE proc_snap;
    PROCESSENTRY32 pe32;

    to_tower_case_wide(proc_name);

    // take a snapshot of all processes in the system.
    proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (proc_snap == INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] Unable to create snapshot of processes!" << std::endl;
        return 0;
    }

    // set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // retrieve information about the first process and exit if unsuccessful.
    if (!Process32First(proc_snap, &pe32))
    {
        std::cout << "[-] Unable to retrieve information about the first process!" << std::endl;
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

    } while (Process32Next(proc_snap, &pe32));

    CloseHandle(proc_snap);
    return 0;
}
