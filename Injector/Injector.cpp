#include "framework.h"
#include "args.h"
#include "utils.h"
#include "dll.h"
#include "injector.h"
#include <vector>
#include <iostream>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")

const byte_t Injector::HEADER[] = { 0x41, 0x42, 0x43, 0x44 };
size_t Injector::DLL_HEADER_SIZE = 0;

int main(int argc, char* argv[])
{
    try {
        Injector injector(argc, argv);

        if (!injector.execute()) {
            std::cerr << "[-] Injection failed\n";
            return 1;
        }

        std::cout << "[+] Injection completed successfully\n";
        return 0;

    }
    catch (const std::exception& e) {
        std::cerr << "[-] Exception occurred: " << e.what() << std::endl;
        return 1;
    }
}

