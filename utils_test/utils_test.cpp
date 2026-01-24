// utils_test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "framework.h"
#include <iostream>
#include "utils.h"


#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "gdiplus.lib")

int main()
{
    std::cout << "Hello World!\n";
    //init_connection();

    HMODULE hGdi32 = LoadLibraryA("gdi32.dll");
    std::cout << GetLastError() << std::endl;

    return 0;
}
