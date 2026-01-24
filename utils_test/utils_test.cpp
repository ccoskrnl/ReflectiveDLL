// utils_test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "utils.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define _CRT_SECURE_NO_WARNINGS 1

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")

int main()
{
    std::cout << "Hello World!\n";
    init_connection();
}
