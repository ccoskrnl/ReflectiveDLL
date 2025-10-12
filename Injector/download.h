#pragma once
#include "framework.h"
#include <Windows.h>
#include <vector>

std::vector<char> download_from_url(_in_ const char* url);

void encrypt_data(byte_t* begin, size_t size);
