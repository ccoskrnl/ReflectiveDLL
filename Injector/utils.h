#pragma once
#include "framework.h"
#include <Windows.h>
#include <vector>
#include <string>

std::vector<char> download_from_url(_in_ const char* url);
std::vector<char> load_local_file(_in_ const std::string& file_path);
void encrypt_data(byte_t* begin, size_t size);
int ret_pid_by_name(wchar_t* proc_name);

wchar_t* get_wc(char* c_str);
