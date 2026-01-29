#pragma once

#include "pch.h"
#include "framework.h"

#include "dll_headers.h"

char* create_temp_filename(const char* basename, kernel32_functions_t* kernel_funcs);
int cleanup_temp_file(const char* filename, kernel32_functions_t* kernel_funcs);
