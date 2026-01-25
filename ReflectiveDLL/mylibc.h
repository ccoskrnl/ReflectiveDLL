#pragma once

#include "pch.h"
#include <stdint.h>

long long int my_strlen(const char* s);

int my_lltoa(long long value, char* buf, int base);

char* my_strncat(char* dest, const char* src, size_t n);

void* my_malloc(SIZE_T size);

void my_free(void* addr);

void* my_memset(void* ptr, int value, unsigned long n);

uint64_t my_byteswap_uint64(uint64_t val);
