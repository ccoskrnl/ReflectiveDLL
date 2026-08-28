#pragma once
#include "framework.h"
#include "headers.h"
#include <stdint.h>

// Macros
#define custom_min(a, b)    ((a) > (b) ? (b) : (a))
#define custom_max(a, b)    ((a) < (b) ? (b) : (a))

long long int custom_strlen(const char* s);

void ToLowerCaseWIDE(WCHAR str[]);

int custom_strcmp(const char* s1, const char* s2);

int custom_stoi(char str[]);

BOOL CompareStringASCII(CHAR str1[], CHAR str2[]);

BOOL ComprareStringWIDE(WCHAR str1[], WCHAR str2[]);
