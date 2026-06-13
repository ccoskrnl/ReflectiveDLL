#pragma once
#include "pch.h"
#include "framework.h"
#include "headers.h"
#include <stdint.h>

// Macros
#define custom_min(a, b)    ((a) > (b) ? (b) : (a))
#define custom_max(a, b)    ((a) < (b) ? (b) : (a))


void* custom_malloc(SIZE_T size);
void custom_free(void* addr);
void* custom_memset(void* ptr, int value, unsigned long n);

void custom_memzero(void* ptr, unsigned int size);
void custom_memcpy_classic(void* pDestination, void* pSource, size_t sLength);
void custom_memset_zero(void* pDestination, size_t sLength);
errno_t custom_memcpy_s(void* dest, size_t destsz, void* src, size_t count);


size_t custom_strlen(char str[]);
size_t custom_wcslen(const wchar_t* str);

long long int custom_strlen(const char* s);
int custom_lltoa(long long value, char* buf, int base);
char* custom_strncat(char* dest, const char* src, size_t n);
void custom_wcscpy(wchar_t* dest, const wchar_t* src);
errno_t custom_wcscpy_s(WCHAR dest[], size_t destsz, WCHAR src[]);
char* custom_strcat(char dest[], char src[]);
size_t custom_wcstombs(CHAR dest[], WCHAR src[], size_t n);
size_t custom_mbstowcs(WCHAR dest[], CHAR src[], size_t n);

int str_icmp(const char* str1, const char* str2);
int custom_strcmp(const char* s1, const char* s2);
bool CompareNStringASCII(CHAR str1[], CHAR str2[], int n);
bool CompareStringASCII(CHAR str1[], CHAR str2[]);
bool ComprareNStringWIDE(WCHAR str1[], WCHAR str2[], int n);  // Note: name intentionally matches implementation
BOOL ComprareStringWIDE(WCHAR str1[], WCHAR str2[]);

void custom_wsstr(WCHAR str[], int start, int length, WCHAR result[]);
void custom_wsstr_end(WCHAR str[], int start, int length, WCHAR result[]);
void custom_sstr(CHAR str[], int start, int length, CHAR result[]);
int custom_wcsstr(WCHAR string[], WCHAR sub[]);
int custom_csstr(CHAR string[], CHAR sub[]);
int custom_find(char str[], char ch);
VOID custom_find_wide_reverse(WCHAR str[], WCHAR ch, int len, int* result);
BOOL containsSubstringUnicode(PWSTR str, WCHAR substring[], int strLen, int subLen);
BOOL containsSubstringASCII(CHAR str[], CHAR substring[]);


void ToLowerCaseWIDE(WCHAR str[]);


void ConvertDWORDToString(DWORD value, char* buffer, size_t bufferSize);
int custom_stoi(char str[]);
void custom_itoa(unsigned int value, CHAR buffer[]);

uint64_t custom_byteswap_uint64(uint64_t val);

