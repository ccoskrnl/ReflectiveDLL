#include "pch.h"
#include "framework.h"
#include "headers.h"
#include <stdint.h>

// =========================================================================
// custom_strlen - returns the length of a null-terminated string
// =========================================================================
long long int custom_strlen(const char* s) {
    const char* p = s;
    while (*p) p++;
    return p - s;
}

// =========================================================================
// custom_lltoa - converts a long long integer to a string in a given base
// =========================================================================
int custom_lltoa(long long value, char* buf, int base) {
    static const char digits[] = "0123456789";
    char temp[24];  /* enough for a 64-bit integer */
    int i = 0;
    int j = 0;

    /* handle negative numbers (only for base 10) */
    int is_negative = 0;
    unsigned long long n;
    if (value < 0 && base == 10) {
        is_negative = 1;
        n = (unsigned long long)(-value);
    }
    else {
        n = (unsigned long long)value;
    }

    /* generate digits in reverse order */
    do {
        temp[i++] = digits[n % base];
        n /= base;
    } while (n > 0);

    /* prepend '-' if negative */
    if (is_negative) {
        temp[i++] = '-';
    }

    /* reverse the string into the output buffer */
    while (i > 0) {
        buf[j++] = temp[--i];
    }
    buf[j] = '\0';

    return j;
}

// =========================================================================
// custom_strncat - appends up to n characters from src to dest
// =========================================================================
char* custom_strncat(char* dest, const char* src, size_t n) {
    if (dest == NULL || src == NULL || n == 0) {
        return dest;
    }

    char* d = dest;
    const char* s = src;

    /* find the end of dest */
    while (*d != '\0') {
        d++;
    }

    /* copy at most n characters (or until the null terminator of src) */
    while (n > 0 && *s != '\0') {
        *d = *s;
        d++;
        s++;
        n--;
    }

    /* ensure null termination */
    *d = '\0';

    return dest;
}

// =========================================================================
// custom_malloc - allocates memory using VirtualAlloc
// =========================================================================
void* custom_malloc(SIZE_T size) {
    void* addr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return addr;
}

// =========================================================================
// custom_free - releases memory allocated with custom_malloc
// =========================================================================
void custom_free(void* addr) {
    VirtualFree(addr, 0, MEM_RELEASE);
}

// =========================================================================
// custom_memset - sets the first n bytes of a memory block to a value
// =========================================================================
void* custom_memset(void* ptr, int value, unsigned long n) {
    if (ptr == NULL) {
        return NULL;
    }

    unsigned char* p = (unsigned char*)ptr;

    /* set each byte individually */
    while (n-- > 0) {
        *p++ = (unsigned char)value;
    }

    return ptr;
}

// =========================================================================
// custom_byteswap_uint64 - reverses the byte order of a 64‑bit integer
// =========================================================================
uint64_t custom_byteswap_uint64(uint64_t val) {
    return ((val & 0xFF00000000000000ULL) >> 56) |
        ((val & 0x00FF000000000000ULL) >> 40) |
        ((val & 0x0000FF0000000000ULL) >> 24) |
        ((val & 0x000000FF00000000ULL) >> 8) |
        ((val & 0x00000000FF000000ULL) << 8) |
        ((val & 0x0000000000FF0000ULL) << 24) |
        ((val & 0x000000000000FF00ULL) << 40) |
        ((val & 0x00000000000000FFULL) << 56);
}

// =========================================================================
// custom_strcmp - compares two strings lexicographically
// =========================================================================
int custom_strcmp(const char* s1, const char* s2) {
    /* compare character by character until a mismatch or end of string */
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }

    /* return the difference between the two characters */
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

size_t custom_wcstombs(CHAR dest[], WCHAR src[], size_t n) {
    size_t i = 0;
    for (i = 0; src[i] != L'\0' && i < n; ++i) {
        dest[i] = (char)src[i]; // Convert ASCII characters directly
    }
    dest[i] = '\0'; // Null-terminate the wide character string
    return i; // Return the number of converted characters
}

size_t custom_strlen(char str[]) {


    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len++;
}

size_t custom_wcslen(const wchar_t* str) {
    if (!str)
        return 0;

    size_t len = 0;

    while (str[len] != L'\0') {
        len++;
    }

    return len++;
}

void custom_wsstr(WCHAR str[], int start, int length, WCHAR result[]) {
    int i = 0;
    while (i < length && str[start + i] != L'\0') {
        result[i] = str[start + i];
        i++;
    }
    result[i] = L'\0'; // Null-terminate the result string
}

void custom_wsstr_end(WCHAR str[], int start, int length, WCHAR result[]) {
    int i = 0;
    while (i < length && str[start + i] != L'\0') {
        result[i] = str[start + i];
        i++;
    }
    result[i] = L'\0'; // Null-terminate the result string
}

void custom_sstr(CHAR str[], int start, int length, CHAR result[]) {
    int i = 0;
    while (i < length && str[start + i] != '\0') {
        result[i] = str[start + i];
        i++;
    }
    result[i] = '\0'; // Null-terminate the result string
}


void custom_memzero(void* ptr, unsigned int size) {
    unsigned char* p = (unsigned char*)ptr;

    while (size--) {
        *p++ = 0;
    }
}


void custom_memcpy_classic(void* pDestination, void* pSource, size_t sLength) {

    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--) {

        *D++ = *S++;
    }


}


void custom_memset_zero(void* pDestination, size_t sLength) {

    PBYTE D = (PBYTE)pDestination;
    while (sLength--) {

        *D++ = 0x00;
    }

}

void custom_wcscpy(wchar_t* dest, const wchar_t* src) {
    while ((*dest++ = *src++) != L'\0') {
        // Copy characters until the null-terminator is encountered
    }
}

void ToLowerCaseWIDE(WCHAR str[]) {



    size_t i = 0;

    while (str[i] != L'\0') {
        if (str[i] >= L'A' && str[i] <= L'Z') {
            str[i] = str[i] + 32; // Convert uppercase to lowercase
        }


        i++;
    }
    //return str;

}

int str_icmp(const char* str1, const char* str2) {
    while (*str1 != '\0' && *str2 != '\0') {
        char c1 = *str1;
        char c2 = *str2;

        // 将字符转换为小写（如果为大写字母）
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 += 32;  // 大写转小写
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 += 32;  // 大写转小写
        }

        // 比较转换后的字符
        if (c1 != c2) {
            return 0;  // 不相同返回FALSE
        }

        str1++;
        str2++;
    }

    // 检查是否同时到达字符串末尾
    return (*str1 == '\0' && *str2 == '\0') ? 1 : 0;
}

bool CompareNStringASCII(CHAR str1[], CHAR str2[], int n) {


    int i = 0;
    if (custom_strlen(str1) == 0 || custom_strlen(str2) == 0 || custom_strlen(str1) < n || custom_strlen(str2) < n) {
        return FALSE;
    }
    while (str1[i] && str2[i] && i < n) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return TRUE;
}

void ConvertDWORDToString(DWORD value, char* buffer, size_t bufferSize) {
    const char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };


    // Add "0x" prefix
    buffer[0] = '0';
    buffer[1] = 'x';

    // Convert each nibble to a hexadecimal digit
    for (int i = 7; i >= 0; --i) {
        buffer[2 + (7 - i)] = hexDigits[(value >> (i * 4)) & 0xF];
    }

    // Null-terminate the string
    buffer[10] = '\n';
    buffer[11] = '\0';
}

bool ComprareNStringWIDE(WCHAR str1[], WCHAR str2[], int n) {


    int i = 0;
    while (str1[i] && str2[i] && i < n) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return TRUE;
}

bool CompareStringASCII(CHAR str1[], CHAR str2[]) {

    if (custom_strlen(str1) != custom_strlen(str2)) {
        return false;
    }

    int i = 0;
    while (str1[i] && str2[i]) {

        if (str1[i] != str2[i]) {
            return false; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return true;
}

BOOL ComprareStringWIDE(WCHAR str1[], WCHAR str2[]) {

    int i = 0;

    while (str1[i] && str2[i]) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    return TRUE;
}

BOOL containsSubstringUnicode(PWSTR str, WCHAR substring[], int strLen, int subLen) {


    CHAR dest[100] = { 0 };

    if (subLen > strLen)
        return FALSE;

    for (size_t i = 0; i <= (strLen - subLen + 1); ++i) {

        for (int j = 0; j < subLen; j++) {

            if (str[i + j] != substring[j]) {

                break;
            }

            if (j == (subLen - 1)) {

                return TRUE;

            }

        }
    }

    return FALSE;
}

BOOL containsSubstringASCII(CHAR str[], CHAR substring[]) {

    size_t strLen = 0;
    size_t subLen = 0;
    strLen = custom_strlen(str);
    subLen = custom_strlen(substring);


    //if (subLen > strLen)
    //    return FALSE;

    for (size_t i = 0; i <= strLen - subLen; i++) {
        //MB(NULL, msg, msg, MB_OK | MB_ICONINFORMATION);
        if (CompareNStringASCII(str + i, substring, subLen) == 0)
            return TRUE;
    }

    return FALSE;
}




errno_t custom_wcscpy_s(WCHAR dest[], size_t destsz, WCHAR src[]) {


    size_t i = 0;
    while (i < destsz - 1 && src[i] != L'\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0'; // Null-terminate the destination string

    return 0; // Success
}

int custom_wcsstr(WCHAR string[], WCHAR sub[]) {

    int index = 0;
    int index_sub = 0;
    while (string[index] != L'\0') {


        while (string[index] == sub[index_sub] && string[index] != L'\0' && sub[index_sub] != L'\0') {
            index++;
            index_sub++;
        }

        if (sub[index_sub] == L'\0') {
            return (index - index_sub);
        }

        index++;
        index_sub = 0;
    }

    return 0;
}

int custom_csstr(CHAR string[], CHAR sub[]) {

    int index = 0;
    int index_sub = 0;
    while (string[index] != '\0') {


        while (string[index] == sub[index_sub] && string[index] != '\0' && sub[index_sub] != '\0') {
            index++;
            index_sub++;
        }

        if (sub[index_sub] == '\0') {
            return (index - index_sub);
        }

        index++;
        index_sub = 0;
    }

    return 0;
}

int custom_find(char str[], char ch) {


    int index = 0;
    while (str[index] != '\0') {
        if (str[index] == ch) {
            return index; // Character found; return its position (index)
        }
        index++;
    }

    return -1; // Character not found
}

VOID custom_find_wide_reverse(WCHAR str[], WCHAR ch, int len, int* result) {



    int index = len - 1;
    while (index >= 0) {

        if (str[index] == ch) {

            *result = index; // Character found; return its position (index)
        }
        index--;
    }
}

int custom_stoi(char str[]) {


    int result = 0;
    int i = 0;

    // Iterate through the string and convert characters to integers
    while (str[i] != '\0') {
        if (str[i] >= '0' && str[i] <= '9') {
            result = result * 10 + (str[i] - '0');
        }
        i++;
    }

    return result;
}

void custom_itoa(unsigned int value, CHAR buffer[]) {
    int i = 0;

    // Process individual digits
    do {
        buffer[i++] = '0' + value % 10;
        value /= 10;
    } while (value);

    buffer[i] = '\0'; // Null-terminate the string

    // Reverse the string
    int start = 0;
    int end = i - 1;
    while (start < end) {
        char temp = buffer[start];
        buffer[start] = buffer[end];
        buffer[end] = temp;
        start++;
        end--;
    }
}



errno_t custom_memcpy_s(void* dest, size_t destsz, void* src, size_t count) {
    if (!dest || !src || destsz < count) {
        return EINVAL; // Invalid parameters or insufficient space
    }

    PBYTE d = (PBYTE)dest;
    PBYTE s = (PBYTE)src;

    while (count--) {
        *d++ = *s++; // Copy bytes from source to destination
    }

    return 0; // Success
}

char* custom_strcat(char dest[], char src[]) {
    size_t dest_len = custom_strlen(dest);
    size_t i;

    for (i = 0; src[i] != '\0'; ++i) {
        dest[dest_len + i] = src[i];
    }
    dest[dest_len + i] = '\0'; // Null-terminate the concatenated string

    return dest;
}

size_t custom_mbstowcs(WCHAR dest[], CHAR src[], size_t n) {
    size_t i = 0;
    for (i = 0; src[i] != '\0' && i < n; ++i) {
        dest[i] = (wchar_t)src[i]; // Convert ASCII characters directly
    }
    dest[i] = L'\0'; // Null-terminate the wide character string
    return i; // Return the number of converted characters
}
