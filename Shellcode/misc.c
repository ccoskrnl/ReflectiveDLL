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


BOOL CompareStringASCII(CHAR str1[], CHAR str2[]) {

    if (custom_strlen(str1) != custom_strlen(str2)) {
        return FALSE;
    }

    int i = 0;
    while (str1[i] && str2[i]) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return TRUE;
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
