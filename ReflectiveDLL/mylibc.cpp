#include "pch.h"
#include "mylibc.h"

long long int my_strlen(const char* s) {
    const char* p = s;
    while (*p) p++;
    return p - s;
}

int my_lltoa(long long value, char* buf, int base) {
    static const char digits[] = "0123456789";
    char temp[24];  /* 足够存储64位整数 */
    int i = 0;
    int j = 0;

    /* 处理负数 */
    int is_negative = 0;
    unsigned long long n;
    if (value < 0 && base == 10) {
        is_negative = 1;
        n = (unsigned long long)(-value);
    }
    else {
        n = (unsigned long long)value;
    }

    /* 生成逆序字符串 */
    do {
        temp[i++] = digits[n % base];
        n /= base;
    } while (n > 0);

    /* 添加负号 */
    if (is_negative) {
        temp[i++] = '-';
    }

    /* 反转字符串 */
    while (i > 0) {
        buf[j++] = temp[--i];
    }
    buf[j] = '\0';

    return j;
}

char* my_strncat(char* dest, const char* src, size_t n) {
    if (dest == NULL || src == NULL || n == 0) {
        return dest;
    }

    char* d = dest;
    const char* s = src;

    /* 找到 dest 的末尾 */
    while (*d != '\0') {
        d++;
    }

    /* 最多复制 n 个字符（或遇到 src 的终止符）*/
    while (n > 0 && *s != '\0') {
        *d = *s;
        d++;
        s++;
        n--;
    }

    /* 确保终止符 */
    *d = '\0';

    return dest;
}

void* my_malloc(SIZE_T size)
{
    void* addr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return addr;
}

void my_free(void* addr)
{
    VirtualFree(addr, 0, MEM_RELEASE);
}

/* 将内存块的前 n 个字节设置为指定值 */
void* my_memset(void* ptr, int value, unsigned long n) {
    /* 检查指针是否为NULL */
    if (ptr == NULL) {
        return NULL;
    }

    /* 转换为字节指针，方便按字节操作 */
    unsigned char* p = (unsigned char*)ptr;

    /* 逐个字节设置值 */
    while (n-- > 0) {
        *p++ = (unsigned char)value;
    }

    return ptr;
}