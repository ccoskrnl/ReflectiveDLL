#!/usr/bin/env python3
"""
自动生成 C 头文件，包含字符串的 DJB2 哈希定义。
用法：直接运行脚本，输出重定向到 .h 文件。
"""

def djb2_hash_ascii(s: str) -> int:
    """计算字符串的 DJB2 哈希（32位），假设字符串为 ASCII"""
    hash_val = 5381
    for ch in s:
        hash_val = ((hash_val << 5) + hash_val) + ord(ch)
    return hash_val & 0xFFFFFFFF

def generate_macro_name(s: str) -> str:
    """根据字符串自动生成宏名：
    - 去除非字母数字字符（如 '.'）
    - 全部转为大写
    - 添加前缀 "HASH_"
    """
    # 只保留字母和数字
    cleaned = ''.join(ch for ch in s if ch.isalnum())
    return "HASH_" + cleaned.upper()

# ================== 在这里添加需要哈希的字符串 ==================
names = [
    "kernel32.dll",
    "winhttp.dll",
    "user32.dll",
    "ntdll.dll",
    "ws2_32.dll",
    "bcrypt.dll",
    

    "LoadLibraryA",
    "CreateThread",
    "GetProcAddress",
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",

    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "WinHttpReadData",
    "WinHttpCloseHandle",
    "WinHttpQueryHeaders",
    
    "RtlAddFunctionTable",
    "RtlDeleteFunctionTable",
    "LoadLibraryExA",
    "GetProcessId",
    "AddVectoredExceptionHandler",
    "RemoveVectoredExceptionHandler",

    "ZwFlushInstructionCache",
    "ZwCreateSection",
    "ZwMapViewOfSection",
    "ZwUnmapViewOfSection",
    "ZwQuerySystemInformation",
    "ZwQueryObject",
    "ZwDuplicateObject",
    "ZwOpenProcess",
    "ZwCreateThreadEx",
    "ZwSetContextThread",
    "ZwGetContextThread",
    "ZwReadVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwAllocateVirtualMemory",
    "ZwProtectVirtualMemory",
    "ZwQueryVirtualMemory",
    "ZwFreeVirtualMemory",
    "ZwOpenProcessToken",
    "ZwAdjustPrivilegesToken",
    "ZwClose",
    "NtMapViewOfSection",
    "NtCreateSection",
]
# ================================================================

def main():
    print("#ifndef HASH_DEFINES_H")
    print("#define HASH_DEFINES_H")
    print()
    # 计算每个宏的最大长度用于对齐
    macros = [generate_macro_name(name) for name in names]
    max_len = max(len(m) for m in macros)
    for name, macro in zip(names, macros):
        hash_val = djb2_hash_ascii(name)
        print(f"#define {macro:<{max_len}} 0x{hash_val:08x}")
    print()
    print("#endif // HASH_DEFINES_H")

if __name__ == "__main__":
    main()