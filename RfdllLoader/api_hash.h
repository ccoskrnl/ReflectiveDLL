#pragma once

/*
 * DJB2 hash constants. Same algorithm as Shellcode/api_hash.h and
 * Shellcode/djb2_hash.py:
 *   hash = 5381; while (*p) hash = hash * 33 + (unsigned char)*p++;
 * Module names are hashed in lower case (that is how they are compared in the
 * PEB), export names are hashed exactly as they appear in the export table.
 */

/* Module names */
#define HASH_KERNEL32             0x7040ee75    /* kernel32.dll */
#define HASH_NTDLL                0x22d3b5ed    /* ntdll.dll    */

/* kernel32.dll exports */
#define HASH_LOADLIBRARYA         0x5fbff0fb    /* LoadLibraryA    */
#define HASH_GETPROCADDRESS       0xcf31bb1f    /* GetProcAddress  */
#define HASH_VIRTUALALLOC         0x382c0f97    /* VirtualAlloc    */
#define HASH_VIRTUALFREE          0x668fcf2e    /* VirtualFree     */
#define HASH_VIRTUALPROTECT       0x844ff18d    /* VirtualProtect  */

/* ntdll.dll exports */
#define HASH_RTLADDFUNCTIONTABLE     0xbdb9f1ae    /* RtlAddFunctionTable    */
#define HASH_RTLDELETEFUNCTIONTABLE  0xf6c5d058    /* RtlDeleteFunctionTable */
