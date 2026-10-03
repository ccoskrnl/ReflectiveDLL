#pragma once
#include "framework.h"
#include "headers.h"

/*
 * Layout of the packed payload, as produced by pack.py:
 *
 *   +0x0000  loader.bin                     the code in this project
 *   ...      0xCC padding up to the next page boundary
 *   +meta    RFDLL_META_HEADER             19 bytes, see below
 *   +meta+19 rc4 key                       key_length bytes
 *   +...     rc4(pe image)                 dll_size bytes, decrypted in place
 *
 * The metadata always starts on a page boundary so that code and data never
 * share a page. pack.py refuses to build a payload whose code contains the
 * magic, which is what lets the loader find the metadata by scanning forward.
 *
 * The magic is compared as two 32 bit immediates in code rather than as a byte
 * array: this project's loader.bin may contain nothing but .text, so a global
 * constant would add a .rdata section and a relocation.
 */
#define RFDLL_MAGIC_LO  0x4c444652    /* "RFDL" of "RFDLMETA" */
#define RFDLL_MAGIC_HI  0x4154454d    /* "META" of "RFDLMETA" */

#define RFDLL_META_VERSION      1
#define RFDLL_META_HEADER_SIZE  19

/*
 * Layout limits shared with the packer. The payload is page aligned by pack.py,
 * and pe_loader.c uses the same page size for section rounding.
 */
#define RFDLL_PAGE_SIZE         0x1000
#define RFDLL_MAX_IMAGE_SIZE    0x7FFFFFFF
#define RFDLL_MAX_KEY_LENGTH    255

/* meta.flags */
#define RFDLL_FLAG_HEADERS_STRIPPED  0x01

/*
 * How far ahead of the loader code the metadata may sit. pack.py places it at
 * the next page boundary after the code, so one page of padding is normal; the
 * caller of the scan bounds it further by the end of the committed region.
 */
#define RFDLL_SCAN_LIMIT  (64 * 1024)

/* The metadata header, exactly 19 bytes (the fields are packed). */
#pragma pack(push, 1)
typedef struct _RFDLL_META
{
	BYTE  magic[8];      /* "RFDLMETA"                                       */
	BYTE  version;       /* RFDLL_META_VERSION                               */
	BYTE  flags;         /* RFDLL_FLAG_*                                     */
	BYTE  key_length;    /* RC4 key length, 0 means the image is stored raw  */
	DWORD dll_size;      /* size of the stored PE image                      */
	DWORD host_hash;     /* 0 = private mapping, else host module name hash  */
} RFDLL_META, *PRFDLL_META;
#pragma pack(pop)

/* Result of locating and validating the metadata. */
typedef struct _RFDLL_PAYLOAD
{
	PRFDLL_META meta;
	PBYTE       image;         /* dll_size bytes, decrypted in place */
	DWORD       image_size;
	const BYTE* key;           /* NULL when key_length is 0          */
	DWORD       key_length;
	DWORD       host_hash;
	BOOL        headers_stripped;
} RFDLL_PAYLOAD, *PRFDLL_PAYLOAD;

/*
 * Handed to the payload DLL so it can clean up after itself.
 *
 * The DLL cannot find the payload on its own: it never sees the loader's stack
 * and the image it runs from is somewhere else entirely. The loader therefore
 * passes this structure two ways, so a DLL can use whichever it can see:
 *
 *   1) as the lpReserved argument of DllMain (third parameter);
 *   2) as a copy at a fixed offset inside the mapped image, at
 *      RFDLL_PAYLOAD_INFO_OFFSET below.
 *
 * The copy exists because DllMain is often reached through the CRT's
 * _DllMainCRTStartup, which is free to pass something other than our pointer as
 * lpReserved. The DLL knows its own base, so the fixed offset is always
 * reachable; the build also strips the PE headers from the payload at pack
 * time, which is what frees that part of the image for this copy.
 *
 * The structure is only valid until the DLL releases the payload, so a DLL that
 * wants to keep it has to copy it first.
 */
#define RFDLL_PAYLOAD_INFO_MAGIC   0x494c4652    /* "RFLI" of "RFLINFO" */
#define RFDLL_PAYLOAD_INFO_VERSION 1

/*
 * info.flags value that tells the payload to release the payload region.
 *
 * Only the executing entry point sets it: that entry point wipes the payload
 * and cannot free it, because it is still running from that region when it
 * jumps away. The plain packed entry point keeps ownership of the payload, so
 * its payloads must not free anything and the flag stays clear.
 */
#define RFDLL_PAYLOAD_FLAG_FREE_BY_DLL  0x00000001

/* Where the copy lives inside the mapped image (inside the DOS stub area). */
#define RFDLL_PAYLOAD_INFO_OFFSET  0x40
#define RFDLL_PAYLOAD_INFO_SIZE    64

#pragma pack(push, 1)
typedef struct _RFDLL_PAYLOAD_INFO
{
	DWORD magic;         /* RFDLL_PAYLOAD_INFO_MAGIC, so a DLL can tell this
	                        structure from uninitialized image bytes          */
	DWORD version;       /* RFDLL_PAYLOAD_INFO_VERSION                        */
	PVOID payload_base;  /* start of the whole payload region                 */
	SIZE_T payload_size; /* size of that region, as the caller allocated it   */
	PVOID image_base;    /* base of the mapped image (the HINSTANCE DllMain
	                        receives as its first argument)                   */
	SIZE_T image_size;   /* SizeOfImage of that mapping                       */
	DWORD host_hash;     /* the metadata's host_hash, currently unused        */
	DWORD flags;         /* RFDLL_PAYLOAD_FLAG_*                              */
} RFDLL_PAYLOAD_INFO, *PRFDLL_PAYLOAD_INFO;
#pragma pack(pop)

/* Entry point of the packed payload. Takes no arguments. */
UINT64 entrypoint_packed(void);

/*
 * Entry point of the executing payload. Takes no arguments and never returns:
 * it maps the image, wipes the payload, then jumps into the image entry point
 * so no return address into the payload is left on the stack.
 *
 * It is written in assembly (entry_exec.asm) so the caller's stack pointer can
 * be read before any frame exists, and it is the first object on the link line
 * so that it sits at offset 0 of loader_exec.bin.
 *
 * Because it does not return, it cannot report a failure to its caller either:
 * a failure ends with the C part returning, and the assembly entry then returns
 * to the caller.
 */
void entrypoint_exec(void);

/*
 * The C part, called by entry_exec.asm with the stack pointer of the payload's
 * caller. Not meant to be called from anywhere else.
 */
void rfdll_exec_run(PBYTE caller_stack);

/*
 * Provided by tail_jump.asm. Enters the image entry point and never returns.
 *
 * caller_stack is the stack pointer the payload's caller had at its call, which
 * is where the image entry point runs from. Restoring it means the DLL's own
 * frame is the only thing on the stack and its return goes back to whoever
 * called the payload. The value is passed in rather than assumed because the
 * compiler decides the frame size.
 */
void rfdll_tail_jump(void* image_base, void* lp_reserved, void* entry, void* caller_stack);
