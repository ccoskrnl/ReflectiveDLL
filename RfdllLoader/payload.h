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

/* Entry point of the packed payload. Takes no arguments. */
UINT64 entrypoint_packed(void);
