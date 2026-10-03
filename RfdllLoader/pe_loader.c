#include "framework.h"
#include "api_hash.h"
#include "headers.h"
#include "ldr.h"
#include "misc.h"
#include "payload.h"
#include "pe_loader.h"

/*
 * This file is compiled into the shellcode as well (/NODEFAULTLIB, only .text
 * survives), so it must obey these rules:
 *   1) no string literals, no global or static data (those land in .rdata/.data
 *      and are dropped by objcopy);
 *   2) no direct call to an imported function (that would leave an IAT
 *      reference in .text); every API has to be resolved to a function pointer
 *      through GMHR_Hash / GPAR_Hash first;
 *   3) own memory copy routine, no CRT dependency.
 *
 * The PE that gets loaded is untrusted input: every RVA read from it is checked
 * against the size of the image (or of the caller's buffer) before it is turned
 * into a pointer. A failure unwinds what has already been applied (DllMain with
 * DLL_PROCESS_DETACH, TLS callbacks with DLL_PROCESS_DETACH, exception table
 * entry removed) and returns 0.
 */

/* ==================== CRT-free memory operations ==================== */

/*
 * Deliberately not named memset / memcpy: MSVC treats those as intrinsic
 * functions (/Oi) and as predefined library helpers (/GL), so defining them
 * raises C2169 / C2268 respectively, and both options are on in the Release
 * configuration of the VS project. The loop accesses are volatile on purpose:
 * otherwise /O2 recognises the whole loop as memcpy and rewrites it into a
 * library call, which loses self-containment (/NODEFAULTLIB then fails to link)
 * and produces an unresolvable library helper under /GL.
 */
static void* rfdll_memcpy(void* dest, const void* src, size_t count)
{
	volatile unsigned char* d = (volatile unsigned char*)dest;
	const volatile unsigned char* s = (const volatile unsigned char*)src;
	size_t i = 0;

	for (i = 0; i < count; i++)
		d[i] = s[i];

	return dest;
}

/* ============================ helpers ============================ */

/*
 * RFDLL_PAGE_SIZE and RFDLL_MAX_IMAGE_SIZE come from payload.h: the packed
 * payload layout and the section rounding here have to agree on them, so they
 * are defined in one place only.
 */

static DWORD rfdll_align_down(DWORD value, DWORD alignment)
{
	return value & ~(alignment - 1);
}

static DWORD rfdll_align_up(DWORD value, DWORD alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

/* Returns TRUE when [rva, rva + size) stays inside [0, limit). */
static BOOL rfdll_range_ok(DWORD rva, DWORD size, DWORD limit)
{
	if (rva > limit)
		return FALSE;
	if (size > limit - rva)
		return FALSE;
	return TRUE;
}

/*
 * NUL terminated string inside the image. The pointer handed to LoadLibraryA /
 * GetProcAddress must be terminated before the image ends, otherwise the API
 * would read past the allocation. On success *out points at the string.
 */
static BOOL rfdll_string_ok(PBYTE base, DWORD rva, DWORD limit, const char** out)
{
	DWORD i = 0;

	if (rva >= limit)
		return FALSE;

	for (i = rva; i < limit; i++)
	{
		if (base[i] == 0)
		{
			*out = (const char*)(base + rva);
			return TRUE;
		}
	}

	return FALSE;
}

/* Expand the sections of the file into the mapped image at their VirtualAddress. */
static void rfdll_map_sections(PBYTE base, const PBYTE file, UINT64 file_size, PIMAGE_NT_HEADERS64 nt_header)
{
	DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;
	DWORD size_of_headers = nt_header->OptionalHeader.SizeOfHeaders;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
	WORD index = 0;

	if (size_of_headers > (DWORD)file_size)
		size_of_headers = (DWORD)file_size;
	if (size_of_headers > size_of_image)
		size_of_headers = size_of_image;
	if (size_of_headers != 0)
		rfdll_memcpy(base, file, size_of_headers);

	for (index = 0; index < nt_header->FileHeader.NumberOfSections; index++)
	{
		DWORD virtual_address = section[index].VirtualAddress;
		DWORD virtual_size = section[index].Misc.VirtualSize;
		DWORD raw_size = section[index].SizeOfRawData;
		DWORD raw_offset = section[index].PointerToRawData;

		if (raw_size == 0 || raw_offset == 0)
			continue;
		if (virtual_address >= size_of_image)
			continue;

		/* Only VirtualSize bytes are guaranteed to exist in the mapped section. */
		if (virtual_size != 0 && raw_size > virtual_size)
			raw_size = virtual_size;
		if (raw_size > size_of_image - virtual_address)
			raw_size = size_of_image - virtual_address;

		/* Never read past the buffer the caller handed us either. */
		if ((UINT64)raw_offset >= file_size)
			continue;
		if ((UINT64)raw_size > file_size - raw_offset)
			raw_size = (DWORD)(file_size - raw_offset);
		if (raw_size == 0)
			continue;

		rfdll_memcpy(base + virtual_address, (PBYTE)file + raw_offset, raw_size);
	}
}

/* Base relocations, needed only when the actual base differs from the preferred one. */
static BOOL rfdll_relocate_image(PBYTE base, PIMAGE_NT_HEADERS64 nt_header, DWORD64 delta)
{
	IMAGE_DATA_DIRECTORY directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;
	DWORD offset = 0;

	if (directory.VirtualAddress == 0 || directory.Size == 0)
		return FALSE;	/* must relocate but has no relocation table -> preferred base only */

	if (!rfdll_range_ok(directory.VirtualAddress, directory.Size, size_of_image))
		return FALSE;

	while (offset < directory.Size)
	{
		PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)(base + directory.VirtualAddress + offset);
		PWORD entry = NULL;
		DWORD count = 0;
		DWORD i = 0;

		if (!rfdll_range_ok(directory.VirtualAddress + offset, sizeof(IMAGE_BASE_RELOCATION), size_of_image))
			return FALSE;
		if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
			return FALSE;
		if (block->SizeOfBlock > directory.Size - offset)
			return FALSE;

		count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		entry = (PWORD)((PBYTE)block + sizeof(IMAGE_BASE_RELOCATION));

		for (i = 0; i < count; i++)
		{
			WORD type = (WORD)(entry[i] >> 12);
			WORD rva = (WORD)(entry[i] & 0x0FFF);
			UINT64 target = (UINT64)block->VirtualAddress + rva;	/* 64 bit: must not wrap */
			DWORD target_rva = 0;
			DWORD width = 0;

			if (type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (type == IMAGE_REL_BASED_DIR64)
				width = sizeof(UINT64);
			else if (type == IMAGE_REL_BASED_HIGHLOW)
				width = sizeof(UINT32);
			else
				return FALSE;	/* no other relocation type may appear in an x64 image */

			if (target >= size_of_image)
				return FALSE;

			target_rva = (DWORD)target;
			if (size_of_image - target_rva < width)
				return FALSE;

			if (type == IMAGE_REL_BASED_DIR64)
				*(UINT64*)(base + target_rva) += delta;
			else
				*(UINT32*)(base + target_rva) += (UINT32)delta;
		}

		offset += block->SizeOfBlock;
	}

	return TRUE;
}

/*
 * Import table: LoadLibraryA pulls in the dependency, GetProcAddress fills the
 * IAT. Descriptor, thunk and name RVAs are bounds checked before use, so a
 * crafted image cannot make this write outside the mapped image.
 */
static BOOL rfdll_fix_imports(PBYTE base, PIMAGE_NT_HEADERS64 nt_header,
	fnLoadLibraryA load_library, fnGetProcAddress get_proc_address)
{
	IMAGE_DATA_DIRECTORY directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;
	DWORD descriptor_count = 0;
	DWORD index = 0;

	if (directory.VirtualAddress == 0 || directory.Size == 0)
		return TRUE;	/* an image without imports is legal */

	if (directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
		return FALSE;
	if (!rfdll_range_ok(directory.VirtualAddress, directory.Size, size_of_image))
		return FALSE;

	descriptor_count = directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	for (index = 0; index < descriptor_count; index++)
	{
		PIMAGE_IMPORT_DESCRIPTOR descriptor =
			(PIMAGE_IMPORT_DESCRIPTOR)(base + directory.VirtualAddress) + index;
		const char* module_name = NULL;
		DWORD lookup_rva = 0;
		DWORD thunk_rva = 0;
		HMODULE module = NULL;

		if (descriptor->Name == 0 && descriptor->FirstThunk == 0)
			break;	/* terminator */

		if (descriptor->Name == 0 || descriptor->FirstThunk == 0)
			return FALSE;

		if (!rfdll_string_ok(base, descriptor->Name, size_of_image, &module_name))
			return FALSE;
		if (!rfdll_range_ok(descriptor->FirstThunk, sizeof(IMAGE_THUNK_DATA64), size_of_image))
			return FALSE;

		/* Names come from OriginalFirstThunk; when it is absent the IAT itself is
		   the lookup table (imports that are not bound). */
		lookup_rva = descriptor->OriginalFirstThunk != 0
			? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
		thunk_rva = descriptor->FirstThunk;

		if (!rfdll_range_ok(lookup_rva, sizeof(IMAGE_THUNK_DATA64), size_of_image))
			return FALSE;

		module = load_library(module_name);
		if (module == NULL)
			return FALSE;

		for (;;)
		{
			PIMAGE_THUNK_DATA64 lookup = NULL;
			PIMAGE_THUNK_DATA64 address = NULL;
			FARPROC proc = NULL;

			/* The thunk array has to end inside the image, otherwise walk no further. */
			if (!rfdll_range_ok(lookup_rva, sizeof(IMAGE_THUNK_DATA64), size_of_image))
				return FALSE;
			if (!rfdll_range_ok(thunk_rva, sizeof(IMAGE_THUNK_DATA64), size_of_image))
				return FALSE;

			lookup = (PIMAGE_THUNK_DATA64)(base + lookup_rva);
			address = (PIMAGE_THUNK_DATA64)(base + thunk_rva);

			if (lookup->u1.AddressOfData == 0)
				break;

			if (IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal))
			{
				proc = get_proc_address(module, (LPCSTR)IMAGE_ORDINAL64(lookup->u1.Ordinal));
			}
			else
			{
				const char* import_name = NULL;
				ULONGLONG name_rva = lookup->u1.AddressOfData;

				/*
				 * IMAGE_IMPORT_BY_NAME is a 2 byte hint followed by the name. The RVA
				 * has to fit into 32 bits before the hint offset is added, otherwise
				 * the addition below could wrap around.
				 */
				if (name_rva > (ULONGLONG)RFDLL_MAX_IMAGE_SIZE)
					return FALSE;
				if (name_rva + sizeof(WORD) > (ULONGLONG)size_of_image)
					return FALSE;
				if (!rfdll_string_ok(base, (DWORD)(name_rva + sizeof(WORD)), size_of_image, &import_name))
					return FALSE;

				proc = get_proc_address(module, import_name);
			}

			if (proc == NULL)
				return FALSE;

			address->u1.Function = (UINT64)proc;

			lookup_rva += (DWORD)sizeof(IMAGE_THUNK_DATA64);
			thunk_rva += (DWORD)sizeof(IMAGE_THUNK_DATA64);
		}
	}

	return TRUE;
}

/*
 * TLS callbacks (reason is DLL_PROCESS_ATTACH on load, DLL_PROCESS_DETACH when a
 * load has to be abandoned). Their addresses are already relocated at this
 * point. Both the TLS directory and the callback array have to lie inside the
 * image, otherwise the loop would walk and call arbitrary memory.
 */
static void rfdll_call_tls_callbacks(PBYTE base, PIMAGE_NT_HEADERS64 nt_header, DWORD reason)
{
	IMAGE_DATA_DIRECTORY directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;
	PIMAGE_TLS_DIRECTORY64 tls = NULL;
	UINT64 image_start = (UINT64)base;
	UINT64 image_end = (UINT64)base + size_of_image;

	if (directory.VirtualAddress == 0 || directory.Size < sizeof(IMAGE_TLS_DIRECTORY64))
		return;
	if (!rfdll_range_ok(directory.VirtualAddress, sizeof(IMAGE_TLS_DIRECTORY64), size_of_image))
		return;

	tls = (PIMAGE_TLS_DIRECTORY64)(base + directory.VirtualAddress);
	if (tls->AddressOfCallBacks == 0)
		return;
	if (tls->AddressOfCallBacks < image_start || tls->AddressOfCallBacks >= image_end)
		return;

	{
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

		while ((UINT64)callback + sizeof(PIMAGE_TLS_CALLBACK) <= image_end)
		{
			PIMAGE_TLS_CALLBACK entry = *callback;

			if (entry == NULL)
				break;

			entry((PVOID)base, reason, NULL);
			callback++;
		}
	}
}

/* x64 exception table: .pdata entries have to be registered or unwinding fails. */
static void rfdll_register_exception_table(PBYTE base, PIMAGE_NT_HEADERS64 nt_header,
	fnRtlAddFunctionTable add_function_table)
{
	IMAGE_DATA_DIRECTORY directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;
	DWORD count = 0;

	if (directory.VirtualAddress == 0 || directory.Size < sizeof(RUNTIME_FUNCTION))
		return;
	if (!rfdll_range_ok(directory.VirtualAddress, directory.Size, size_of_image))
		return;

	count = directory.Size / sizeof(RUNTIME_FUNCTION);
	add_function_table((PRUNTIME_FUNCTION)(base + directory.VirtualAddress), count, (DWORD64)base);
}

/* Undo rfdll_register_exception_table when a load has to be abandoned. */
static void rfdll_unregister_exception_table(PBYTE base, PIMAGE_NT_HEADERS64 nt_header,
	fnRtlDeleteFunctionTable delete_function_table)
{
	IMAGE_DATA_DIRECTORY directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;

	if (directory.VirtualAddress == 0 || directory.Size < sizeof(RUNTIME_FUNCTION))
		return;
	if (!rfdll_range_ok(directory.VirtualAddress, directory.Size, size_of_image))
		return;

	delete_function_table((PRUNTIME_FUNCTION)(base + directory.VirtualAddress));
}

/*
 * Tighten page protection per section. Everything is allocated as
 * PAGE_EXECUTE_READWRITE, so sections that are not needed afterwards (for
 * example .reloc) end up read-only instead of staying writable and executable.
 * Protection is page granular, so the gaps between sections keep the initial
 * RWX protection.
 */
static void rfdll_protect_sections(PBYTE base, PIMAGE_NT_HEADERS64 nt_header, fnVirtualProtect virtual_protect)
{
	DWORD size_of_image = nt_header->OptionalHeader.SizeOfImage;
	DWORD size_of_headers = nt_header->OptionalHeader.SizeOfHeaders;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
	DWORD old_protect = 0;
	WORD index = 0;

	if (size_of_headers > size_of_image)
		size_of_headers = size_of_image;
	if (size_of_headers != 0)
	{
		DWORD header_end = rfdll_align_up(size_of_headers, RFDLL_PAGE_SIZE);
		if (header_end > size_of_image)
			header_end = size_of_image;
		virtual_protect(base, header_end, PAGE_READONLY, &old_protect);
	}

	for (index = 0; index < nt_header->FileHeader.NumberOfSections; index++)
	{
		DWORD start = 0;
		DWORD end = 0;
		DWORD protect = 0;
		UINT64 section_end = 0;

		if (section[index].Misc.VirtualSize == 0)
			continue;

		if ((section[index].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
		{
			protect = PAGE_READONLY;
		}
		else if ((section[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
		{
			protect = (section[index].Characteristics & IMAGE_SCN_MEM_WRITE) != 0
				? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		}
		else
		{
			protect = (section[index].Characteristics & IMAGE_SCN_MEM_WRITE) != 0
				? PAGE_READWRITE : PAGE_READONLY;
		}

		/* 64 bit arithmetic: VirtualAddress + VirtualSize must not wrap around. */
		section_end = (UINT64)section[index].VirtualAddress + section[index].Misc.VirtualSize;
		if (section_end > size_of_image)
			section_end = size_of_image;

		start = rfdll_align_down(section[index].VirtualAddress, RFDLL_PAGE_SIZE);
		if (start >= size_of_image || section_end <= start)
			continue;

		end = (DWORD)((section_end + RFDLL_PAGE_SIZE - 1) & ~(UINT64)(RFDLL_PAGE_SIZE - 1));
		if (end > size_of_image)
			end = size_of_image;
		if (end <= start)
			continue;

		virtual_protect(base + start, end - start, protect, &old_protect);
	}
}

/* ============================== main flow ============================== */

UINT64 rfdll_load_image(PVOID image, UINT64 image_size)
{
	PIMAGE_DOS_HEADER dos_header = NULL;
	PIMAGE_NT_HEADERS64 nt_header = NULL;
	PBYTE base = NULL;
	DWORD64 preferred_base = 0;
	DWORD64 delta = 0;
	DWORD size_of_image = 0;
	DWORD entry_point_rva = 0;
	HMODULE kernel32 = NULL;
	HMODULE ntdll = NULL;
	fnLoadLibraryA load_library = NULL;
	fnGetProcAddress get_proc_address = NULL;
	fnVirtualAlloc virtual_alloc = NULL;
	fnVirtualFree virtual_free = NULL;
	fnVirtualProtect virtual_protect = NULL;
	fnRtlAddFunctionTable add_function_table = NULL;
	fnRtlDeleteFunctionTable delete_function_table = NULL;
	UINT64 sections_end = 0;

	if (image == NULL)
		return 0;

	/* Everything below works on DWORDs, so clamp sizes that cannot occur. */
	if (image_size > RFDLL_MAX_IMAGE_SIZE)
		image_size = RFDLL_MAX_IMAGE_SIZE;
	if (image_size < sizeof(IMAGE_DOS_HEADER))
		return 0;

	/* ---------- 1. validate the PE ---------- */
	dos_header = (PIMAGE_DOS_HEADER)image;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	if ((UINT64)dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > image_size)
		return 0;

	nt_header = (PIMAGE_NT_HEADERS64)((PBYTE)image + dos_header->e_lfanew);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
		return 0;
	if (nt_header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		return 0;
	if (nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 0;
	if (nt_header->FileHeader.NumberOfSections == 0 || nt_header->FileHeader.NumberOfSections > 96)
		return 0;

	/*
	 * SizeOfOptionalHeader decides where the section table starts, so it has to
	 * be the standard one; the whole section table then has to fit into the
	 * buffer the caller handed us before rfdll_map_sections reads it.
	 */
	if (nt_header->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64))
		return 0;
	sections_end = (UINT64)dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64) +
		(UINT64)nt_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	if (sections_end > image_size)
		return 0;

	size_of_image = nt_header->OptionalHeader.SizeOfImage;
	preferred_base = (DWORD64)nt_header->OptionalHeader.ImageBase;
	entry_point_rva = nt_header->OptionalHeader.AddressOfEntryPoint;
	if (size_of_image == 0 || size_of_image > RFDLL_MAX_IMAGE_SIZE)
		return 0;

	/* ---------- 2. resolve the APIs by hash, leaving no static imports ---------- */
	kernel32 = GMHR_Hash(HASH_KERNEL32);
	if (kernel32 == NULL)
		return 0;

	load_library = (fnLoadLibraryA)GPAR_Hash(kernel32, HASH_LOADLIBRARYA);
	get_proc_address = (fnGetProcAddress)GPAR_Hash(kernel32, HASH_GETPROCADDRESS);
	virtual_alloc = (fnVirtualAlloc)GPAR_Hash(kernel32, HASH_VIRTUALALLOC);
	virtual_free = (fnVirtualFree)GPAR_Hash(kernel32, HASH_VIRTUALFREE);
	virtual_protect = (fnVirtualProtect)GPAR_Hash(kernel32, HASH_VIRTUALPROTECT);
	if (load_library == NULL || get_proc_address == NULL || virtual_alloc == NULL ||
		virtual_free == NULL || virtual_protect == NULL)
		return 0;

	ntdll = GMHR_Hash(HASH_NTDLL);
	if (ntdll != NULL)
	{
		add_function_table = (fnRtlAddFunctionTable)GPAR_Hash(ntdll, HASH_RTLADDFUNCTIONTABLE);
		delete_function_table = (fnRtlDeleteFunctionTable)GPAR_Hash(ntdll, HASH_RTLDELETEFUNCTIONTABLE);
	}

	/* ---------- 3. allocate the image, preferred base first ---------- */
	base = (PBYTE)virtual_alloc((LPVOID)preferred_base, size_of_image,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (base == NULL)
	{
		base = (PBYTE)virtual_alloc(NULL, size_of_image,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	if (base == NULL)
		return 0;

	delta = (DWORD64)base - preferred_base;

	/* ---------- 4. map the sections ---------- */
	rfdll_map_sections(base, (const PBYTE)image, image_size, nt_header);

	/* ---------- 5. relocations ---------- */
	if (delta != 0)
	{
		if (!rfdll_relocate_image(base, nt_header, delta))
		{
			virtual_free(base, 0, MEM_RELEASE);
			return 0;
		}
	}

	/* ---------- 6. import table ---------- */
	if (!rfdll_fix_imports(base, nt_header, load_library, get_proc_address))
	{
		virtual_free(base, 0, MEM_RELEASE);
		return 0;
	}

	/*
	 * ---------- 7. exception table ----------
	 * Registered before the TLS callbacks run, like the real loader does: a TLS
	 * callback that raises an exception needs the .pdata entries already in place.
	 * The delete helper has to be available as well, otherwise a registration
	 * could not be undone if the load has to be abandoned later.
	 */
	if (add_function_table != NULL && delete_function_table != NULL)
		rfdll_register_exception_table(base, nt_header, add_function_table);

	/* ---------- 8. TLS callbacks ---------- */
	rfdll_call_tls_callbacks(base, nt_header, DLL_PROCESS_ATTACH);

	/* ---------- 9. per-section page protection ---------- */
	rfdll_protect_sections(base, nt_header, virtual_protect);

	/* ---------- 10. enter the image entry point with DLL_PROCESS_ATTACH ---------- */
	if (entry_point_rva != 0)	/* 0 means: the image simply has no entry point */
	{
		fnDllMain dll_main = NULL;

		if (entry_point_rva >= size_of_image)
		{
			/*
			 * A non zero entry point outside the image is a malformed image: undo
			 * what was applied (the TLS callbacks already ran, the entry point did
			 * not) and fail.
			 */
			rfdll_call_tls_callbacks(base, nt_header, DLL_PROCESS_DETACH);
			if (add_function_table != NULL && delete_function_table != NULL)
				rfdll_unregister_exception_table(base, nt_header, delete_function_table);
			virtual_free(base, 0, MEM_RELEASE);
			return 0;
		}

		dll_main = (fnDllMain)(base + entry_point_rva);
		if (!dll_main((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL))
		{
			/*
			 * The image refused to initialize. Undo what was applied, in the order
			 * the real loader uses for an unload: DllMain with DLL_PROCESS_DETACH,
			 * then the TLS callbacks with DLL_PROCESS_DETACH, then drop the
			 * exception table entry so no dynamic function table keeps pointing
			 * into memory that is about to be released.
			 */
			dll_main((HINSTANCE)base, DLL_PROCESS_DETACH, NULL);
			rfdll_call_tls_callbacks(base, nt_header, DLL_PROCESS_DETACH);
			if (add_function_table != NULL && delete_function_table != NULL)
				rfdll_unregister_exception_table(base, nt_header, delete_function_table);
			virtual_free(base, 0, MEM_RELEASE);
			return 0;
		}
	}

	return (UINT64)base;
}
