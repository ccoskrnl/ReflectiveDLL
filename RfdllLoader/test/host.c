/*
 * End to end test host for the reflective loader shellcode.
 *
 *   host <loader.bin> <target.dll> <fail.dll>
 *
 * It maps loader.bin as executable code and calls it as
 * UINT64 entry(PVOID image, UINT64 size).
 *
 * case 1  The host occupies target.dll's preferred base first, so the loader is
 *         forced onto the relocation path. Checked afterwards: the reported
 *         base differs from the preferred one, per section page protection, the
 *         exports are callable, the TLS callback and DllMain ran, a global
 *         pointer was relocated, and an exception raised inside the image is
 *         caught by the image's own handler (which needs the .pdata table the
 *         loader registered).
 *
 * case 2  load fail.dll, whose DllMain returns FALSE for DLL_PROCESS_ATTACH.
 *         Checked: the loader returns 0, DllMain(DLL_PROCESS_DETACH) and the TLS
 *         callback with DLL_PROCESS_DETACH ran in that order, and the image
 *         memory was released again.
 *
 * Exports are looked up by walking the export table by hand. GetProcAddress is
 * not used for that: the reflectively loaded image is deliberately not in the
 * PEB module list, so GetProcAddress may refuse to look at it. Its result is
 * printed for information.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long (*rfdll_entry)(void* image, unsigned long long size);

static int g_checks = 0;
static int g_failures = 0;

static void check(int ok, const char* what)
{
	g_checks++;
	if (ok)
	{
		printf("  [ ok ] %s\n", what);
	}
	else
	{
		g_failures++;
		printf("  [FAIL] %s\n", what);
	}
}

static unsigned char* read_file(const char* path, unsigned long* size_out)
{
	FILE* f = NULL;
	unsigned char* buffer = NULL;
	long size = 0;

	*size_out = 0;
	if (fopen_s(&f, path, "rb") != 0 || f == NULL)
		return NULL;

	if (fseek(f, 0, SEEK_END) != 0)
	{
		fclose(f);
		return NULL;
	}
	size = ftell(f);
	if (size <= 0)
	{
		fclose(f);
		return NULL;
	}
	rewind(f);

	buffer = (unsigned char*)malloc((size_t)size);
	if (buffer == NULL)
	{
		fclose(f);
		return NULL;
	}
	if (fread(buffer, 1, (size_t)size, f) != (size_t)size)
	{
		free(buffer);
		fclose(f);
		return NULL;
	}

	fclose(f);
	*size_out = (unsigned long)size;
	return buffer;
}

static int find_line(const char* path, const char* needle)
{
	FILE* f = NULL;
	char line[512];
	int index = 0;

	if (fopen_s(&f, path, "rb") != 0 || f == NULL)
		return 0;

	while (fgets(line, sizeof(line), f) != NULL)
	{
		index++;
		if (strstr(line, needle) != NULL)
		{
			fclose(f);
			return index;
		}
	}

	fclose(f);
	return 0;
}

/* TRUE when "first" appears before "second" in the marker log. */
static int order_ok(const char* path, const char* first, const char* second)
{
	int a = find_line(path, first);
	int b = find_line(path, second);

	return (a > 0 && b > 0 && a < b);
}

/* Value that follows <tag> in the marker log (0 when not found). */
static unsigned long long file_value(const char* path, const char* tag)
{
	FILE* f = NULL;
	char line[512];
	size_t tag_len = strlen(tag);
	unsigned long long value = 0;

	if (fopen_s(&f, path, "rb") != 0 || f == NULL)
		return 0;

	while (fgets(line, sizeof(line), f) != NULL)
	{
		if (strncmp(line, tag, tag_len) == 0)
		{
			const char* p = line + tag_len;
			while (*p == ' ' || *p == '\t')
				p++;
			value = _strtoui64(p, NULL, 16);
			break;
		}
	}

	fclose(f);
	return value;
}

static void truncate_file(const char* path)
{
	FILE* f = NULL;

	if (fopen_s(&f, path, "wb") == 0 && f != NULL)
		fclose(f);
}

static DWORD query_protect(const void* address)
{
	MEMORY_BASIC_INFORMATION info;

	memset(&info, 0, sizeof(info));
	if (VirtualQuery(address, &info, sizeof(info)) == 0)
		return 0;
	return info.Protect;
}

static DWORD query_state(const void* address)
{
	MEMORY_BASIC_INFORMATION info;

	memset(&info, 0, sizeof(info));
	if (VirtualQuery(address, &info, sizeof(info)) == 0)
		return 0;
	return info.State;
}

static const char* protection_name(DWORD protect)
{
	switch (protect & 0xFF)
	{
	case PAGE_NOACCESS: return "NOACCESS";
	case PAGE_READONLY: return "R";
	case PAGE_READWRITE: return "RW";
	case PAGE_EXECUTE: return "X";
	case PAGE_EXECUTE_READ: return "RX";
	case PAGE_EXECUTE_READWRITE: return "RWX";
	default: return "?";
	}
}

static const IMAGE_NT_HEADERS64* image_nt(const unsigned char* file)
{
	const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)file;

	return (const IMAGE_NT_HEADERS64*)(file + dos->e_lfanew);
}

/*
 * Per section page protection. With strict != 0 the exact protection the loader
 * computes is required, which is only meaningful when the payload's own code did
 * not run (case 3). Otherwise the payload may have tightened its own sections
 * while it initialized - a C runtime turns its writable .fptable (the control
 * flow guard table) read-only - so only the security relevant invariants are
 * asserted: executable sections are not writable, non executable sections are
 * not executable, and sections that are not writable in the file stay read-only.
 */
static void check_sections(unsigned long long base, const unsigned char* file, int strict)
{
	const IMAGE_NT_HEADERS64* nt = image_nt(file);
	const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
	WORD index = 0;

	for (index = 0; index < nt->FileHeader.NumberOfSections; index++)
	{
		char name[9];
		char what[192];
		DWORD expected = 0;
		DWORD observed = 0;

		if (section[index].Misc.VirtualSize == 0)
			continue;

		if ((section[index].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
			expected = PAGE_READONLY;
		else if ((section[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
			expected = (section[index].Characteristics & IMAGE_SCN_MEM_WRITE) != 0
				? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		else
			expected = (section[index].Characteristics & IMAGE_SCN_MEM_WRITE) != 0
				? PAGE_READWRITE : PAGE_READONLY;

		memcpy(name, section[index].Name, 8);
		name[8] = 0;
		observed = query_protect((const void*)(base + section[index].VirtualAddress)) & 0xFF;

		if (strict)
		{
			sprintf_s(what, sizeof(what), "section %-8s is %s (expected %s)",
				name, protection_name(observed), protection_name(expected));
			check(observed == expected, what);
		}
		else
		{
			int is_writable = (observed == PAGE_READWRITE || observed == PAGE_EXECUTE_READWRITE);
			int is_executable = (observed == PAGE_EXECUTE || observed == PAGE_EXECUTE_READ ||
				observed == PAGE_EXECUTE_READWRITE);
			int want_executable = (expected == PAGE_EXECUTE_READ || expected == PAGE_EXECUTE_READWRITE);
			int want_writable = (expected == PAGE_READWRITE || expected == PAGE_EXECUTE_READWRITE);
			int ok = (is_executable == want_executable) && (!is_writable || want_writable);

			sprintf_s(what, sizeof(what), "section %-8s is %s (loader sets %s, payload may tighten)",
				name, protection_name(observed), protection_name(expected));
			check(ok, what);
		}
	}
}

/* Page by page protection map, with the section that covers the page. */
static void dump_page_map(unsigned long long base, const unsigned char* file)
{
	const IMAGE_NT_HEADERS64* nt = image_nt(file);
	const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
	DWORD offset = 0;

	printf("  [*] page protection map (RVA:protection:covering section):\n");
	for (offset = 0; offset < nt->OptionalHeader.SizeOfImage; offset += 0x1000)
	{
		const char* owner = "-";
		char name[9];
		WORD index = 0;

		for (index = 0; index < nt->FileHeader.NumberOfSections; index++)
		{
			DWORD va = section[index].VirtualAddress;
			DWORD vs = section[index].Misc.VirtualSize;

			if (offset >= va && offset < (va + vs))
			{
				memcpy(name, section[index].Name, 8);
				name[8] = 0;
				owner = name;
				break;
			}
		}
		printf("    %05x:%-8s %s\n", offset, protection_name(query_protect((const void*)(base + offset))), owner);
	}
}

/* Compare the section headers in the file with the ones in the mapped image. */
static void dump_section_headers(unsigned long long base, const unsigned char* file)
{
	const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)file;
	const IMAGE_NT_HEADERS64* file_nt = image_nt(file);
	const IMAGE_NT_HEADERS64* mapped_nt = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
	const IMAGE_SECTION_HEADER* file_section = IMAGE_FIRST_SECTION(file_nt);
	const IMAGE_SECTION_HEADER* mapped_section = IMAGE_FIRST_SECTION(mapped_nt);
	WORD index = 0;

	printf("  [*] section headers, file vs mapped image:\n");
	printf("    SizeOfHeaders=0x%x SizeOfImage=0x%x SectionAlignment=0x%x\n",
		file_nt->OptionalHeader.SizeOfHeaders, file_nt->OptionalHeader.SizeOfImage,
		file_nt->OptionalHeader.SectionAlignment);
	for (index = 0; index < file_nt->FileHeader.NumberOfSections; index++)
	{
		char name[9];

		memcpy(name, file_section[index].Name, 8);
		name[8] = 0;
		printf("    %-9s file VA=%05x VS=%06x C=%08x | mapped VA=%05x VS=%06x C=%08x\n",
			name,
			file_section[index].VirtualAddress, file_section[index].Misc.VirtualSize,
			file_section[index].Characteristics,
			mapped_section[index].VirtualAddress, mapped_section[index].Misc.VirtualSize,
			mapped_section[index].Characteristics);
	}
}

/* Walks the export table by hand; see the note at the top of this file. */
static void* find_export(unsigned long long base, const unsigned char* file, const char* name)
{
	const IMAGE_NT_HEADERS64* nt = image_nt(file);
	const IMAGE_DATA_DIRECTORY* directory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	const IMAGE_EXPORT_DIRECTORY* exports = NULL;
	const DWORD* names = NULL;
	const WORD* ordinals = NULL;
	const DWORD* functions = NULL;
	DWORD index = 0;

	if (directory->VirtualAddress == 0 || directory->Size == 0)
		return NULL;

	exports = (const IMAGE_EXPORT_DIRECTORY*)(base + directory->VirtualAddress);
	names = (const DWORD*)(base + exports->AddressOfNames);
	ordinals = (const WORD*)(base + exports->AddressOfNameOrdinals);
	functions = (const DWORD*)(base + exports->AddressOfFunctions);

	for (index = 0; index < exports->NumberOfNames; index++)
	{
		const char* candidate = (const char*)(base + names[index]);

		if (strcmp(candidate, name) == 0)
			return (void*)(base + functions[ordinals[index]]);
	}

	return NULL;
}

/* Takes the preferred base away so the loader has to relocate. */
static void occupy_preferred_base(const unsigned char* file)
{
	const IMAGE_NT_HEADERS64* nt = image_nt(file);
	unsigned long long preferred = (unsigned long long)nt->OptionalHeader.ImageBase;
	void* squatter = NULL;

	if (query_state((const void*)(ULONG_PTR)preferred) != MEM_FREE)
	{
		printf("  [*] preferred base 0x%llx already in use\n", preferred);
	}
	else
	{
		squatter = VirtualAlloc((void*)(ULONG_PTR)preferred, nt->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		printf("  [*] squatter at 0x%llx: %p\n", preferred, squatter);
	}

	check(query_state((const void*)(ULONG_PTR)preferred) != MEM_FREE,
		"preferred base is occupied, so the loader cannot use it");
}

static void case_target(rfdll_entry entry, const unsigned char* file, unsigned long size)
{
	const IMAGE_NT_HEADERS64* nt = image_nt(file);
	unsigned long long preferred = (unsigned long long)nt->OptionalHeader.ImageBase;
	unsigned long long base = 0;
	int (*export_reloc)(void) = NULL;
	int (*export_tls)(void) = NULL;
	int (*export_seh)(void) = NULL;

	printf("\n=== case 1: load target.dll (relocation forced) ===\n");
	truncate_file("target_marker.log");
	occupy_preferred_base(file);

	base = entry((void*)file, size);
	printf("  [*] entry returned 0x%llx\n", base);
	check(base != 0, "loader returned an image base");
	if (base == 0)
		return;

	check(base != preferred, "image was relocated (base differs from preferred base)");
	check(query_protect((const void*)(ULONG_PTR)base) == PAGE_READONLY, "PE header page is R");
	check_sections(base, file, 0);
	dump_section_headers(base, file);
	dump_page_map(base, file);

	/* Probe: can this process still change that page by itself? */
	{
		DWORD old_protect = 0;
		BOOL ok = VirtualProtect((void*)(ULONG_PTR)(base + 0x1d000), 0x1000, PAGE_READWRITE, &old_protect);

		printf("  [*] probe VirtualProtect(base+0x1d000, RW): ok=%d old=%s now=%s\n",
			ok, protection_name(old_protect),
			protection_name(query_protect((const void*)(ULONG_PTR)(base + 0x1d000))));
	}

	check(file_value("target_marker.log", "tls_flag") == 1,
		"TLS callback ran before DllMain (flag it wrote was visible to DllMain)");
	check(find_line("target_marker.log", "dll_attach") > 0,
		"DllMain ran with DLL_PROCESS_ATTACH (CRT and imports resolved)");
	check(find_line("target_marker.log", "RELOC_PROBE_OK") > 0,
		"global string pointer was fixed up (DIR64 relocation applied)");
	check(file_value("target_marker.log", "image_base") == base,
		"DllMain saw the base the loader returned");

	export_reloc = (int (*)(void))find_export(base, file, "TestReloc");
	export_tls = (int (*)(void))find_export(base, file, "TestTlsFlag");
	export_seh = (int (*)(void))find_export(base, file, "TestSeh");
	check(export_reloc != NULL && export_tls != NULL && export_seh != NULL,
		"exports found in the mapped image's export table");
	printf("  [*] GetProcAddress on the mapped image: %p (informational)\n",
		(void*)GetProcAddress((HMODULE)(ULONG_PTR)base, "TestReloc"));

	if (export_reloc != NULL)
		check(export_reloc() == 7, "export reads the relocated global");
	if (export_tls != NULL)
		check(export_tls() == 1, "export reads the flag the TLS callback wrote to .data");

	if (export_seh != NULL)
	{
		__try
		{
			check(export_seh() == 42, "SEH handler inside the image was reached (.pdata registered)");
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			check(0, "SEH handler inside the image was reached (.pdata registered)");
		}
	}
}

/*
 * case 3: the same image with AddressOfEntryPoint set to 0, so the payload's own
 * code never runs and the page protection the loader applies can be checked
 * exactly, section by section. It also covers the documented "an image without
 * an entry point is accepted" path.
 */
static void case_protect_only(rfdll_entry entry, unsigned char* file, unsigned long size)
{
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(file + dos->e_lfanew);
	DWORD saved_entry_point = nt->OptionalHeader.AddressOfEntryPoint;
	unsigned long long base = 0;

	printf("\n=== case 3: load with AddressOfEntryPoint = 0 (loader protection only) ===\n");
	nt->OptionalHeader.AddressOfEntryPoint = 0;
	occupy_preferred_base(file);

	base = entry((void*)file, size);
	printf("  [*] entry returned 0x%llx\n", base);
	nt->OptionalHeader.AddressOfEntryPoint = saved_entry_point;
	check(base != 0, "loader returned an image base although the image has no entry point");
	if (base == 0)
		return;

	check(query_protect((const void*)(ULONG_PTR)base) == PAGE_READONLY, "PE header page is R");
	check_sections(base, file, 1);
	dump_page_map(base, file);
}

/*
 * case 4: the failure payload again, but with an entry point RVA outside the
 * image. The loader must treat the image as malformed: return 0, release the TLS
 * callbacks with DLL_PROCESS_DETACH (their ATTACH already ran), never call the
 * entry point, and release the image memory.
 */
static void case_bad_entry_point(rfdll_entry entry, unsigned char* file, unsigned long size)
{
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(file + dos->e_lfanew);
	DWORD saved_entry_point = nt->OptionalHeader.AddressOfEntryPoint;
	unsigned long long freed_base = 0;
	unsigned long long base = 0;

	printf("\n=== case 4: entry point RVA outside the image (malformed) ===\n");
	truncate_file("fail_marker.log");
	nt->OptionalHeader.AddressOfEntryPoint = nt->OptionalHeader.SizeOfImage + 0x1000;
	occupy_preferred_base(file);

	base = entry((void*)file, size);
	printf("  [*] entry returned 0x%llx\n", base);
	nt->OptionalHeader.AddressOfEntryPoint = saved_entry_point;
	check(base == 0, "loader rejected an image whose entry point RVA is outside the image");

	check(find_line("fail_marker.log", "tls_attach") > 0,
		"TLS callback still ran with DLL_PROCESS_ATTACH");
	check(find_line("fail_marker.log", "tls_detach") > 0,
		"TLS callback was released with DLL_PROCESS_DETACH");
	check(find_line("fail_marker.log", "dll_attach") == 0 &&
		find_line("fail_marker.log", "dll_detach") == 0,
		"the entry point itself was never called");

	freed_base = file_value("fail_marker.log", "tls_attach");
	check(freed_base != 0 && query_state((const void*)(ULONG_PTR)freed_base) == MEM_FREE,
		"image memory was released again");
}

static void case_fail(rfdll_entry entry, const unsigned char* file, unsigned long size)
{
	unsigned long long freed_base = 0;
	unsigned long long base = 0;

	printf("\n=== case 2: load fail.dll (entry point refuses to initialize) ===\n");
	truncate_file("fail_marker.log");
	occupy_preferred_base(file);

	base = entry((void*)file, size);
	printf("  [*] entry returned 0x%llx\n", base);
	check(base == 0, "loader returned 0 when the entry point refused to initialize");

	check(find_line("fail_marker.log", "tls_attach") > 0,
		"TLS callback ran with DLL_PROCESS_ATTACH before the entry point");
	check(find_line("fail_marker.log", "dll_attach") > 0,
		"entry point ran and reported failure");
	check(find_line("fail_marker.log", "dll_detach") > 0,
		"unwind called the entry point with DLL_PROCESS_DETACH");
	check(find_line("fail_marker.log", "tls_detach") > 0,
		"unwind called the TLS callback with DLL_PROCESS_DETACH");
	check(order_ok("fail_marker.log", "tls_attach", "dll_attach") &&
		order_ok("fail_marker.log", "dll_attach", "dll_detach") &&
		order_ok("fail_marker.log", "dll_detach", "tls_detach"),
		"unwind order is tls_attach, dll_attach, dll_detach, tls_detach");

	freed_base = file_value("fail_marker.log", "dll_attach");
	check(freed_base != 0 && query_state((const void*)(ULONG_PTR)freed_base) == MEM_FREE,
		"image memory was released again after the unwind");
}

/*
 * Case 5: packed payload.
 *
 * The payload is loader_packed.bin followed by its metadata and the RC4
 * encrypted DLL (see pack.py). The packed entry takes no arguments and finds
 * the metadata by itself, so the host only has to place the bytes somewhere
 * writable and executable and jump to offset 0.
 *
 * The expected image size is passed in by the caller because the packed
 * metadata is the loader's business; the host knows it from the packer report.
 */
static void case_packed(const unsigned char* payload, unsigned long payload_size,
	const unsigned char* dll_file)
{
	const IMAGE_NT_HEADERS64* nt = image_nt(dll_file);
	unsigned long long preferred = (unsigned long long)nt->OptionalHeader.ImageBase;
	unsigned long long base = 0;
	void* payload_mem = NULL;
	rfdll_entry entry = NULL;
	int (*export_reloc)(void) = NULL;
	int (*export_tls)(void) = NULL;

	printf("\n=== case 5: packed payload (0 argument entry) ===\n");
	truncate_file("target_marker.log");
	occupy_preferred_base(dll_file);

	/*
	 * The loader needs to write while it decrypts, so the payload goes into
	 * memory this process owns; a read only copy would fault inside the loader.
	 */
	payload_mem = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (payload_mem == NULL)
	{
		check(0, "host could allocate memory for the packed payload");
		return;
	}
	memcpy(payload_mem, payload, payload_size);
	FlushInstructionCache(GetCurrentProcess(), payload_mem, payload_size);
	printf("  [*] payload: %lu bytes at %p\n", payload_size, payload_mem);

	entry = (rfdll_entry)payload_mem;

	/* The packed entry ignores its arguments; pass zeros to prove it. */
	base = entry(NULL, 0);
	printf("  [*] entry returned 0x%llx\n", base);
	check(base != 0, "packed loader returned an image base");
	if (base == 0)
		return;

	check(base != preferred, "packed image was relocated");
	check(query_protect((const void*)(ULONG_PTR)base) == PAGE_READONLY, "packed PE header page is R");
	check_sections(base, dll_file, 0);
	dump_section_headers(base, dll_file);
	dump_page_map(base, dll_file);

	/* The DLL must be a working module, not just a mapped image. */
	export_reloc = (int (*)(void))find_export(base, dll_file, "TestReloc");
	export_tls = (int (*)(void))find_export(base, dll_file, "TestTlsFlag");
	check(export_reloc != NULL, "TestReloc is reachable through the export table");
	check(export_tls != NULL, "TestTlsFlag is reachable through the export table");

	if (export_reloc != NULL)
		check(export_reloc() != 0, "a relocated export still works in the packed image");
	if (export_tls != NULL)
		check(export_tls() != 0, "the TLS callback ran for the packed image");

	check(file_value("target_marker.log", "dll_attach") != 0, "DllMain saw DLL_PROCESS_ATTACH in the packed image");
}

int main(int argc, char** argv)
{
	unsigned char* loader_bytes = NULL;
	unsigned char* target_bytes = NULL;
	unsigned char* fail_bytes = NULL;
	unsigned char* payload_bytes = NULL;
	unsigned long loader_size = 0;
	unsigned long target_size = 0;
	unsigned long fail_size = 0;
	unsigned long payload_size = 0;
	void* loader_mem = NULL;

	setvbuf(stdout, NULL, _IONBF, 0);

	if (argc < 4)
	{
		printf("usage: %s <loader.bin> <target.dll> <fail.dll> [payload.bin]\n", argv[0]);
		return 2;
	}

	loader_bytes = read_file(argv[1], &loader_size);
	target_bytes = read_file(argv[2], &target_size);
	fail_bytes = read_file(argv[3], &fail_size);
	if (loader_bytes == NULL || target_bytes == NULL || fail_bytes == NULL)
	{
		printf("[FAIL] cannot read %s, %s or %s\n", argv[1], argv[2], argv[3]);
		return 2;
	}

	loader_mem = VirtualAlloc(NULL, loader_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (loader_mem == NULL)
	{
		printf("[FAIL] cannot allocate memory for loader.bin\n");
		return 2;
	}
	memcpy(loader_mem, loader_bytes, loader_size);
	FlushInstructionCache(GetCurrentProcess(), loader_mem, loader_size);
	printf("[*] loader.bin: %lu bytes mapped at %p\n", loader_size, loader_mem);

	case_target((rfdll_entry)loader_mem, target_bytes, target_size);
	case_protect_only((rfdll_entry)loader_mem, target_bytes, target_size);
	case_fail((rfdll_entry)loader_mem, fail_bytes, fail_size);
	case_bad_entry_point((rfdll_entry)loader_mem, fail_bytes, fail_size);

	/*
	 * The packed payload is optional: it needs a 4th argument and a packer run,
	 * so the three argument form still exercises everything above.
	 */
	if (argc >= 5)
	{
		payload_bytes = read_file(argv[4], &payload_size);
		if (payload_bytes == NULL)
		{
			printf("[FAIL] cannot read %s\n", argv[4]);
			return 2;
		}
		case_packed(payload_bytes, payload_size, target_bytes);
		free(payload_bytes);
	}
	else
	{
		printf("\n=== case 5: packed payload skipped (no payload.bin argument) ===\n");
	}

	free(loader_bytes);
	free(target_bytes);
	free(fail_bytes);

	printf("\n=== %d checks, %d failures ===\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
