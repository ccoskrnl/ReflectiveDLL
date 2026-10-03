/*
 * Reflective load test payload.
 *
 * Every step the loader is supposed to perform is recorded in target_marker.log
 * (written with kernel32 only, so it also works from a TLS callback, which the
 * loader - like the real one - runs before the CRT is initialized):
 *
 *   dll_attach      DllMain, DLL_PROCESS_ATTACH: CRT and imports resolved
 *   image_base      the base DllMain was given
 *   reloc_probe     contents of a global string pointer (DIR64 relocation)
 *   tls_flag        set when the TLS callback ran before DllMain
 *   dll_detach      DllMain, DLL_PROCESS_DETACH
 *
 * The exports are called by the host from the mapped image:
 *   TestReloc   reads the relocated global
 *   TestTlsFlag reads the flag the TLS callback wrote into .data
 *   TestSeh     raises an exception caught by its own __except, which only works
 *               when the loader registered the image's .pdata table
 */
#include <windows.h>

/* .data: the pointer itself needs a DIR64 fixup, so reading it only yields valid
 * memory when the image was relocated correctly. */
static const char* g_reloc_probe = "RELOC_PROBE_OK";

/* .data: written by the TLS callback, read back by an export. */
static DWORD g_tls_attach_seen = 0;

/*
 * .data: what the executing entry point told us about the payload, and whether
 * it was released. Kept so the host can query it through an export after
 * DllMain has returned.
 */
static DWORD g_payload_info_seen = 0;
static DWORD g_payload_freed = 0;
static unsigned long long g_payload_base = 0;
static unsigned long long g_payload_size = 0;

/* Provided by the linker: lets the payload report the base it runs at. */
extern IMAGE_DOS_HEADER __ImageBase;

static char* append_text(char* p, const char* text)
{
	while (*text != 0)
		*p++ = *text++;
	return p;
}

static char* append_hex(char* p, unsigned long long value)
{
	static const char digits[] = "0123456789abcdef";
	int shift = 0;

	*p++ = '0';
	*p++ = 'x';
	for (shift = 60; shift >= 0; shift -= 4)
		*p++ = digits[(value >> shift) & 0xF];
	return p;
}

/* Kernel32 only: safe before the CRT is initialized. */
static void log_line(const char* tag, unsigned long long value)
{
	char buffer[128];
	char* p = buffer;
	HANDLE file = INVALID_HANDLE_VALUE;
	DWORD written = 0;

	p = append_text(p, tag);
	*p++ = ' ';
	p = append_hex(p, value);
	*p++ = '\n';

	file = CreateFileA("target_marker.log", FILE_APPEND_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;
	WriteFile(file, buffer, (DWORD)(p - buffer), &written, NULL);
	CloseHandle(file);
}

static void log_text(const char* tag, const char* text)
{
	char buffer[128];
	char* p = buffer;
	HANDLE file = INVALID_HANDLE_VALUE;
	DWORD written = 0;

	p = append_text(p, tag);
	*p++ = ' ';
	p = append_text(p, text);
	*p++ = '\n';

	file = CreateFileA("target_marker.log", FILE_APPEND_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;
	WriteFile(file, buffer, (DWORD)(p - buffer), &written, NULL);
	CloseHandle(file);
}

/*
 * The payload info layout, mirrored from RfdllLoader/payload.h.
 *
 * The payload cannot include that header: it is written to be loaded as an
 * ordinary DLL by the reflective loader, and pulling in the loader's own
 * headers would drag in the loader internals. The layout is therefore repeated
 * here on purpose, and the magic and version are what catch a mismatch.
 */
#define RFDLL_PAYLOAD_INFO_MAGIC    0x494c4652
#define RFDLL_PAYLOAD_INFO_VERSION  1
#define RFDLL_PAYLOAD_INFO_OFFSET   0x40
#define RFDLL_PAYLOAD_FLAG_FREE_BY_DLL  0x00000001

typedef struct _RFDLL_PAYLOAD_INFO
{
	DWORD magic;
	DWORD version;
	void* payload_base;
	unsigned long long payload_size;
	void* image_base;
	unsigned long long image_size;
	DWORD host_hash;
	DWORD flags;
} RFDLL_PAYLOAD_INFO;

/*
 * A DllMain is often entered through the CRT's _DllMainCRTStartup, which is
 * free to pass on something other than the loader's pointer as lpReserved. The
 * loader writes the same structure at a fixed offset inside the image, so the
 * payload can always reach it from its own base. Both are tried, and the
 * in-image copy wins when both look valid, because it is the one the DLL is
 * documented to use.
 */
static const RFDLL_PAYLOAD_INFO* find_payload_info(LPVOID lp_reserved)
{
	const RFDLL_PAYLOAD_INFO* in_image =
		(const RFDLL_PAYLOAD_INFO*)((const unsigned char*)&__ImageBase + RFDLL_PAYLOAD_INFO_OFFSET);
	const RFDLL_PAYLOAD_INFO* from_argument = (const RFDLL_PAYLOAD_INFO*)lp_reserved;

	if (in_image->magic == RFDLL_PAYLOAD_INFO_MAGIC &&
		in_image->version == RFDLL_PAYLOAD_INFO_VERSION)
	{
		return in_image;
	}

	if (from_argument != NULL &&
		from_argument->magic == RFDLL_PAYLOAD_INFO_MAGIC &&
		from_argument->version == RFDLL_PAYLOAD_INFO_VERSION)
	{
		return from_argument;
	}

	return NULL;
}

/*
 * Hand the payload region back, once, and remember that it happened.
 *
 * Only the executing entry point asks for this: it wipes the payload and cannot
 * free it itself, because it is running from that very region when it starts.
 * The plain packed entry point keeps owning the payload, so for it this is
 * never called, which is why the result is recorded rather than assumed.
 */
static void release_payload(const RFDLL_PAYLOAD_INFO* info)
{
	if (info == NULL || info->payload_base == NULL || info->payload_size == 0)
		return;

	g_payload_base = (unsigned long long)(ULONG_PTR)info->payload_base;
	g_payload_size = info->payload_size;

	if (VirtualFree(info->payload_base, 0, MEM_RELEASE))
	{
		g_payload_freed = 1;
		log_text("payload_free", "ok");
	}
	else
	{
		log_line("payload_free_failed", (unsigned long long)GetLastError());
	}
}

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved)
{
	(void)module;
	(void)reserved;
	if (reason == DLL_PROCESS_ATTACH)
		g_tls_attach_seen = 1;	/* the loader must run this before DllMain */
}

/* A TLS callback registered this way makes the linker emit the TLS directory,
 * but only when _tls_used is pulled in. */
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_tls_callback = tls_callback;

__declspec(dllexport) int TestReloc(void)
{
	return g_reloc_probe[0] == 'R' ? 7 : 0;
}

__declspec(dllexport) int TestTlsFlag(void)
{
	return (int)g_tls_attach_seen;
}

__declspec(dllexport) int TestSeh(void)
{
	__try
	{
		RaiseException(0xE0000001, 0, 0, NULL);
	}
	__except (GetExceptionCode() == 0xE0000001 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		return 42;
	}
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		const RFDLL_PAYLOAD_INFO* info = find_payload_info(lpvReserved);

		log_line("dll_attach", (unsigned long long)(ULONG_PTR)hinstDLL);
		log_line("image_base", (unsigned long long)(ULONG_PTR)&__ImageBase);
		log_text("reloc_probe", g_reloc_probe);
		log_line("tls_flag", (unsigned long long)g_tls_attach_seen);

		if (info != NULL)
		{
			g_payload_info_seen = 1;
			log_line("payload_base", (unsigned long long)(ULONG_PTR)info->payload_base);
			log_line("payload_size", info->payload_size);
			log_line("payload_image", (unsigned long long)(ULONG_PTR)info->image_base);
		}
		else
		{
			log_text("payload_info", "absent");
		}

		/*
		 * The executing entry point wiped the payload and cannot release it
		 * itself, so it asks the payload to. The plain packed entry point keeps
		 * the payload as its own, and then this flag is not set.
		 */
		if (info != NULL && info->flags == RFDLL_PAYLOAD_FLAG_FREE_BY_DLL)
			release_payload(info);
		break;
	}
	case DLL_PROCESS_DETACH:
		log_line("dll_detach", (unsigned long long)(ULONG_PTR)hinstDLL);
		break;
	default:
		break;
	}

	return TRUE;
}

/* Read by the host from outside, after DllMain has run. */
__declspec(dllexport) int TestPayloadInfoSeen(void)
{
	return (int)g_payload_info_seen;
}

__declspec(dllexport) int TestPayloadFreed(void)
{
	return (int)g_payload_freed;
}

__declspec(dllexport) unsigned long long TestPayloadBase(void)
{
	return g_payload_base;
}

__declspec(dllexport) unsigned long long TestPayloadSize(void)
{
	return g_payload_size;
}
