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
	(void)lpvReserved;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		log_line("dll_attach", (unsigned long long)(ULONG_PTR)hinstDLL);
		log_line("image_base", (unsigned long long)(ULONG_PTR)&__ImageBase);
		log_text("reloc_probe", g_reloc_probe);
		log_line("tls_flag", (unsigned long long)g_tls_attach_seen);
		break;
	case DLL_PROCESS_DETACH:
		log_line("dll_detach", (unsigned long long)(ULONG_PTR)hinstDLL);
		break;
	default:
		break;
	}

	return TRUE;
}
