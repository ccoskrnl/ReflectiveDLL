/*
 * Reflective load failure payload.
 *
 * DllMain refuses DLL_PROCESS_ATTACH, so the loader has to unwind: it must call
 * DllMain with DLL_PROCESS_DETACH, then the TLS callback with
 * DLL_PROCESS_DETACH, then drop the .pdata registration and release the image.
 *
 * fail_marker.log must therefore contain, in this order:
 *
 *   tls_attach   TLS callback, DLL_PROCESS_ATTACH
 *   dll_attach   DllMain,    DLL_PROCESS_ATTACH   (returns FALSE)
 *   dll_detach   DllMain,    DLL_PROCESS_DETACH
 *   tls_detach   TLS callback, DLL_PROCESS_DETACH
 *
 * The base logged by dll_attach lets the host verify that the image memory was
 * released again. Logging uses kernel32 only, because the TLS callback runs
 * before the CRT is initialized.
 */
#include <windows.h>

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

	file = CreateFileA("fail_marker.log", FILE_APPEND_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;
	WriteFile(file, buffer, (DWORD)(p - buffer), &written, NULL);
	CloseHandle(file);
}

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved)
{
	(void)reserved;
	log_line(reason == DLL_PROCESS_ATTACH ? "tls_attach" : "tls_detach",
		(unsigned long long)(ULONG_PTR)module);
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_tls_callback = tls_callback;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	(void)lpvReserved;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		log_line("dll_attach", (unsigned long long)(ULONG_PTR)hinstDLL);
		return FALSE;	/* refuse to initialize -> the loader must unwind */
	case DLL_PROCESS_DETACH:
		log_line("dll_detach", (unsigned long long)(ULONG_PTR)hinstDLL);
		break;
	default:
		break;
	}

	return TRUE;
}
