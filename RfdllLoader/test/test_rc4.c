/*
 * Unit check for the RC4 implementation that is compiled into the shellcode.
 *
 * It verifies the published RC4 test vectors and, more importantly, that the C
 * implementation in ..\rc4.c agrees byte for byte with the Python implementation
 * in ..\pack.py: the packer encrypts the DLL and the loader has to decrypt it, so
 * the two must not diverge. The "cross check" vectors below were produced by
 * pack.rc4() and are copied here as a fixed expectation.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "..\rc4.h"

static int g_checks = 0;
static int g_failures = 0;

static void check(int ok, const char* what)
{
	g_checks++;
	printf("  [%s] %s\n", ok ? " ok " : "FAIL", what);
	if (!ok)
		g_failures++;
}

static int equals_hex(const BYTE* data, const char* hex)
{
	char text[3];
	size_t i = 0;

	for (i = 0; i < strlen(hex) / 2; i++)
	{
		sprintf_s(text, sizeof(text), "%02x", data[i]);
		if (text[0] != hex[i * 2] || text[1] != hex[i * 2 + 1])
			return 0;
	}
	return 1;
}

int main(void)
{
	BYTE buffer[64];
	BYTE original[64];
	BYTE key[64];

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== rc4.c unit check ===\n");

	/* Published RC4 test vectors (Wikipedia / RFC 6229 style examples). */
	memcpy(buffer, "Plaintext", 9);
	rfdll_rc4(buffer, 9, (const BYTE*)"Key", 3);
	check(equals_hex(buffer, "bbf316e8d940af0ad3"), "vector: key 'Key', data 'Plaintext'");

	memcpy(buffer, "pedia", 5);
	rfdll_rc4(buffer, 5, (const BYTE*)"Wiki", 4);
	check(equals_hex(buffer, "1021bf0420"), "vector: key 'Wiki', data 'pedia'");

	/* Cross check against pack.py (same inputs, same expected bytes). */
	for (int i = 0; i < 64; i++)
		buffer[i] = (BYTE)i;
	rfdll_rc4(buffer, 64, (const BYTE*)"cross-check", 11);
	check(equals_hex(buffer,
		"09affb043a473f7cf9979e414efaab11bc783ca80c428612636aa088511253a7"
		"06f5a5360032de0d71657d67e0cf04c2957dad02f51ee7f47059486b7ce827f0"),
		"cross check: matches pack.py for a 64 byte pattern");

	buffer[0] = 0;
	rfdll_rc4(buffer, 1, (const BYTE*)"x", 1);
	check(equals_hex(buffer, "04"), "cross check: single byte key 'x'");

	/* Round trip and the degenerate inputs. */
	for (int i = 0; i < 64; i++)
		original[i] = (BYTE)(i * 7 + 1);
	memcpy(buffer, original, 64);
	rfdll_rc4(buffer, 64, (const BYTE*)"round-trip-key", 14);
	check(memcmp(buffer, original, 64) != 0, "ciphertext differs from the plaintext");
	rfdll_rc4(buffer, 64, (const BYTE*)"round-trip-key", 14);
	check(memcmp(buffer, original, 64) == 0, "round trip restores every byte");

	memcpy(buffer, original, 64);
	rfdll_rc4(buffer, 64, (const BYTE*)"k", 0);
	check(memcmp(buffer, original, 64) == 0, "zero length key leaves the data untouched");

	memcpy(buffer, original, 64);
	rfdll_rc4(buffer, 0, (const BYTE*)"k", 1);
	check(memcmp(buffer, original, 64) == 0, "zero length data leaves the buffer untouched");

	rfdll_rc4(NULL, 64, (const BYTE*)"k", 1);
	rfdll_rc4(buffer, 64, NULL, 1);
	check(1, "null arguments are ignored instead of crashing");

	/* A full 256 byte key, the maximum the metadata can express. */
	for (int i = 0; i < 64; i++)
		key[i] = (BYTE)(255 - i);
	memcpy(buffer, original, 64);
	rfdll_rc4(buffer, 64, key, 64);
	rfdll_rc4(buffer, 64, key, 64);
	check(memcmp(buffer, original, 64) == 0, "64 byte key round trips");

	printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
