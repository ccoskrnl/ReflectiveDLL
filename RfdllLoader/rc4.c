#include "framework.h"
#include "headers.h"
#include "rc4.h"

/*
 * RC4: key scheduling algorithm followed by the pseudo random generation
 * algorithm, XORed over the data. This file is compiled into the shellcode, so
 * the same rules apply as in pe_loader.c: no globals, no static data, no string
 * literals, and no CRT. The 256 byte state is a stack buffer; the build disables
 * stack probes (/Gs9999999), so no __chkstk call is generated for it.
 */
void rfdll_rc4(BYTE* data, SIZE_T size, const BYTE* key, DWORD key_length)
{
	BYTE state[256];
	BYTE swap = 0;
	DWORD i = 0;
	DWORD j = 0;
	SIZE_T n = 0;

	if (data == NULL || size == 0 || key == NULL || key_length == 0)
		return;

	for (i = 0; i < 256; i++)
		state[i] = (BYTE)i;

	j = 0;
	for (i = 0; i < 256; i++)
	{
		j = (j + state[i] + key[i % key_length]) & 0xFF;
		swap = state[i];
		state[i] = state[j];
		state[j] = swap;
	}

	i = 0;
	j = 0;
	for (n = 0; n < size; n++)
	{
		i = (i + 1) & 0xFF;
		j = (j + state[i]) & 0xFF;
		swap = state[i];
		state[i] = state[j];
		state[j] = swap;
		data[n] ^= state[(state[i] + state[j]) & 0xFF];
	}
}
