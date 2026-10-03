#pragma once
#include "framework.h"
#include "headers.h"

/*
 * RC4 keystream XOR, in place. RC4 is a stream cipher, so the same call both
 * encrypts and decrypts. Used by the packed payload entry: the packed DLL is
 * RC4 encrypted where it sits in the payload area.
 */
void rfdll_rc4(BYTE* data, SIZE_T size, const BYTE* key, DWORD key_length);
