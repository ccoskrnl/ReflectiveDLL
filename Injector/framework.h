#pragma once

#define WIN32_LEAN_AND_MEAN
#include <stdint.h>
#include <Windows.h>

typedef DWORD	dword_t;
typedef WORD	word_t;
typedef BYTE	byte_t;

namespace Key {
	const byte_t OB_XOR_KEY[] = { 0xAF, 0x41, 0x33, 0xCC };
	const size_t OB_XOR_KEY_SIZE = 4 * sizeof(byte_t);
}


#define _in_
#define _out_
