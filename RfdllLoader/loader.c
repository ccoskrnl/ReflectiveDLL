#include "framework.h"
#include "pe_loader.h"

/*
 * Entry point of the reflective loader shellcode.
 *
 * Calling convention (x64 / Microsoft x64 calling convention):
 *   RCX = dll_base : address of the raw PE file bytes (on-disk layout)
 *   RDX = dll_size : size of that buffer
 *
 * Return value (RAX): base address of the mapped image, or 0 on failure.
 *
 * build.cmd extracts only .text with "objcopy -O binary -j .text" to produce
 * loader.bin, and the caller starts executing at byte 0 of that file. Therefore
 * entrypoint must be the first function of the first object file on the link
 * line, which is why this file holds nothing else.
 */
UINT64 entrypoint(PVOID dll_base, UINT64 dll_size)
{
	return rfdll_load_image(dll_base, dll_size);
}
