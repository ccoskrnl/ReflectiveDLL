#pragma once
#include "framework.h"
#include "headers.h"

/* headers.h has no function pointer type for GetProcAddress, so add one here. */
typedef FARPROC(WINAPI* fnGetProcAddress)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

/* Used to undo the .pdata registration when a load has to be abandoned. */
typedef BOOLEAN(NTAPI* fnRtlDeleteFunctionTable)(
    PRUNTIME_FUNCTION FunctionTable
    );

/*
 * Reflective load: map the raw PE file bytes at "image" into memory, then run
 * the image entry point with DLL_PROCESS_ATTACH.
 *
 * Performed here: section mapping, base relocations, import table fixups,
 * x64 exception table registration, TLS callbacks and per-section page
 * protection.
 *
 * Parameters:
 *   image      : address of the raw PE file bytes (on-disk layout, not mapped)
 *   image_size : size of that buffer
 * Returns:
 *   success -> base address of the mapped image (the HINSTANCE DllMain sees)
 *   failure -> 0. Whatever was already applied is undone first: the entry point
 *              is called with DLL_PROCESS_DETACH, the TLS callbacks with
 *              DLL_PROCESS_DETACH, the exception table entry is removed and the
 *              image memory is released.
 */
UINT64 rfdll_load_image(PVOID image, UINT64 image_size);

/*
 * Map the raw PE file bytes and prepare them to run, but do not call the image
 * entry point: hand it back to the caller instead.
 *
 * Used by the packed executing entry point, which has to wipe the payload and
 * then jump into the entry point rather than call it, so that no return address
 * into the payload is left on the stack. Everything rfdll_load_image does except
 * the entry point call happens here as well (sections, relocations, imports,
 * exception table, TLS callbacks, page protection).
 *
 * Parameters:
 *   image      : address of the raw PE file bytes (on-disk layout, not mapped)
 *   image_size : size of that buffer
 *   entry_rva  : receives AddressOfEntryPoint of the mapped image
 *   out_size   : receives SizeOfImage of that mapping
 *   needs_delete_table : receives TRUE when an exception table entry was
 *                        registered, so the caller knows it should be removed
 *                        if it has to abandon the image
 * Returns:
 *   success -> base address of the mapped image (not yet entered)
 *   failure -> 0, with everything already applied undone
 */
PBYTE rfdll_prepare_image(PVOID image, UINT64 image_size, DWORD* entry_rva,
	DWORD* out_size, BOOL* needs_delete_table);
