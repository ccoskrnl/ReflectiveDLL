# RfdllLoader

A position independent **reflective loader shellcode**. It takes the address and
size of a DLL's raw file bytes, maps that PE into the current process and runs
the image entry point (`DllMain(DLL_PROCESS_ATTACH)`).

Difference from the `Shellcode` project: `Shellcode` downloads its payload over
the network and only jumps to the raw code of the export named `yolo`. This
loader does not use the network at all; it expands a complete PE into a running
image.

## Interface

The build product is `loader.bin`, a pure `.text` blob that starts executing at
byte 0. The entry point follows the x64 calling convention:

| Register | Meaning |
| --- | --- |
| `RCX` | `dll_base`: address of the raw PE file bytes (on-disk layout, not mapped) |
| `RDX` | `dll_size`: size of that buffer |
| `RAX` | return: base address of the mapped image (the `HINSTANCE` DllMain sees), or `0` on failure |

What happens after the call:

1. validate the DOS / NT headers, `Machine == AMD64`, `PE32+`,
   `SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)`, the section table
   inside the caller's buffer, and `SizeOfImage` within a sane bound;
2. `VirtualAlloc` the image (`SizeOfImage`) at the **preferred base**, falling
   back to an arbitrary address if that fails;
3. map the sections (copying `min(SizeOfRawData, VirtualSize)` bytes, bounded by
   the caller's buffer as well);
4. apply base relocations (`DIR64` / `HIGHLOW`; if relocation is required but
   the image has no relocation table the loader fails and releases the memory);
5. fix the import table (`LoadLibraryA` + `GetProcAddress`, ordinal imports
   included);
6. register the x64 exception table (`RtlAddFunctionTable`, so `.pdata` works);
7. call the TLS callbacks with `DLL_PROCESS_ATTACH`;
8. tighten page protection per section (RWX -> RX / RW / R; sections marked
   `IMAGE_SCN_MEM_DISCARDABLE`, typically `.reloc`, become read-only);
9. call the image entry point (`AddressOfEntryPoint`, i.e. the CRT's
   `_DllMainCRTStartup`, which ends up in `DllMain`).

If the entry point returns `FALSE`, the loader unwinds in the order the real
loader uses for an unload: `DllMain(DLL_PROCESS_DETACH)`, then the TLS callbacks
with `DLL_PROCESS_DETACH`, then `RtlDeleteFunctionTable` for the `.pdata` entry
it added, and finally `VirtualFree`; it returns `0`. An image whose
`AddressOfEntryPoint` is 0 is accepted as is, without calling any entry point.

An entry point RVA that is not inside the image is treated as a malformed image:
the loader unwinds the same way (the TLS callbacks already ran, the entry point
did not) and returns `0`.

## Untrusted input

The PE being loaded is treated as hostile input. Every RVA that the loader reads
from the file is range checked against `SizeOfImage` (or against the caller's
buffer for file offsets) before it becomes a pointer:

* section table start and size (via `SizeOfOptionalHeader` / `NumberOfSections`);
* every section's `VirtualAddress` / `PointerToRawData` / `SizeOfRawData`;
* the base relocation directory and each relocation block;
* the import directory, each descriptor's `Name` / `OriginalFirstThunk` /
  `FirstThunk`, each thunk entry, and each imported name (which must be NUL
  terminated inside the image);
* the TLS directory and the TLS callback array;
* the exception (`.pdata`) directory.

Anything that does not fit makes the loader release the image and return `0`
rather than reading or writing outside the mapped region. Relocation fixups use
64 bit arithmetic so a crafted `VirtualAddress + rva` cannot wrap around.

## Build

`build.cmd` has the same style as `Shellcode/build.cmd` and has to be run from a
**VS developer command prompt** (`vcvars64.bat` already applied):

```
build.cmd
```

Output:

* `loader.exe`: intermediate, only used to feed `objcopy`;
* `loader.bin`: the final shellcode
  (`objcopy -O binary -j .text loader.exe loader.bin`).

`entrypoint` has to be the first function of `.text`: `loader.c` contains that
one function only and `loader.obj` is listed first on the link line, so offset 0
of `loader.bin` is the entry point.

## How to call it

The entry point takes two arguments (`RCX`/`RDX`) while `CreateRemoteThread` only
passes one parameter to a thread start routine, so the injector side needs a
short trampoline:

```asm
; in the target process: write loader.bin first, then write this trampoline
mov rcx, <dll_base>      ; 48 B9 imm64
mov rdx, <dll_size>      ; 48 BA imm64
mov rax, <loader_entry>  ; 48 B8 imm64
sub rsp, 28h             ; 48 83 EC 28   (32 byte shadow space + 16 byte alignment)
call rax                 ; FF D0
add rsp, 28h             ; 48 83 C4 28
ret                      ; C3
```

For local (same process) testing it can be called through a function pointer:

```c
typedef UINT64 (*rfdll_entry)(PVOID dll_base, UINT64 dll_size);
UINT64 image_base = ((rfdll_entry)loader_entry)(dll_image, dll_image_size);
```

## Code reused from the `Shellcode` project

| File | Note |
| --- | --- |
| `framework.h` | copied as is |
| `headers.h` | copied as is, contents identical (PEB / LDR / NT structures and function pointer types); the original's UTF-8 BOM was dropped so that every file here is pure ASCII |
| `ldr.c` / `ldr.h` | copied; only the comments were translated into English (`GMHR_Hash` resolves a module base by name hash, `GPAR_Hash` resolves an export by name hash) |
| `misc.c` / `misc.h` | copied as is (self-contained string routines) |
| `get_peb.asm` | copied; only the comments were translated into English (`gs:[60h]` reads the PEB) |
| `api_hash.h` | based on the original, extended with `HASH_NTDLL`, `HASH_VIRTUALPROTECT`, `HASH_RTLADDFUNCTIONTABLE` and `HASH_RTLDELETEFUNCTIONTABLE` |

New: `loader.c` (entry point), `pe_loader.c` / `pe_loader.h` (reflective mapping
logic), `build.cmd`, project files.

## End to end test

`test/` holds a self contained test of the loader (four cases, 41 checks). Build it from
a VS developer command prompt, after `build.cmd` produced `loader.bin`:

```
cd test
build_test.cmd
host.exe ..\loader.bin target.dll fail.dll
```

* `target_dll.c`: payload that records every step in `target_marker.log` (kernel32 only,
  because the loader runs its TLS callback before the CRT is initialized) and exports
  `TestReloc`, `TestTlsFlag` and `TestSeh`;
* `fail_dll.c`: payload whose `DllMain` returns `FALSE` for `DLL_PROCESS_ATTACH`, used to
  check the unwind path;
* `host.c`: maps `loader.bin` as code, occupies the payload's preferred base so the loader
  has to relocate, and runs the three cases.

| Case | What it verifies |
| --- | --- |
| 1 - load `target.dll` with its preferred base taken | the image is relocated; page protection is sane; the TLS callback ran before `DllMain`; `DllMain` ran (CRT and imports resolved); a global pointer was relocated (DIR64); exports are present and callable; an exception raised inside the image is caught by its own handler (so the `.pdata` registration works) |
| 2 - load `fail.dll` | the loader returns 0 and unwinds in loader order: `DllMain(DLL_PROCESS_DETACH)`, TLS callback with `DLL_PROCESS_DETACH`, then releases the image (the base logged by `DllMain` is `MEM_FREE` afterwards) |
| 3 - load `target.dll` with `AddressOfEntryPoint` zeroed | the exact per section page protection the loader applies, because no payload code runs; also covers the "an image without an entry point is accepted" path |
| 4 - load `fail.dll` with its entry point RVA outside the image | the loader treats the image as malformed: it returns 0, releases the TLS callbacks with `DLL_PROCESS_DETACH`, never calls the entry point, and frees the image |

Behaviour the test pins down:

* `GetProcAddress` does **not** find the mapped image (it is not in the PEB module list), so
  the host resolves exports by walking the export table by hand; payload code that calls
  `GetModuleHandle`/`GetProcAddress` on itself hits the same limitation;
* a normally built MSVC payload tightens its own `.fptable` (the control flow guard table)
  to read-only while its CRT initializes, so case 1 checks invariants there and case 3
  checks the exact value;
* TLS callbacks really do run before CRT initialization, so a payload must not call CRT
  functions from them.
## Known limitations

* delay-loaded imports are ignored;
* bound imports (an `OriginalFirstThunk` of 0 whose IAT already holds VAs) are not
  detected: such an image will either fail the bounds check or resolve wrongly;
* if `ntdll!RtlAddFunctionTable` or `ntdll!RtlDeleteFunctionTable` cannot be
  resolved, exception table registration is skipped silently and loading still
  succeeds (without the delete helper a registration could not be undone);
* a TLS directory or callback array that fails the range check is skipped
  silently instead of failing the load;
* `SizeOfOptionalHeader` must be exactly `sizeof(IMAGE_OPTIONAL_HEADER64)`
  (240), which is stricter than Windows and rejects images with a padded
  optional header;
* protection changes are page granular, so the gaps between sections keep the
  initial `PAGE_EXECUTE_READWRITE`; a failed `VirtualProtect` is not fatal;
* `FlushInstructionCache` is not called (the `Shellcode` project does not either);
* the image is not linked into the PEB module lists (it never shows up in
  `InLoadOrderModuleList`).

## Notes

* This code is compiled into the shellcode as well, so it must not contain
  string literals, global or static data, or direct API calls: those would end
  up in `.rdata`/`.data` or in the IAT while `objcopy -j .text` keeps `.text`
  only. Keep that rule in mind when adding code.
* ASCII only, English comments.
* x64 only.
* For security research, teaching and authorized testing only.
