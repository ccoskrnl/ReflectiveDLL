# RfdllLoader

A position independent **reflective loader shellcode**. It takes the address and
size of a DLL's raw file bytes, maps that PE into the current process and runs
the image entry point (`DllMain(DLL_PROCESS_ATTACH)`).

Difference from the `Shellcode` project: `Shellcode` downloads its payload over
the network and only jumps to the raw code of the export named `yolo`. This
loader does not use the network at all; it expands a complete PE into a running
image.

## Packed payload

`loader.bin` is the loader on its own: the caller has to supply the DLL bytes.
`pack.py` produces the other shape, a single self contained buffer entered with
**no arguments**:

```
+0x0000              loader_packed.bin   the loader code
...                  0xCC padding up to the next page boundary
+meta                RFDLL_META_HEADER   19 bytes
+meta+19             RC4 key              key_length bytes
+...                 rc4(PE image)        dll_size bytes
```

The metadata is laid out exactly as in `payload.h` (packed, 19 bytes, little
endian for the multi byte fields):

| Offset | Size | Field |
| --- | --- | --- |
| +0 | 8 | magic, `"RFDLMETA"` |
| +8 | 1 | version (`1`) |
| +9 | 1 | flags (`0x01` = PE headers were stripped) |
| +10 | 1 | `key_length` (0 means the image is stored in the clear) |
| +11 | 4 | `dll_size` |
| +15 | 4 | `host_hash` (0 = private mapping, reserved for the host module mode) |

`entrypoint_packed` (`RCX`/`RDX` ignored, `RAX` = image base or `0`):

1. `rfdll_get_rip()` anchors on its own address, because the entry point is
   called with no arguments and nothing else says where the payload starts;
2. scan forward from the next page boundary for the magic. The scan is bounded
   by `RFDLL_SCAN_LIMIT` (64 KB) **and** by the end of the committed region that
   `VirtualQuery` reports, so a missing metadata fails cleanly instead of
   reading unmapped memory. Only page aligned addresses are tested, which is
   where `pack.py` puts the header;
3. validate version, flags, `dll_size` and `key_length`, and refuse a metadata
   whose key plus image would run past the region found in step 2 (the metadata
   is inside the payload, so those fields are untrusted input). A payload whose
   region limit could not be determined at all is refused as well, rather than
   decrypting without a bound;
4. RC4 the image **in place** at `data_offset`. RC4 is a stream cipher, so this
   is the same operation as encryption; the payload must therefore be writable,
   and the caller gives up its copy of the ciphertext;
5. hand the decrypted image to the same `rfdll_load_image` described above.

The image is decrypted where it lies, so the mapped image never contains the
loader, and the header page is read-only once mapping is done.

## Executing payload (incomplete)

`loader_exec.bin` is a third shape, packed the same way as `loader_packed.bin`
but entered with `entrypoint_exec`. It does everything the packed entry point
does, and then:

1. maps the image from a **private copy** of the decrypted PE, because the
   payload is about to be destroyed and the image cannot be mapped from bytes
   that are being wiped;
2. **wipes the payload**: the decrypted image, the RC4 key and the metadata. The
   loader code itself is left alone because it is still executing;
3. writes `RFDLL_PAYLOAD_INFO` (see `payload.h`) at offset `0x40` inside the
   mapped image, through the `rfdll_prepare_hook` callback so it happens before
   the header page is made read-only;
4. passes the same structure as `lpReserved` and jumps into the image entry
   point instead of calling it, so no return address into the wiped payload is
   left on the stack.

The payload reads that structure and releases the payload region itself, which
it can only do because the loader tells it where the region is and how big it
is. `test/target_dll.c` does exactly that and logs `payload_free ok`.

**Known incomplete:** returning from the image entry point back to the caller
does not work yet. Everything up to and including the jump is verified (the
metadata is found, the image runs, the info arrives through both channels, and
the payload frees the loader's region), but the return path faults afterwards,
so the case is opt-in in the test and the entry point should be treated as
"runs the payload and does not come back" for now. This is the one part of the
design that is not finished.

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

* `loader.exe` / `loader_packed.exe`: intermediates, only used to feed `objcopy`;
* `loader.bin`: the shellcode for the two argument form
  (`objcopy -O binary -j .text loader.exe loader.bin`);
* `loader_packed.bin`: the shellcode for the packed form
  (`objcopy -O binary -j .text loader_packed.exe loader_packed.bin`);
* `loader_exec.bin`: the shellcode for the executing form
  (`objcopy -O binary -j .text loader_exec.exe loader_exec.bin`).

`entrypoint`, `entrypoint_packed` and `entrypoint_exec` each have to be the
first function of `.text`, so the three blobs are linked separately: `loader.c`,
`loader_packed.c` and `entry_exec.asm` contain one entry each and their object
file is listed first on its link line. Offset 0 of each blob is therefore its
entry point.

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
| `headers.h` | copied as is, contents identical (PEB / LDR / NT structures and function pointer types); the original's UTF-8 BOM was dropped so that every file here is pure ASCII. `fnVirtualQuery` was added next to the other kernel32 function pointer types for the packed entry point |
| `ldr.c` / `ldr.h` | copied; only the comments were translated into English (`GMHR_Hash` resolves a module base by name hash, `GPAR_Hash` resolves an export by name hash) |
| `misc.c` / `misc.h` | copied as is (self-contained string routines) |
| `get_peb.asm` | copied; only the comments were translated into English (`gs:[60h]` reads the PEB) |
| `api_hash.h` | based on the original, extended with `HASH_NTDLL`, `HASH_VIRTUALPROTECT`, `HASH_RTLADDFUNCTIONTABLE` and `HASH_RTLDELETEFUNCTIONTABLE` |

New: `loader.c` (entry point for the two argument form), `loader_packed.c` and
`payload.h` (self locating entry point and the payload layout), `pe_loader.c` /
`pe_loader.h` (reflective mapping logic), `rc4.c` / `rc4.h` (in place stream
cipher), `get_rip.asm` (RIP anchor for the argument-less entry point),
`pack.py` (payload packer), `build.cmd`, project files.

## End to end test

`test/` holds a self contained test of the loader (six cases, 58 checks when a
packed payload is supplied). Build it from a VS developer command prompt, after
`build.cmd` produced `loader.bin`:

```
cd test
build_test.cmd
host.exe ..\loader.bin target.dll fail.dll
```

The packed form is optional and needs a payload built by `pack.py` first:

```
python ..\pack.py --dll target.dll --loader ..\loader_packed.bin ^
    --out packtest_b2b\payload.bin --info packtest_b2b\payload_info.json --seed 1234
host.exe ..\loader.bin target.dll fail.dll packtest_b2b\payload.bin
```

* `target_dll.c`: payload that records every step in `target_marker.log` (kernel32 only,
  because the loader runs its TLS callback before the CRT is initialized) and exports
  `TestReloc`, `TestTlsFlag` and `TestSeh`;
* `fail_dll.c`: payload whose `DllMain` returns `FALSE` for `DLL_PROCESS_ATTACH`, used to
  check the unwind path;
* `host.c`: maps `loader.bin` as code, occupies the payload's preferred base so the loader
  has to relocate, and runs the cases;
* `test_rc4.c` and `test_pack.py` cover the cipher and the packer on their own
  (published RC4 vectors, round trips, the metadata layout and the stripping
  rules).

| Case | What it verifies |
| --- | --- |
| 1 - load `target.dll` with its preferred base taken | the image is relocated; page protection is sane; the TLS callback ran before `DllMain`; `DllMain` ran (CRT and imports resolved); a global pointer was relocated (DIR64); exports are present and callable; an exception raised inside the image is caught by its own handler (so the `.pdata` registration works) |
| 2 - load `fail.dll` | the loader returns 0 and unwinds in loader order: `DllMain(DLL_PROCESS_DETACH)`, TLS callback with `DLL_PROCESS_DETACH`, then releases the image (the base logged by `DllMain` is `MEM_FREE` afterwards) |
| 3 - load `target.dll` with `AddressOfEntryPoint` zeroed | the exact per section page protection the loader applies, because no payload code runs; also covers the "an image without an entry point is accepted" path |
| 4 - load `fail.dll` with its entry point RVA outside the image | the loader treats the image as malformed: it returns 0, releases the TLS callbacks with `DLL_PROCESS_DETACH`, never calls the entry point, and frees the image |
| 5 - packed payload, entry called with **no** arguments | the packed entry finds its own metadata, decrypts the image in place and maps it: the 64 bit region bound, the RC4 step and the metadata layout all work together, and the resulting image passes the same relocation / protection / export / TLS checks as case 1 |
| 6 - packed payload with `dll_size` patched past the buffer | the metadata is untrusted input and the in place decrypt happens before the PE is validated, so the loader has to refuse it: it returns 0 without writing outside the payload |

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
  `InLoadOrderModuleList`);
* in the packed form the RC4 key sits in the payload right next to the
  ciphertext, so the ciphertext is only as secret as the payload itself (this
  hides the DLL on disk and from a plaintext scan of the buffer, it is not key
  management);
* the packed form requires the metadata to be reachable by a forward page scan
  within the same committed region as the code, and it needs the payload to stay
  writable until the decrypt is done;
* `host_hash` is written by the packer and validated by the loader, but the host
  module placement mode it is meant for is not implemented yet: a non zero value
  is currently carried along and ignored.

## Notes

* This code is compiled into the shellcode as well, so it must not contain
  string literals, global or static data, or direct API calls: those would end
  up in `.rdata`/`.data` or in the IAT while `objcopy -j .text` keeps `.text`
  only. Keep that rule in mind when adding code.
* ASCII only, English comments.
* x64 only.
* For security research, teaching and authorized testing only.
