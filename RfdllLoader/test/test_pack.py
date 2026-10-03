#!/usr/bin/env python3
"""
Self test for pack.py. Pure Python, no build required.

It builds a synthetic x64 PE image (DOS stub, Rich header, debug directory with
a PDB path, a resource section, build fingerprints) plus a synthetic loader
blob, packs them and then checks the container format, the RC4 round trip, the
header stripping and the error paths.

Run:  python test_pack.py
"""

import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pack  # noqa: E402

SCRATCH_DIR = "packtest_scratch"

CHECKS = [0]
FAILURES = [0]

DOS_STUB = b"This program cannot be run in DOS mode"
PDB_PATH = b"c:\\build\\secret\\payload.pdb"

MZ_OFFSET = 0x80
SECTION_TABLE = MZ_OFFSET + 24 + pack.OPTIONAL_HEADER64_SIZE
SECTION1_RAW = 0x200
SECTION2_RAW = 0x400
FILE_SIZE = 0x600
SIZE_OF_IMAGE = 0x3000
DEBUG_RVA = 0x2000          # debug directory array
DEBUG_DATA_RVA = 0x2040     # the PDB path lives here
RESOURCE_RVA = 0x2000


def check(ok, what):
    CHECKS[0] += 1
    if ok:
        print("  [ ok ] %s" % what)
    else:
        FAILURES[0] += 1
        print("  [FAIL] %s" % what)
    return ok


def build_synthetic_pe():
    """A small but syntactically valid PE32+ image full of things to strip."""
    buf = bytearray(FILE_SIZE)

    # DOS header plus stub plus a fake Rich header.
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, MZ_OFFSET)
    buf[0x40:0x40 + len(DOS_STUB)] = DOS_STUB
    buf[0x70:0x78] = b"Rich" + b"\xAA\xBB\xCC\xDD"

    pe = MZ_OFFSET
    buf[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<H", buf, pe + 4, pack.IMAGE_FILE_MACHINE_AMD64)
    struct.pack_into("<H", buf, pe + 6, 2)                       # NumberOfSections
    struct.pack_into("<I", buf, pe + 8, 0x5F5E1000)              # TimeDateStamp
    struct.pack_into("<H", buf, pe + 20, pack.OPTIONAL_HEADER64_SIZE)

    opt = pe + 24
    struct.pack_into("<H", buf, opt + 0, pack.PE32_PLUS_MAGIC)
    buf[opt + 2] = 14                                            # MajorLinkerVersion
    buf[opt + 3] = 51                                            # MinorLinkerVersion
    struct.pack_into("<I", buf, opt + 16, 0x1000)                # AddressOfEntryPoint
    struct.pack_into("<Q", buf, opt + 24, 0x180000000)           # ImageBase
    struct.pack_into("<I", buf, opt + 32, 0x1000)                # SectionAlignment
    struct.pack_into("<I", buf, opt + 36, 0x200)                 # FileAlignment
    struct.pack_into("<I", buf, opt + 56, SIZE_OF_IMAGE)         # SizeOfImage
    struct.pack_into("<I", buf, opt + 60, 0x200)                 # SizeOfHeaders
    struct.pack_into("<I", buf, opt + 64, 0x12345678)            # CheckSum
    struct.pack_into("<I", buf, opt + 108, 16)                   # NumberOfRvaAndSizes

    def directory(index, rva, size):
        off = opt + 112 + index * 8
        struct.pack_into("<I", buf, off, rva)
        struct.pack_into("<I", buf, off + 4, size)

    directory(pack.DIR_EXPORT, 0x1100, 0x40)        # kept
    directory(pack.DIR_IMPORT, 0x1200, 0x28)        # kept
    directory(pack.DIR_RESOURCE, RESOURCE_RVA, 0x100)
    directory(pack.DIR_EXCEPTION, 0x1300, 0x30)     # kept
    directory(pack.DIR_BASERELOC, 0x1400, 0x20)     # kept
    directory(pack.DIR_DEBUG, DEBUG_RVA, 28)
    directory(pack.DIR_TLS, 0x1500, 0x28)           # kept
    directory(pack.DIR_LOAD_CONFIG, 0x1600, 0x40)
    directory(pack.DIR_BOUND_IMPORT, 0x1700, 0x10)
    directory(pack.DIR_IAT, 0x1800, 0x20)           # kept
    directory(pack.DIR_DELAY_IMPORT, 0x1900, 0x20)

    # Section table: an executable section and a read only data section.
    s1 = SECTION_TABLE
    buf[s1:s1 + 8] = b"mycode\0\0"
    struct.pack_into("<I", buf, s1 + 8, 0x100)                       # VirtualSize
    struct.pack_into("<I", buf, s1 + 12, 0x1000)                     # VirtualAddress
    struct.pack_into("<I", buf, s1 + 16, 0x200)                      # SizeOfRawData
    struct.pack_into("<I", buf, s1 + 20, SECTION1_RAW)               # PointerToRawData
    struct.pack_into("<I", buf, s1 + 36, 0x60000020)                 # code, execute, read

    s2 = SECTION_TABLE + 40
    buf[s2:s2 + 8] = b"mysecrets"
    struct.pack_into("<I", buf, s2 + 8, 0x200)
    struct.pack_into("<I", buf, s2 + 12, 0x2000)
    struct.pack_into("<I", buf, s2 + 16, 0x200)
    struct.pack_into("<I", buf, s2 + 20, SECTION2_RAW)
    struct.pack_into("<I", buf, s2 + 36, 0x40000040)                 # data, read

    # Debug directory: one entry pointing at the PDB path.
    entry = SECTION2_RAW + (DEBUG_RVA - 0x2000)
    struct.pack_into("<I", buf, entry + 12, 2)                        # Type = CODEVIEW
    struct.pack_into("<I", buf, entry + 16, len(PDB_PATH))            # SizeOfData
    struct.pack_into("<I", buf, entry + 20, DEBUG_DATA_RVA)           # AddressOfRawData
    struct.pack_into("<I", buf, entry + 24, SECTION2_RAW + (DEBUG_DATA_RVA - 0x2000))
    data = SECTION2_RAW + (DEBUG_DATA_RVA - 0x2000)
    buf[data:data + len(PDB_PATH)] = PDB_PATH

    # Some code bytes so the executable section is not all zeros.
    for i in range(0x20):
        buf[SECTION1_RAW + i] = 0x90 + (i & 0x0F)

    return bytes(buf)


def test_rc4_vectors():
    print("\n=== rc4 test vectors ===")
    check(pack.rc4(b"Key", b"Plaintext").hex() == "bbf316e8d940af0ad3",
          "known answer: key 'Key', plaintext 'Plaintext'")
    check(pack.rc4(b"Wiki", b"pedia").hex() == "1021bf0420",
          "known answer: key 'Wiki', plaintext 'pedia'")
    blob = bytes(range(256)) * 3
    check(pack.rc4(b"roundtrip", pack.rc4(b"roundtrip", blob)) == blob,
          "round trip restores every byte")


def parse_meta(payload, meta_offset):
    magic = payload[meta_offset:meta_offset + 8]
    version, flags, keylen = struct.unpack_from("<BBB", payload, meta_offset + 8)
    dll_size, host_hash = struct.unpack_from("<II", payload, meta_offset + 11)
    return magic, version, flags, keylen, dll_size, host_hash


def test_payload():
    print("\n=== payload layout, stripping and round trip ===")
    dll = build_synthetic_pe()
    loader = bytes((i * 7 + 3) & 0xFF for i in range(0x2600))   # 9728 bytes, no magic
    check(pack.MAGIC not in loader, "synthetic loader contains no metadata magic")

    key = bytes(range(32))
    payload, info = pack.pack_payload(loader, dll, key)

    meta_offset = info["meta_offset"]
    check(meta_offset % pack.PAGE_SIZE == 0, "metadata starts on a page boundary")
    check(meta_offset >= len(loader), "metadata comes after the loader")
    check(payload[:len(loader)] == loader, "payload starts with the loader bytes")
    check(all(b == pack.FILLER for b in payload[len(loader):meta_offset]),
          "padding between loader and metadata is 0xCC")

    magic, version, flags, keylen, dll_size, host_hash = parse_meta(payload, meta_offset)
    check(magic == pack.MAGIC, "metadata magic round trips")
    check(version == pack.VERSION, "metadata version round trips")
    check(flags & pack.FLAG_HEADERS_STRIPPED, "flags report that headers were stripped")
    check(keylen == len(key), "key length round trips")
    check(host_hash == 0, "host hash defaults to 0 (private mapping)")

    key_off = info["key_offset"]
    data_off = info["data_offset"]
    check(payload[key_off:key_off + len(key)] == key, "RC4 key is stored right after the header")
    check(dll_size == len(payload) - data_off, "dll_size matches the ciphertext length")

    stripped_sha = hashlib.sha256(pack.rc4(key, payload[data_off:])).hexdigest()
    check(stripped_sha == info["dll_stripped_sha256"],
          "decrypting the payload reproduces the stripped DLL")

    check(PDB_PATH not in payload, "PDB path does not survive into the payload")
    check(DOS_STUB not in payload, "DOS stub text does not survive into the payload")
    check(dll[0:0x40] not in payload, "plaintext PE header is not present in the payload")

    # The stripped DLL itself.
    stripped = pack.rc4(key, payload[data_off:])
    pe = pack.PeImage(stripped)
    check(DOS_STUB not in stripped, "DOS stub text is gone from the stripped DLL")
    check(b"Rich" + b"\xAA\xBB\xCC\xDD" not in stripped, "Rich header is gone")
    check(PDB_PATH not in stripped, "PDB path is gone from the stripped DLL")
    check(struct.unpack_from("<I", stripped, pe.pe + 8)[0] == 0, "TimeDateStamp is zeroed")
    check(struct.unpack_from("<I", stripped, pe.optional + 64)[0] == 0, "CheckSum is zeroed")
    check(stripped[pe.optional + 2] == 0 and stripped[pe.optional + 3] == 0,
          "linker version is zeroed")

    for index, name, kept in (
        (pack.DIR_DEBUG, "DEBUG", False),
        (pack.DIR_RESOURCE, "RESOURCE", False),
        (pack.DIR_LOAD_CONFIG, "LOAD_CONFIG", False),
        (pack.DIR_BOUND_IMPORT, "BOUND_IMPORT", False),
        (pack.DIR_DELAY_IMPORT, "DELAY_IMPORT", False),
        (pack.DIR_EXPORT, "EXPORT", True),
        (pack.DIR_IMPORT, "IMPORT", True),
        (pack.DIR_EXCEPTION, "EXCEPTION", True),
        (pack.DIR_BASERELOC, "BASERELOC", True),
        (pack.DIR_TLS, "TLS", True),
        (pack.DIR_IAT, "IAT", True),
    ):
        got = pe.directory(index)
        if kept:
            check(got != (0, 0), "directory %s is kept" % name)
        else:
            check(got == (0, 0), "directory %s is cleared" % name)

    names = [bytes(pe.data[pe.section(i)["header"]:pe.section(i)["header"] + 8]).rstrip(b"\0")
             for i in range(pe.num_sections)]
    check(names == [b".text", b".rdata"], "section names became conventional (%s)" % names)
    check(pe.section(0)["virtual_address"] == 0x1000, "section layout is untouched")
    check(pe.size_of_image == SIZE_OF_IMAGE, "SizeOfImage is untouched")


def test_options_and_errors():
    print("\n=== options and error paths ===")
    dll = build_synthetic_pe()
    loader = bytes((i * 5 + 1) & 0xFF for i in range(0x1100))

    payload, info = pack.pack_payload(loader, dll, b"", strip=False)
    check(info["flags"] == 0, "--no-strip leaves flags clear")
    data_off = info["data_offset"]
    check(payload[data_off:] == dll, "--no-strip stores the DLL unchanged")
    check(PDB_PATH in payload, "--no-strip keeps the PDB path")

    payload, info = pack.pack_payload(loader, dll, b"k" * 16, keep_debug=True, keep_resource=True)
    data_off = info["data_offset"]
    stripped = pack.rc4(b"k" * 16, payload[data_off:])
    check(PDB_PATH in stripped, "--keep-debug/--keep-resource preserve the PDB path")
    pe = pack.PeImage(stripped)
    check(pe.directory(pack.DIR_DEBUG) != (0, 0), "debug directory kept on request")
    check(pe.directory(pack.DIR_RESOURCE) != (0, 0), "resource directory kept on request")

    low = bytearray(dll)
    low[MZ_OFFSET + 4:MZ_OFFSET + 6] = struct.pack("<H", 0x14C)     # i386
    try:
        pack.pack_payload(loader, bytes(low), b"k")
        check(False, "non x64 input is rejected")
    except pack.PackError:
        check(True, "non x64 input is rejected")

    bad = bytearray(dll)
    struct.pack_into("<H", bad, MZ_OFFSET + 20, 0xF0 + 8)
    try:
        pack.pack_payload(loader, bytes(bad), b"k")
        check(False, "unexpected SizeOfOptionalHeader is rejected")
    except pack.PackError:
        check(True, "unexpected SizeOfOptionalHeader is rejected")

    try:
        pack.pack_payload(loader + pack.MAGIC, dll, b"k")
        check(False, "loader containing the magic is rejected")
    except pack.PackError:
        check(True, "loader containing the magic is rejected")

    try:
        pack.rc4(b"", b"data")
        check(False, "empty RC4 key is rejected")
    except pack.PackError:
        check(True, "empty RC4 key is rejected")

    try:
        pack.pack_payload(b"", dll, b"k")
        check(False, "empty loader is rejected")
    except pack.PackError:
        check(True, "empty loader is rejected")


def test_cli():
    print("\n=== command line ===")
    dll = build_synthetic_pe()
    loader = bytes((i * 11 + 5) & 0xFF for i in range(0x900))

    # A fixed scratch directory inside the project: some sandboxes deny writes to
    # the system temp area, and cleaning up is left to the operator on purpose.
    tmp = os.path.join(HERE, SCRATCH_DIR)
    os.makedirs(tmp, exist_ok=True)

    dll_path = os.path.join(tmp, "payload.dll")
    loader_path = os.path.join(tmp, "loader.bin")
    out_path = os.path.join(tmp, "payload.bin")
    info_path = os.path.join(tmp, "payload_info.json")
    with open(dll_path, "wb") as f:
        f.write(dll)
    with open(loader_path, "wb") as f:
        f.write(loader)

    rc = pack.main(["--dll", dll_path, "--loader", loader_path, "--out", out_path,
                    "--info", info_path, "--seed", "1", "--keylen", "32"])
    check(rc == 0, "cli exits 0")
    check(os.path.exists(out_path) and os.path.getsize(out_path) > 0, "cli wrote the payload")
    with open(info_path) as f:
        info = json.load(f)
    check(info["keylen"] == 32, "cli metadata reports the key length")
    check(info["payload_size"] == os.path.getsize(out_path), "reported size matches the file")
    text = json.dumps(info)
    check(("01" * 32) not in text and "key_hex" not in text,
          "metadata report does not leak key material")

    plain_path = os.path.join(tmp, "plain.bin")
    rc_no_rc4 = pack.main(["--dll", dll_path, "--loader", loader_path, "--out", plain_path,
                           "--info", "", "--no-rc4"])
    check(rc_no_rc4 == 0, "cli accepts --no-rc4")
    with open(plain_path, "rb") as f:
        plain = f.read()
    check(len(plain) == info["payload_size"] - 32, "--no-rc4 drops the key bytes")
    print("  [*] scratch files left in %s" % tmp)
    return


def main():
    test_rc4_vectors()
    test_payload()
    test_options_and_errors()
    test_cli()
    print("\n=== %d checks, %d failures ===" % (CHECKS[0], FAILURES[0]))
    return 1 if FAILURES[0] else 0


if __name__ == "__main__":
    sys.exit(main())
