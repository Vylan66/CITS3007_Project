#!/usr/bin/env python3

"""
BUN file generator.

Provides functions for writing BUN headers and asset records to disk.
You can use and extend this script to generate valid or deliberately
malformed BUN files for testing.

BUN format reference: bun-spec.pdf
"""

import struct
import sys
import argparse
from pathlib import Path
from typing import Optional

# Header fields for output
HEADER_FIELDS = [
    ("magic",               "hex"),
    ("version_major",       "dec"),
    ("version_minor",       "dec"),
    ("asset_count",         "dec"),
    ("asset_table_offset",  "dec"),
    ("string_table_offset", "dec"),
    ("string_table_size",   "dec"),
    ("data_section_offset", "dec"),
    ("data_section_size",   "dec"),
    ("reserved",            "dec"),
]

# Record fields for output
RECORD_FIELDS = [
    ("name_offset",       "dec"),
    ("name_length",       "dec"),
    ("data_offset",       "dec"),
    ("data_size",         "dec"),
    ("uncompressed_size", "dec"),
    ("compression",       "dec"),
    ("asset_type",        "dec"),
    ("checksum",          "dec"),
    ("flags",             "dec"),
]

# On-disk format strings (little-endian)
# See bun-spec.pdf sections 4 and 5.
# These are used by the Python *struct* library (https://docs.python.org/3/library/struct.html) -
# see <https://docs.python.org/3/library/struct.html#format-strings> for an explanation.

# Header fields in order:
#   magic, version_major, version_minor, asset_count,
#   asset_table_offset, string_table_offset, string_table_size,
#   data_section_offset, data_section_size, reserved
_HEADER_FMT = "<IHHIQQQQQQ"

# Asset record fields in order:
#   name_offset, name_length, data_offset, data_size,
#   uncompressed_size, compression, asset_type, checksum, flags
_RECORD_FMT = "<IIQQQIIII"

BUN_MAGIC         = 0x304E5542   # "BUN0" in little-endian
BUN_VERSION_MAJOR = 1
BUN_VERSION_MINOR = 0

COMPRESS_NONE = 0
COMPRESS_RLE  = 1
COMPRESS_ZLIB = 2

FLAG_ENCRYPTED  = 0x1
FLAG_EXECUTABLE = 0x2

def display_struct(header_dict: dict, field_names) -> str:
    "display a dict containing struct values"
    output = []

    # compute column widths based on max field length
    longest_field_len = max(list(len(pair[0]) for pair in field_names))

    for name, fmt in field_names:
        value = header_dict[name]
        if fmt == "hex":
            rendered = f"0x{value:08x}"
        else:
            rendered = str(value)
        output.append(f"{name:<{longest_field_len}} = {rendered}")

    return "\n".join(output)

def write_header(
    f,
    *,
    asset_count: int,
    asset_table_offset: int,
    string_table_offset: int,
    string_table_size: int,
    data_section_offset: int,
    data_section_size: int,
    magic: int = BUN_MAGIC,
    version_major: int = BUN_VERSION_MAJOR,
    version_minor: int = BUN_VERSION_MINOR,
    reserved: int = 0,
) -> None:
    """
    Write a BUN header to file object f at its current position.

    All offset and size arguments are in bytes from the start of the file.
    The magic, version, and reserved fields have sensible defaults and
    normally need not be specified -- but can be overridden to produce
    deliberately malformed files for testing.
    """
    header_args = dict(locals())
    print("writing header to disk:")
    print("\n" + display_struct(header_args, HEADER_FIELDS) + "\n")

    data = pack_header(
        asset_count         = asset_count,
        asset_table_offset  = asset_table_offset,
        string_table_offset = string_table_offset,
        string_table_size   = string_table_size,
        data_section_offset = data_section_offset,
        data_section_size   = data_section_size,
        magic               = magic,
        version_major       = version_major,
        version_minor       = version_minor,
        reserved            = reserved,
    )
    print("len of header data:", len(data))
    f.write(data)


def write_asset_record(
    f,
    *,
    name_offset: int,
    name_length: int,
    data_offset: int,
    data_size: int,
    uncompressed_size: int = 0,
    compression: int       = COMPRESS_NONE,
    asset_type: int        = 0,
    checksum: int          = 0,
    flags: int             = 0,
) -> None:
    """
    Write a single BUN asset record to file object f at its current position.

    name_offset and name_length describe the asset name within the string
    table. data_offset and data_size describe the asset payload within the
    data section. Both offsets are relative to the start of their respective
    sections (not the start of the file).

    uncompressed_size must be 0 if the data is not compressed (compression=0).
    If the data is compressed, uncompressed_size must be the expected size
    after decompression.

    asset_type is a user-defined value (e.g. 1=texture, 2=audio).
    checksum, if non-zero, is a CRC-32 of the uncompressed data.
    """
    record_args = dict(locals())
    print("\nwriting asset record to disk:")
    print("\n" + display_struct(record_args, RECORD_FIELDS) + "\n")

    data = struct.pack(
        _RECORD_FMT,
        name_offset,
        name_length,
        data_offset,
        data_size,
        uncompressed_size,
        compression,
        asset_type,
        checksum,
        flags,
    )
    print("len of record data:", len(data), "\n")
    f.write(data)


def _align4(n: int) -> int:
    """Round n up to the next multiple of 4."""
    return (n + 3) & ~3

def write_padding(f, n: int, description: str) -> None:
    """write n many NULL bytes"""
    assert n >= 0

    print(f"writing {n} null bytes {description}\n")
    f.write(b"\x00" * n)

# On-disk size -- useful for computing offsets.
HEADER_SIZE = struct.calcsize(_HEADER_FMT)
RECORD_SIZE = struct.calcsize(_RECORD_FMT)

assert HEADER_SIZE == 60, f"Unexpected record size: {HEADER_SIZE}"
assert RECORD_SIZE == 48, f"Unexpected record size: {RECORD_SIZE}"

def pack_header(
    *,
    asset_count: int,
    asset_table_offset: int,
    string_table_offset: int,
    string_table_size: int,
    data_section_offset: int,
    data_section_size: int,
    magic: int = BUN_MAGIC,
    version_major: int = BUN_VERSION_MAJOR,
    version_minor: int = BUN_VERSION_MINOR,
    reserved: int = 0,
) -> bytes:
    """Return a packed BUN header."""
    return struct.pack(
        _HEADER_FMT,
        magic,
        version_major,
        version_minor,
        asset_count,
        asset_table_offset,
        string_table_offset,
        string_table_size,
        data_section_offset,
        data_section_size,
        reserved,
    )

def write_header_fixture(
    path: Path,
    *,
    truncate_to: Optional[int] = None,
    total_size: int = HEADER_SIZE,
    **header_fields,
) -> None:
    """Write a header-only fixture, optionally truncated or padded."""
    data = pack_header(**header_fields)
    if truncate_to is not None:
        data = data[:truncate_to]
    elif total_size > len(data):
        data += b"\x00" * (total_size - len(data))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def generate_header_fixtures(root: Path) -> None:
    """Generate the header parser fixtures used by tests/test_bun.c."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "valid").mkdir(exist_ok=True)
    (root / "invalid").mkdir(exist_ok=True)

    valid_empty = dict(
        asset_count         = 0,
        asset_table_offset  = HEADER_SIZE,
        string_table_offset = HEADER_SIZE,
        string_table_size   = 0,
        data_section_offset = HEADER_SIZE,
        data_section_size   = 0,
    )

    write_header_fixture(root / "valid" / "01-empty.bun", **valid_empty)

    write_header_fixture(
        root / "invalid" / "01-bad-magic.bun",
        **{**valid_empty, "magic": 0x12345678},
    )

    write_header_fixture(
        root / "invalid" / "02-bad-version.bun",
        **{**valid_empty, "version_major": 9, "version_minor": 9},
    )

    write_header_fixture(
        root / "invalid" / "03-truncated-header.bun",
        truncate_to=HEADER_SIZE - 1,
        **valid_empty,
    )

    write_header_fixture(
        root / "invalid" / "04-unaligned-offset.bun",
        total_size=64,
        **{**valid_empty, "asset_table_offset": HEADER_SIZE + 2},
    )

    write_header_fixture(
        root / "invalid" / "05-asset-table-oob.bun",
        **{**valid_empty, "asset_count": 1},
    )

    write_header_fixture(
        root / "invalid" / "06-overlap-sections.bun",
        total_size=112,
        asset_count         = 1,
        asset_table_offset  = HEADER_SIZE,
        string_table_offset = 80,
        string_table_size   = 32,
        data_section_offset = 112,
        data_section_size   = 0,
    )

def write_minimal(out_path: Path) -> None:
    """
    Write a minimal valid BUN file with a single uncompressed asset.

    Layout (canonical order):
      [header] [asset entry table] [string table] [data section]
    """
    asset_name    = b"hello"
    asset_payload = b"Hello, BUN world!\n"
    asset_count   = 1

    # Compute section offsets.
    # For a valid file, all offsets must be divisible by 4 (see spec section 4.1).
    asset_table_offset  = _align4(HEADER_SIZE)
    string_table_offset = _align4(asset_table_offset + asset_count * RECORD_SIZE)
    string_table_size   = _align4(len(asset_name))
    data_section_offset = _align4(string_table_offset + len(asset_name))
    data_section_size   = _align4(len(asset_payload))

    with open(out_path, "wb") as f:
        write_header(
            f,
            asset_count         = asset_count,
            asset_table_offset  = asset_table_offset,
            string_table_offset = string_table_offset,
            string_table_size   = string_table_size,
            data_section_offset = data_section_offset,
            data_section_size   = data_section_size,
        )

        def write_padded(size: int, desc: str):
            "helper for padding and output"
            if size > 0:
                write_padding(f, size, desc)

        # Pad to asset table offset (gap between header and asset table).
        # In canonical format, gaps are filled with null bytes.
        header_padding_len = asset_table_offset - HEADER_SIZE
        write_padded(header_padding_len, "header padding")

        write_asset_record(
            f,
            name_offset = 0,
            name_length = len(asset_name),
            data_offset = 0,
            data_size   = len(asset_payload),
        )

        # Pad to string table offset.
        records_padding_len = string_table_offset - (asset_table_offset + RECORD_SIZE)
        write_padded(records_padding_len, "records padding")

        f.write(asset_name)

        # Pad to end of string table
        name_padding_len = string_table_size - len(asset_name)
        write_padded(name_padding_len, "name padding")

        # Pad to data section offset
        strings_padding_len = data_section_offset - (string_table_offset + string_table_size)
        write_padded(strings_padding_len, "string table padding")

        f.write(asset_payload)

        # Pad to end of file
        payload_padding_len = data_section_size - len(asset_payload)
        write_padded(payload_padding_len, "payload padding")

    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")

def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate BUN files.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("minimal.bun"),
        help="output path for the default minimal BUN file",
    )
    parser.add_argument(
        "--header-fixtures",
        type=Path,
        metavar="DIR",
        help="generate header test fixtures under DIR/{valid,invalid}",
    )
    args = parser.parse_args(argv)

    if args.header_fixtures is not None:
        generate_header_fixtures(args.header_fixtures)
    else:
        write_minimal(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
