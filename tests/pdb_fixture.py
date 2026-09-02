from __future__ import annotations

import struct
import uuid
from pathlib import Path

_MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
_BLOCK_SIZE = 512


def build_test_pdb(
    path: Path,
    *,
    symbols: dict[str, int] | None = None,
    stripped: bool = False,
) -> str:
    symbols = symbols or {"TestSymbol": 0x1234}
    guid = uuid.UUID("12345678-1234-5678-90ab-cdef01234567")
    image_age = 1
    info_age = 3 if stripped else image_age
    key = f"{guid.hex.upper()}{image_age:X}"

    info = struct.pack("<III", 20000404, 0, info_age) + guid.bytes_le

    dbi_header = bytearray(64)
    struct.pack_into("<I", dbi_header, 0, 0xFFFFFFFF)
    struct.pack_into("<I", dbi_header, 4, 19990903)
    struct.pack_into("<I", dbi_header, 8, image_age)
    struct.pack_into("<H", dbi_header, 20, 4)
    struct.pack_into("<I", dbi_header, 48, 22)
    struct.pack_into("<H", dbi_header, 56, 0x2 if stripped else 0)
    struct.pack_into("<H", dbi_header, 58, 0x8664)
    debug_streams = [0xFFFF] * 11
    debug_streams[5] = 5
    dbi = bytes(dbi_header) + struct.pack("<11H", *debug_streams)

    symbol_records = b"".join(
        _public_symbol_record(name, rva - 0x1000) for name, rva in symbols.items()
    )
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x4000,
        0x1000,
        0,
        0,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    streams = [b"", info, b"", dbi, symbol_records, section]
    stream_blocks: list[list[int]] = []
    next_block = 4
    for stream in streams:
        count = (len(stream) + _BLOCK_SIZE - 1) // _BLOCK_SIZE
        blocks = list(range(next_block, next_block + count))
        stream_blocks.append(blocks)
        next_block += count

    directory = struct.pack("<I", len(streams))
    directory += struct.pack(f"<{len(streams)}I", *(len(stream) for stream in streams))
    directory += b"".join(
        struct.pack(f"<{len(blocks)}I", *blocks) for blocks in stream_blocks if blocks
    )
    if len(directory) > _BLOCK_SIZE:
        raise AssertionError("test directory unexpectedly spans multiple blocks")

    file_data = bytearray(next_block * _BLOCK_SIZE)
    file_data[:56] = _MSF7_MAGIC + struct.pack(
        "<6I", _BLOCK_SIZE, 1, next_block, len(directory), 0, 2
    )
    struct.pack_into("<I", file_data, 2 * _BLOCK_SIZE, 3)
    file_data[3 * _BLOCK_SIZE : 3 * _BLOCK_SIZE + len(directory)] = directory

    for stream, blocks in zip(streams, stream_blocks, strict=True):
        for index, block in enumerate(blocks):
            chunk = stream[index * _BLOCK_SIZE : (index + 1) * _BLOCK_SIZE]
            start = block * _BLOCK_SIZE
            file_data[start : start + len(chunk)] = chunk

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(file_data)
    return key


def _public_symbol_record(name: str, offset: int) -> bytes:
    body = struct.pack("<HIIH", 0x110E, 0, offset, 1) + name.encode() + b"\x00"
    body += b"\x00" * (-(len(body) + 2) % 4)
    return struct.pack("<H", len(body)) + body
