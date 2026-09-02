from __future__ import annotations

import struct
import uuid
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from http_pdb.errors import PdbFormatError, PdbIdentityMismatch

_MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
_INVALID_STREAM = 0xFFFF
_SECTION_HEADER_SIZE = 40

_SZ_ADDRESS_SYMBOLS = {
    0x110C,
    0x110D,
    0x110E,
    0x1112,
    0x1113,
}
_ST_ADDRESS_SYMBOLS = {
    0x1007,
    0x1008,
    0x1009,
    0x100E,
    0x100F,
}


@dataclass(frozen=True, slots=True)
class _DbiStreams:
    symbol_records: int
    section_headers: int
    original_section_headers: int
    omap_from_source: int


class _MsfFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._file: BinaryIO = path.open("rb")
        self._file_size = path.stat().st_size
        self.block_size = 0
        self.num_blocks = 0
        self._stream_sizes: list[int | None] = []
        self._stream_blocks: list[list[int]] = []
        try:
            self._load_directory()
        except Exception:
            self._file.close()
            raise

    def __enter__(self) -> _MsfFile:
        return self

    def __exit__(self, *_: object) -> None:
        self._file.close()

    def _read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self._file_size:
            raise PdbFormatError("PDB read exceeds file bounds")
        self._file.seek(offset)
        data = self._file.read(size)
        if len(data) != size:
            raise PdbFormatError("PDB is truncated")
        return data

    def _read_block(self, block: int) -> bytes:
        if block < 0 or block >= self.num_blocks:
            raise PdbFormatError("PDB references an invalid block")
        return self._read_at(block * self.block_size, self.block_size)

    def _load_directory(self) -> None:
        if self._file_size < 56:
            raise PdbFormatError("PDB is smaller than an MSF 7 superblock")
        header_prefix = self._read_at(0, 52)
        if header_prefix[:32] != _MSF7_MAGIC:
            raise PdbFormatError("only PDB/MSF 7 files are supported")

        (
            self.block_size,
            active_free_page_map,
            self.num_blocks,
            directory_size,
            _reserved,
        ) = struct.unpack_from("<5I", header_prefix, 32)

        if self.block_size < 512 or self.block_size > 65536:
            raise PdbFormatError("invalid MSF block size")
        if self.block_size & (self.block_size - 1):
            raise PdbFormatError("MSF block size is not a power of two")
        if active_free_page_map not in {1, 2}:
            raise PdbFormatError("invalid active MSF free page map")
        if self.num_blocks == 0 or self.num_blocks * self.block_size > self._file_size:
            raise PdbFormatError("invalid MSF block count")
        if directory_size < 4 or directory_size > self._file_size or directory_size % 4:
            raise PdbFormatError("invalid MSF directory size")

        directory_block_count = _blocks_for(directory_size, self.block_size)
        page_map_page_count = _blocks_for(directory_block_count * 4, self.block_size)
        page_map_end = 52 + page_map_page_count * 4
        if page_map_end > self.block_size:
            raise PdbFormatError("MSF directory page map does not fit in the header page")

        header_page = self._read_at(0, self.block_size)
        page_map_pages = struct.unpack_from(f"<{page_map_page_count}I", header_page, 52)
        block_map = b"".join(self._read_block(block) for block in page_map_pages)
        directory_blocks = struct.unpack_from(f"<{directory_block_count}I", block_map, 0)
        directory = b"".join(self._read_block(block) for block in directory_blocks)
        directory = directory[:directory_size]

        stream_count = _unpack_u32(directory, 0)
        if stream_count == 0 or stream_count > 1_000_000:
            raise PdbFormatError("unreasonable PDB stream count")
        sizes_offset = 4
        blocks_offset = sizes_offset + stream_count * 4
        if blocks_offset > len(directory):
            raise PdbFormatError("truncated PDB stream directory")

        raw_sizes = struct.unpack_from(f"<{stream_count}I", directory, sizes_offset)
        self._stream_sizes = [None if size == 0xFFFFFFFF else size for size in raw_sizes]
        self._stream_blocks = []

        cursor = blocks_offset
        for size in self._stream_sizes:
            block_count = 0 if size is None else _blocks_for(size, self.block_size)
            byte_count = block_count * 4
            if cursor + byte_count > len(directory):
                raise PdbFormatError("truncated PDB stream block list")
            blocks = list(struct.unpack_from(f"<{block_count}I", directory, cursor))
            if any(block >= self.num_blocks for block in blocks):
                raise PdbFormatError("PDB stream references an invalid block")
            self._stream_blocks.append(blocks)
            cursor += byte_count

    def has_stream(self, stream: int) -> bool:
        return (
            stream != _INVALID_STREAM
            and 0 <= stream < len(self._stream_sizes)
            and self._stream_sizes[stream] is not None
        )

    def read_stream(self, stream: int) -> bytes:
        if not self.has_stream(stream):
            raise PdbFormatError(f"PDB stream {stream} is missing")
        size = self._stream_sizes[stream]
        assert size is not None
        data = b"".join(self._read_block(block) for block in self._stream_blocks[stream])
        return data[:size]


class _Omap:
    def __init__(self, data: bytes) -> None:
        if not data or len(data) % 8:
            raise PdbFormatError("invalid OMAP stream")
        pairs = list(struct.iter_unpack("<II", data))
        self._source = [source for source, _target in pairs]
        self._target = [target for _source, target in pairs]
        if self._source != sorted(self._source):
            raise PdbFormatError("unsorted OMAP stream")

    def remap(self, rva: int) -> int | None:
        index = bisect_right(self._source, rva) - 1
        if index < 0 or self._target[index] == 0:
            return None
        return self._target[index] + (rva - self._source[index])


def _blocks_for(size: int, block_size: int) -> int:
    return (size + block_size - 1) // block_size


def _unpack_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise PdbFormatError("truncated PDB data")
    return struct.unpack_from("<I", data, offset)[0]


def _identifier(reader: _MsfFile) -> str:
    info = reader.read_stream(1)
    if len(info) < 28:
        raise PdbFormatError("truncated PDB info stream")
    age = struct.unpack_from("<I", info, 8)[0]
    guid = uuid.UUID(bytes_le=info[12:28])
    dbi = reader.read_stream(3)
    if len(dbi) >= 64 and struct.unpack_from("<I", dbi, 0)[0] == 0xFFFFFFFF:
        dbi_age = struct.unpack_from("<I", dbi, 8)[0]
        dbi_flags = struct.unpack_from("<H", dbi, 56)[0]
        if dbi_flags & 0x2:
            age = dbi_age
    return f"{guid.hex.upper()}{age:X}"


def pdb_identifier(path: Path) -> str:
    with _MsfFile(path) as reader:
        return _identifier(reader)


def _dbi_streams(reader: _MsfFile) -> _DbiStreams:
    dbi = reader.read_stream(3)
    if len(dbi) < 64 or struct.unpack_from("<I", dbi, 0)[0] != 0xFFFFFFFF:
        raise PdbFormatError("invalid DBI stream header")

    symbol_records = struct.unpack_from("<H", dbi, 20)[0]
    module_size, section_contribution_size, section_map_size, file_info_size, type_map_size = (
        struct.unpack_from("<5I", dbi, 24)
    )
    debug_header_size = struct.unpack_from("<I", dbi, 48)[0]
    ec_info_size = struct.unpack_from("<I", dbi, 52)[0]
    debug_header_offset = 64 + sum(
        (
            module_size,
            section_contribution_size,
            section_map_size,
            file_info_size,
            type_map_size,
            ec_info_size,
        )
    )
    if debug_header_size < 22 or debug_header_offset + debug_header_size > len(dbi):
        raise PdbFormatError("DBI optional debug header is missing or truncated")

    debug_streams = struct.unpack_from("<11H", dbi, debug_header_offset)
    return _DbiStreams(
        symbol_records=symbol_records,
        section_headers=debug_streams[5],
        original_section_headers=debug_streams[10],
        omap_from_source=debug_streams[4],
    )


def _section_rvas(data: bytes) -> list[int]:
    if len(data) < _SECTION_HEADER_SIZE:
        raise PdbFormatError("PDB section header stream is empty")
    sections = []
    for offset in range(0, len(data) - (_SECTION_HEADER_SIZE - 1), _SECTION_HEADER_SIZE):
        sections.append(struct.unpack_from("<I", data, offset + 12)[0])
    return sections


def _decode_name(record: bytes, *, pascal: bool) -> str:
    raw = record[14:]
    if pascal:
        if not raw or raw[0] > len(raw) - 1:
            raise PdbFormatError("invalid Pascal symbol name")
        raw = raw[1 : raw[0] + 1]
    else:
        raw = raw.split(b"\x00", 1)[0]
    return raw.decode("utf-8", errors="replace")


def _parse_symbols(data: bytes, section_rvas: list[int], omap: _Omap | None) -> dict[str, int]:
    symbols: dict[str, int] = {}
    cursor = 0
    while cursor + 4 <= len(data):
        record_length = struct.unpack_from("<H", data, cursor)[0]
        total_length = record_length + 2
        if record_length < 2 or cursor + total_length > len(data):
            raise PdbFormatError("invalid CodeView symbol record length")
        record = data[cursor : cursor + total_length]
        kind = struct.unpack_from("<H", record, 2)[0]

        if kind in _SZ_ADDRESS_SYMBOLS or kind in _ST_ADDRESS_SYMBOLS:
            if len(record) < 15:
                raise PdbFormatError("truncated address symbol record")
            _type_or_flags, offset, segment = struct.unpack_from("<IIH", record, 4)
            if 0 < segment <= len(section_rvas):
                rva = section_rvas[segment - 1] + offset
                if omap is not None:
                    mapped = omap.remap(rva)
                    if mapped is None:
                        cursor += total_length
                        continue
                    rva = mapped
                if rva <= 0xFFFFFFFF:
                    name = _decode_name(record, pascal=kind in _ST_ADDRESS_SYMBOLS)
                    if name:
                        previous = symbols.get(name)
                        if previous is None or rva < previous:
                            symbols[name] = rva

        cursor += total_length
    return symbols


def read_symbol_index(path: Path, expected_key: str | None = None) -> dict[str, int]:
    with _MsfFile(path) as reader:
        actual_key = _identifier(reader)
        if expected_key is not None and actual_key != expected_key.upper():
            raise PdbIdentityMismatch(expected_key.upper(), actual_key)

        streams = _dbi_streams(reader)
        use_omap = reader.has_stream(streams.original_section_headers) and reader.has_stream(
            streams.omap_from_source
        )
        if use_omap:
            sections = _section_rvas(reader.read_stream(streams.original_section_headers))
            omap = _Omap(reader.read_stream(streams.omap_from_source))
        else:
            sections = _section_rvas(reader.read_stream(streams.section_headers))
            omap = None

        symbol_records = reader.read_stream(streams.symbol_records)
        return _parse_symbols(symbol_records, sections, omap)
