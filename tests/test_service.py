from pathlib import Path

import pytest

from http_pdb.config import Settings
from http_pdb.errors import SymbolNotFound
from http_pdb.service import SymbolService
from tests.pdb_fixture import build_test_pdb


def test_persists_entire_symbol_index(tmp_path: Path) -> None:
    settings = Settings(cache_dir=tmp_path)
    temporary_path = tmp_path / "fixture.pdb"
    key = build_test_pdb(temporary_path, symbols={"TestSymbol": 0x1234})
    cached_path = tmp_path / "pdb" / "test.pdb" / key / "test.pdb"
    cached_path.parent.mkdir(parents=True)
    temporary_path.replace(cached_path)

    first_service = SymbolService(settings)
    try:
        first = first_service.resolve("test.dll", "TestSymbol", key)
        second = first_service.resolve("test.dll", "TestSymbol", key)
    finally:
        first_service.close()

    assert first.rva == 0x1234
    assert first.cached is False
    assert first.pdb_cached is True
    assert second.rva == 0x1234
    assert second.cached is True

    cached_path.unlink()
    second_service = SymbolService(settings)
    try:
        persisted = second_service.resolve("test.dll", "TestSymbol", key)
        with pytest.raises(SymbolNotFound) as missing:
            second_service.resolve("test.dll", "MissingSymbol", key)
    finally:
        second_service.close()

    assert persisted.rva == 0x1234
    assert persisted.cached is True
    assert missing.value.cached is True
