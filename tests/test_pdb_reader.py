from pathlib import Path

import pytest

from http_pdb.errors import PdbIdentityMismatch
from http_pdb.pdb_reader import pdb_identifier, read_symbol_index
from tests.pdb_fixture import build_test_pdb


@pytest.mark.parametrize("stripped", [False, True])
def test_reads_public_symbols_and_image_key(tmp_path: Path, stripped: bool) -> None:
    path = tmp_path / "test.pdb"
    key = build_test_pdb(
        path,
        symbols={"TestSymbol": 0x1234, "SecondSymbol": 0x2345},
        stripped=stripped,
    )

    assert pdb_identifier(path) == key
    assert read_symbol_index(path, key) == {
        "TestSymbol": 0x1234,
        "SecondSymbol": 0x2345,
    }


def test_rejects_wrong_pdb_key(tmp_path: Path) -> None:
    path = tmp_path / "test.pdb"
    build_test_pdb(path)

    with pytest.raises(PdbIdentityMismatch):
        read_symbol_index(path, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1")
