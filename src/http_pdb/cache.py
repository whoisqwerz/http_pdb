from __future__ import annotations

import sqlite3
import time
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CacheLookup:
    indexed: bool
    rva: int | None


class SymbolIndexCache:
    def __init__(self, cache_dir: Path) -> None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.path = cache_dir / "symbols-v1.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pdb_indexes (
                    pdb_name TEXT NOT NULL,
                    pdb_key TEXT NOT NULL,
                    indexed_at INTEGER NOT NULL,
                    symbol_count INTEGER NOT NULL,
                    PRIMARY KEY (pdb_name, pdb_key)
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS symbols (
                    pdb_name TEXT NOT NULL,
                    pdb_key TEXT NOT NULL,
                    symbol TEXT NOT NULL,
                    rva INTEGER NOT NULL,
                    PRIMARY KEY (pdb_name, pdb_key, symbol)
                ) WITHOUT ROWID
                """
            )

    def lookup(self, pdb_name: str, pdb_key: str, symbol: str) -> CacheLookup:
        with closing(self._connect()) as connection, connection:
            indexed = connection.execute(
                "SELECT 1 FROM pdb_indexes WHERE pdb_name = ? AND pdb_key = ?",
                (pdb_name, pdb_key),
            ).fetchone()
            if indexed is None:
                return CacheLookup(indexed=False, rva=None)
            row = connection.execute(
                """
                SELECT rva FROM symbols
                WHERE pdb_name = ? AND pdb_key = ? AND symbol = ?
                """,
                (pdb_name, pdb_key, symbol),
            ).fetchone()
            return CacheLookup(indexed=True, rva=None if row is None else int(row[0]))

    def store_index(self, pdb_name: str, pdb_key: str, symbols: Mapping[str, int]) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            already_indexed = connection.execute(
                "SELECT 1 FROM pdb_indexes WHERE pdb_name = ? AND pdb_key = ?",
                (pdb_name, pdb_key),
            ).fetchone()
            if already_indexed is not None:
                return
            connection.executemany(
                """
                INSERT INTO symbols (pdb_name, pdb_key, symbol, rva)
                VALUES (?, ?, ?, ?)
                """,
                ((pdb_name, pdb_key, name, rva) for name, rva in symbols.items()),
            )
            connection.execute(
                """
                INSERT INTO pdb_indexes (pdb_name, pdb_key, indexed_at, symbol_count)
                VALUES (?, ?, ?, ?)
                """,
                (pdb_name, pdb_key, int(time.time()), len(symbols)),
            )
