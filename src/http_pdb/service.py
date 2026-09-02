from __future__ import annotations

import threading
from dataclasses import dataclass

from http_pdb.cache import SymbolIndexCache
from http_pdb.config import Settings
from http_pdb.errors import SymbolNotFound
from http_pdb.models import normalize_dll, normalize_pdb_key, normalize_symbol
from http_pdb.pdb_reader import read_symbol_index
from http_pdb.symbol_server import PdbStore


@dataclass(frozen=True, slots=True)
class ResolveResult:
    dll: str
    pdb: str
    symbol: str
    key: str
    rva: int
    cached: bool
    pdb_cached: bool


class SymbolService:
    def __init__(
        self,
        settings: Settings,
        *,
        store: PdbStore | None = None,
        index_cache: SymbolIndexCache | None = None,
    ) -> None:
        self._store = store or PdbStore(settings)
        self._index_cache = index_cache or SymbolIndexCache(settings.cache_dir)
        self._locks = [threading.Lock() for _ in range(64)]

    def close(self) -> None:
        self._store.close()

    def resolve(self, dll: str, symbol: str, key: str) -> ResolveResult:
        dll = normalize_dll(dll)
        symbol = normalize_symbol(symbol)
        key = normalize_pdb_key(key)
        pdb_name = f"{dll[:-4]}.pdb"

        lookup = self._index_cache.lookup(pdb_name, key, symbol)
        if lookup.indexed:
            return self._from_lookup(dll, pdb_name, symbol, key, lookup.rva, cached=True)

        lock = self._locks[hash((pdb_name, key)) % len(self._locks)]
        with lock:
            lookup = self._index_cache.lookup(pdb_name, key, symbol)
            if lookup.indexed:
                return self._from_lookup(dll, pdb_name, symbol, key, lookup.rva, cached=True)

            cached_pdb = self._store.get(pdb_name, key)
            symbols = read_symbol_index(cached_pdb.path, expected_key=key)
            self._index_cache.store_index(pdb_name, key, symbols)
            return self._from_lookup(
                dll,
                pdb_name,
                symbol,
                key,
                symbols.get(symbol),
                cached=False,
                pdb_cached=cached_pdb.cached,
            )

    @staticmethod
    def _from_lookup(
        dll: str,
        pdb_name: str,
        symbol: str,
        key: str,
        rva: int | None,
        *,
        cached: bool,
        pdb_cached: bool = True,
    ) -> ResolveResult:
        if rva is None:
            raise SymbolNotFound(dll, symbol, key, cached=cached)
        return ResolveResult(
            dll=dll,
            pdb=pdb_name,
            symbol=symbol,
            key=key,
            rva=rva,
            cached=cached,
            pdb_cached=pdb_cached,
        )
