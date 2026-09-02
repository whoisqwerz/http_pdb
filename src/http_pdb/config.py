from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def _read_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return default if raw is None else int(raw)


def _read_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    return default if raw is None else float(raw)


@dataclass(frozen=True, slots=True)
class Settings:
    symbol_server_url: str = "https://msdl.microsoft.com/download/symbols"
    cache_dir: Path = Path(".cache")
    connect_timeout: float = 10.0
    read_timeout: float = 60.0
    max_pdb_size: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        parsed = urlparse(self.symbol_server_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("symbol_server_url must be an HTTP(S) URL")
        if self.connect_timeout <= 0 or self.read_timeout <= 0:
            raise ValueError("timeouts must be positive")
        if self.max_pdb_size <= 0:
            raise ValueError("max_pdb_size must be positive")

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            symbol_server_url=os.getenv(
                "HTTP_PDB_SYMBOL_SERVER", "https://msdl.microsoft.com/download/symbols"
            ).rstrip("/"),
            cache_dir=Path(os.getenv("HTTP_PDB_CACHE_DIR", ".cache")),
            connect_timeout=_read_float("HTTP_PDB_CONNECT_TIMEOUT", 10.0),
            read_timeout=_read_float("HTTP_PDB_READ_TIMEOUT", 60.0),
            max_pdb_size=_read_int("HTTP_PDB_MAX_PDB_SIZE", 256 * 1024 * 1024),
        )
