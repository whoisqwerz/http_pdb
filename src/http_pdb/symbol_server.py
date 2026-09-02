from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx

from http_pdb.config import Settings
from http_pdb.errors import PdbFormatError, PdbNotFound, SymbolServerError
from http_pdb.pdb_reader import pdb_identifier


@dataclass(frozen=True, slots=True)
class CachedPdb:
    path: Path
    cached: bool


class PdbStore:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._owns_client = client is None
        self._client = client or httpx.Client(
            follow_redirects=True,
            headers={"User-Agent": "http-pdb/0.1"},
            timeout=httpx.Timeout(
                settings.read_timeout,
                connect=settings.connect_timeout,
            ),
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def path_for(self, pdb_name: str, key: str) -> Path:
        return self._settings.cache_dir / "pdb" / pdb_name / key / pdb_name

    def get(self, pdb_name: str, key: str) -> CachedPdb:
        target = self.path_for(pdb_name, key)
        if target.is_file():
            try:
                if pdb_identifier(target) == key:
                    return CachedPdb(path=target, cached=True)
            except (OSError, PdbFormatError):
                pass

        target.parent.mkdir(parents=True, exist_ok=True)
        url = "/".join(
            (
                self._settings.symbol_server_url.rstrip("/"),
                quote(pdb_name, safe=""),
                quote(key, safe=""),
                quote(pdb_name, safe=""),
            )
        )

        descriptor, temporary_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{pdb_name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        try:
            try:
                with self._client.stream("GET", url) as response:
                    if response.status_code == 404:
                        raise PdbNotFound(pdb_name, key)
                    if response.is_error:
                        raise SymbolServerError(
                            f"symbol server returned HTTP {response.status_code}"
                        )
                    content_length = response.headers.get("Content-Length")
                    if (
                        content_length is not None
                        and int(content_length) > self._settings.max_pdb_size
                    ):
                        raise SymbolServerError("PDB exceeds the configured size limit")

                    written = 0
                    with os.fdopen(descriptor, "wb") as output:
                        descriptor = -1
                        for chunk in response.iter_bytes():
                            written += len(chunk)
                            if written > self._settings.max_pdb_size:
                                raise SymbolServerError("PDB exceeds the configured size limit")
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
            except httpx.RequestError as error:
                raise SymbolServerError(f"symbol server request failed: {error}") from error
            except ValueError as error:
                raise SymbolServerError(
                    "symbol server returned an invalid Content-Length"
                ) from error

            actual_key = pdb_identifier(temporary)
            if actual_key != key:
                raise SymbolServerError(
                    f"symbol server returned a PDB with key {actual_key}, expected {key}"
                )
            os.replace(temporary, target)
            return CachedPdb(path=target, cached=False)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
