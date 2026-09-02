from pathlib import Path

from fastapi.testclient import TestClient

from http_pdb.config import Settings
from http_pdb.main import create_app
from http_pdb.service import SymbolService
from tests.pdb_fixture import build_test_pdb


def test_resolve_endpoint_and_cache_header(tmp_path: Path) -> None:
    settings = Settings(cache_dir=tmp_path)
    fixture = tmp_path / "fixture.pdb"
    key = build_test_pdb(fixture, symbols={"TestSymbol": 0x1234})
    cached_path = tmp_path / "pdb" / "test.pdb" / key / "test.pdb"
    cached_path.parent.mkdir(parents=True)
    fixture.replace(cached_path)
    service = SymbolService(settings)
    app = create_app(settings, service)

    try:
        with TestClient(app) as client:
            first = client.post(
                "/v1/resolve",
                json={"dll": "test.dll", "symbol": "TestSymbol", "key": key},
            )
            second = client.get(
                "/v1/resolve",
                params={"dll": "test.dll", "symbol": "TestSymbol", "key": key},
            )
            health = client.get("/health")
    finally:
        service.close()

    assert first.status_code == 200
    assert first.headers["x-cache"] == "MISS"
    assert first.json()["rva"] == 0x1234
    assert first.json()["rva_hex"] == "0x1234"
    assert second.status_code == 200
    assert second.headers["x-cache"] == "HIT"
    assert second.json()["cached"] is True
    assert health.json() == {"status": "ok"}


def test_rejects_path_traversal_before_resolving(tmp_path: Path) -> None:
    settings = Settings(cache_dir=tmp_path)
    service = SymbolService(settings)
    app = create_app(settings, service)

    try:
        with TestClient(app) as client:
            response = client.post(
                "/v1/resolve",
                json={
                    "dll": "../ntdll.dll",
                    "symbol": "TestSymbol",
                    "key": "11BDBCF721AA1FA8527D3B1CB267D7F21",
                },
            )
    finally:
        service.close()

    assert response.status_code == 422
