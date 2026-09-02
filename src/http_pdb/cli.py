from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "http_pdb.main:app",
        host=os.getenv("HTTP_PDB_HOST", "127.0.0.1"),
        port=int(os.getenv("HTTP_PDB_PORT", "8000")),
        workers=int(os.getenv("HTTP_PDB_WORKERS", "1")),
    )
