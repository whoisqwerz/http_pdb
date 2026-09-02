from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_DLL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,249}\.dll", re.IGNORECASE)
_PDB_KEY_PATTERN = re.compile(r"[0-9A-F]{33,40}")


def normalize_dll(value: str) -> str:
    normalized = value.strip().lower()
    if not _DLL_PATTERN.fullmatch(normalized):
        raise ValueError("dll must be a base file name ending in .dll")
    return normalized


def normalize_symbol(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("symbol must not be empty")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in normalized):
        raise ValueError("symbol must not contain control characters")
    return normalized


def normalize_pdb_key(value: str) -> str:
    normalized = value.strip().replace("-", "").replace("{", "").replace("}", "").upper()
    if not _PDB_KEY_PATTERN.fullmatch(normalized):
        raise ValueError("key must contain a 32-hex GUID followed by a 1-8 hex age")
    return normalized


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dll: str = Field(min_length=5, max_length=255)
    symbol: str = Field(min_length=1, max_length=1024)
    key: str = Field(min_length=33, max_length=64)

    @field_validator("dll")
    @classmethod
    def validate_dll(cls, value: str) -> str:
        return normalize_dll(value)

    @field_validator("symbol")
    @classmethod
    def validate_symbol(cls, value: str) -> str:
        return normalize_symbol(value)

    @field_validator("key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        return normalize_pdb_key(value)


class ResolveResponse(BaseModel):
    dll: str
    pdb: str
    symbol: str
    key: str
    rva: int
    rva_hex: str
    cached: bool
    pdb_cached: bool


class HealthResponse(BaseModel):
    status: str
