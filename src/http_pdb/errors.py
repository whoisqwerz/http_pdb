class ResolverError(Exception):
    pass


class PdbFormatError(ResolverError):
    pass


class PdbIdentityMismatch(PdbFormatError):
    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"PDB identity mismatch: expected {expected}, got {actual}")


class PdbNotFound(ResolverError):
    def __init__(self, pdb_name: str, key: str) -> None:
        self.pdb_name = pdb_name
        self.key = key
        super().__init__(f"PDB not found: {pdb_name}/{key}")


class SymbolNotFound(ResolverError):
    def __init__(self, dll: str, symbol: str, key: str, *, cached: bool) -> None:
        self.dll = dll
        self.symbol = symbol
        self.key = key
        self.cached = cached
        super().__init__(f"Symbol not found: {dll}!{symbol}")


class SymbolServerError(ResolverError):
    pass
