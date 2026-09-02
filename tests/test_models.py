import pytest
from pydantic import ValidationError

from http_pdb.models import ResolveRequest


def test_normalizes_request() -> None:
    request = ResolveRequest(
        dll=" NTDLL.DLL ",
        symbol=" LdrpHandleTlsData ",
        key="{11bdbcf7-21aa-1fa8-527d-3b1cb267d7f2}1",
    )

    assert request.dll == "ntdll.dll"
    assert request.symbol == "LdrpHandleTlsData"
    assert request.key == "11BDBCF721AA1FA8527D3B1CB267D7F21"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dll", "../ntdll.dll"),
        ("dll", "ntdll.exe"),
        ("symbol", "bad\nsymbol"),
        ("key", "not-a-pdb-key"),
    ],
)
def test_rejects_invalid_request(field: str, value: str) -> None:
    data = {
        "dll": "ntdll.dll",
        "symbol": "LdrpHandleTlsData",
        "key": "11BDBCF721AA1FA8527D3B1CB267D7F21",
    }
    data[field] = value

    with pytest.raises(ValidationError):
        ResolveRequest(**data)
