from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from http_pdb import __version__
from http_pdb.config import Settings
from http_pdb.errors import (
    PdbFormatError,
    PdbNotFound,
    SymbolNotFound,
    SymbolServerError,
)
from http_pdb.models import HealthResponse, ResolveRequest, ResolveResponse
from http_pdb.service import ResolveResult, SymbolService


def create_app(
    settings: Settings | None = None,
    service: SymbolService | None = None,
) -> FastAPI:
    configured_settings = settings or Settings.from_env()
    owns_service = service is None

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.symbol_service = service or SymbolService(configured_settings)
        try:
            yield
        finally:
            if owns_service:
                application.state.symbol_service.close()

    application = FastAPI(
        title="HTTP PDB",
        version=__version__,
        lifespan=lifespan,
    )

    def get_service(request: Request) -> SymbolService:
        return request.app.state.symbol_service

    def perform_resolve(
        payload: ResolveRequest,
        response: Response,
        resolver: SymbolService,
    ) -> ResolveResponse:
        try:
            result = resolver.resolve(payload.dll, payload.symbol, payload.key)
        except SymbolNotFound as error:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "symbol_not_found",
                    "dll": error.dll,
                    "symbol": error.symbol,
                    "key": error.key,
                    "cached": error.cached,
                },
                headers={"X-Cache": "HIT" if error.cached else "MISS"},
            ) from error
        except PdbNotFound as error:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "pdb_not_found",
                    "pdb": error.pdb_name,
                    "key": error.key,
                },
                headers={"X-Cache": "MISS"},
            ) from error
        except SymbolServerError as error:
            raise HTTPException(
                status_code=502,
                detail={"code": "symbol_server_error", "message": str(error)},
            ) from error
        except PdbFormatError as error:
            raise HTTPException(
                status_code=502,
                detail={"code": "invalid_pdb", "message": str(error)},
            ) from error

        response.headers["X-Cache"] = "HIT" if result.cached else "MISS"
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return _response_from_result(result)

    @application.get("/health", response_model=HealthResponse, tags=["service"])
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @application.post("/v1/resolve", response_model=ResolveResponse, tags=["symbols"])
    def resolve_post(
        payload: ResolveRequest,
        response: Response,
        resolver: Annotated[SymbolService, Depends(get_service)],
    ) -> ResolveResponse:
        return perform_resolve(payload, response, resolver)

    @application.get("/v1/resolve", response_model=ResolveResponse, tags=["symbols"])
    def resolve_get(
        response: Response,
        dll: Annotated[str, Query(min_length=5, max_length=255)],
        symbol: Annotated[str, Query(min_length=1, max_length=1024)],
        key: Annotated[str, Query(min_length=33, max_length=64)],
        resolver: Annotated[SymbolService, Depends(get_service)],
    ) -> ResolveResponse:
        try:
            payload = ResolveRequest(dll=dll, symbol=symbol, key=key)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return perform_resolve(payload, response, resolver)

    return application


def _response_from_result(result: ResolveResult) -> ResolveResponse:
    return ResolveResponse(
        dll=result.dll,
        pdb=result.pdb,
        symbol=result.symbol,
        key=result.key,
        rva=result.rva,
        rva_hex=f"0x{result.rva:X}",
        cached=result.cached,
        pdb_cached=result.pdb_cached,
    )


app = create_app()
