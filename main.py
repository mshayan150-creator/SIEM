"""ASGI entry point. SIGTERM/SIGINT are handled by Uvicorn's lifespan protocol."""
import asyncio
import hashlib
import logging
import re
import sqlite3
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Annotated, Any

import structlog
from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from redis.exceptions import RedisError
from starlette.types import Message, Receive, Scope, Send
from structlog.typing import Processor

from auth import IdentityStore, collector_auth
from cache import Cache, IdempotencyConflict, QueueFull
from config import Settings
from dashboard import router as dashboard_router
from database import Database
from engine import Engine
from schemas import Accepted, Batch


def configure_logging() -> None:
    processors: list[Processor] = [structlog.contextvars.merge_contextvars, structlog.stdlib.add_log_level,
                  structlog.processors.TimeStamper(fmt="iso", utc=True)]
    structlog.configure(
        processors=[*processors, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(), cache_logger_on_first_use=True,
    )
    handler = logging.StreamHandler()
    handler.setFormatter(structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=processors,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.JSONRenderer()],
    ))
    logging.getLogger().handlers = [handler]
    logging.getLogger().setLevel(logging.INFO)
    for name in ("httpx", "httpcore", "elastic_transport", "elasticsearch"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True


class StartupFailure(RuntimeError):
    """Expected configuration/dependency failure; contains no source exception text."""


class StartupSafeFastAPI(FastAPI):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def safe_send(message: Message) -> None:
            if message["type"] == "lifespan.startup.failed" and getattr(self.state, "startup_failed", False):
                # Starlette serializes a traceback into this message, even when the
                # exception was caught/logged in lifespan. Keep Uvicorn's failure
                # signal and nonzero exit, but replace that serialized traceback.
                message = {"type": "lifespan.startup.failed", "message": "Startup failed; see startup_failed log."}
            await send(message)

        await super().__call__(scope, receive, safe_send if scope["type"] == "lifespan" else send)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    app.state.startup_failed = False
    stage = "configuration"
    async with AsyncExitStack() as resources:
        try:
            settings = Settings()
            stage = "client_initialization"
            cache = Cache(settings)
            resources.push_async_callback(cache.redis.aclose)
            database = Database(settings)
            resources.push_async_callback(database.client.close)
            engine = Engine(settings, cache, database)
            resources.push_async_callback(engine.close)
            app.state.settings, app.state.cache, app.state.engine = settings, cache, engine
            app.state.database = database
            stage = "identities"
            app.state.identities = IdentityStore(settings.identity_db_path)
            await asyncio.to_thread(app.state.identities.initialize)
            app.state.password_slots = asyncio.Semaphore(2)
            stage = "redis"
            await cache.initialize()
            stage = "elasticsearch"
            await database.client.info()
            engine.start()
        except (ValidationError, RedisError, TransportError, ApiError, OSError, sqlite3.Error, TimeoutError) as exc:
            app.state.startup_failed = True
            log.error("startup_failed", dependency=stage, error_type=type(exc).__name__,
                      hint="Check configuration, credentials and dependency availability")
            raise StartupFailure("Startup failed") from None
        yield


app = StartupSafeFastAPI(title="SIEM ingestion", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None)
log = structlog.get_logger()


@app.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
async def ready(request: Request) -> JSONResponse:
    engine: Engine = request.app.state.engine
    try:
        await request.app.state.cache.redis.ping()
        healthy = engine.healthy
    except RedisError:
        healthy = False
    return JSONResponse({"ready": healthy}, status_code=200 if healthy else 503)


def batch_openapi_schema() -> dict[str, Any]:
    schema = Batch.model_json_schema()
    definitions = schema.pop("$defs", {})

    def expand(value: Any) -> Any:
        if isinstance(value, dict):
            if "$ref" in value:
                return expand(definitions[value["$ref"].split("/")[-1]])
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        return value

    result: dict[str, Any] = expand(schema)
    return result


@app.post("/api/v1/telemetry", response_model=Accepted, status_code=202,
          openapi_extra={"requestBody": {"required": True, "content": {
              "application/json": {"schema": batch_openapi_schema()}}}})
async def telemetry(
    request: Request,
    idempotency_key: Annotated[str | None, Header()] = None,
) -> Accepted:
    settings: Settings = request.app.state.settings
    collector = await collector_auth(request)
    if not idempotency_key or not re.fullmatch(r"[A-Za-z0-9_.:-]{16,128}", idempotency_key):
        raise HTTPException(400, "Provide a unique 16–128 character Idempotency-Key per batch; reuse it for retries")
    if not request.app.state.engine.healthy:
        raise HTTPException(503, "Worker unavailable", headers={"Retry-After": "5"})
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Content-Type must be application/json")
    if request.headers.get("content-encoding", "identity") != "identity":
        raise HTTPException(415, "Compressed request bodies are not accepted")
    body = bytearray()
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                if len(body) + len(chunk) > settings.max_body_bytes:
                    raise HTTPException(413, "Request body too large")
                body.extend(chunk)
    except TimeoutError:
        raise HTTPException(408, "Request body timeout") from None
    try:
        batch = Batch.model_validate_json(bytes(body))
    except ValidationError as exc:
        # Return field paths and types, never sensitive values or exception context.
        raise HTTPException(422, [{"loc": error["loc"], "type": error["type"]}
                                  for error in exc.errors(include_input=False, include_context=False)]) from None
    if len(batch.events) > settings.max_batch:
        raise HTTPException(413, "Batch exceeds configured event limit")
    if any(event.host is None or event.host.name.casefold() != collector["host"].casefold() for event in batch.events):
        raise HTTPException(403, "Events must match the hostname registered for this collector")
    # Collectors may independently choose the same batch key without colliding.
    scoped_key = hashlib.sha256((collector["id"] + ":" + idempotency_key).encode()).hexdigest()
    try:
        duplicate = await request.app.state.cache.ingest(batch.events, scoped_key)
    except IdempotencyConflict:
        raise HTTPException(409, "Idempotency-Key already used for a different batch") from None
    except QueueFull:
        raise HTTPException(503, "Delivery queues are full", headers={"Retry-After": "5"}) from None
    except RedisError as exc:
        log.error("ingest_failed", error_type=type(exc).__name__)
        raise HTTPException(503, "Ingestion unavailable; retry with the same Idempotency-Key",
                            headers={"Retry-After": "5"}) from None
    log.info("batch_accepted", count=len(batch.events), duplicate=duplicate)
    return Accepted(accepted=len(batch.events), duplicate=duplicate)


app.include_router(dashboard_router)


@app.middleware("http")
async def response_security(request: Request, call_next: Any) -> Response:
    try:
        response = await call_next(request)
    except (RedisError, sqlite3.Error):
        return JSONResponse({"detail": "State service unavailable"}, status_code=503)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.url.path.startswith("/api/v1/dashboard"):
        response.headers["Cache-Control"] = "no-store"
    return response
