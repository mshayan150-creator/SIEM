"""Local-only signed webhook sink. Verifies signatures and records receipt metadata, without evidence."""
import hashlib
import hmac
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError

from monitoring import record_status
from schemas import Incident


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    redis = Redis.from_url(os.environ["SIEM_REDIS_URL"], decode_responses=True)
    app.state.redis = redis
    try:
        yield
    finally:
        await redis.aclose()


app = FastAPI(docs_url=None, redoc_url=None, lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "local-sink"}


@app.post("/incidents", status_code=204)
async def incident(request: Request) -> Response:
    timestamp = request.headers.get("X-SIEM-Timestamp", "")
    try:
        fresh = abs(time.time() - int(timestamp)) <= 300
    except ValueError:
        fresh = False
    if not fresh:
        raise HTTPException(401, "Invalid timestamp")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 1_000_000:
            raise HTTPException(413, "Incident too large")
        body.extend(chunk)
    secret = os.environ["SIEM_WEBHOOK_SIGNING_SECRET"].encode()
    expected = "sha256=" + hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-SIEM-Signature", "")):
        raise HTTPException(401, "Invalid signature")
    try:
        payload = Incident.model_validate_json(bytes(body))
    except ValidationError:
        raise HTTPException(422, "Invalid incident") from None
    if request.headers.get("Idempotency-Key") != payload.id:
        raise HTTPException(400, "Incident identity mismatch")
    try:
        await record_status(request.app.state.redis, "receipts", payload.id,
                            {"status": "signature_verified", "rule_id": payload.rule_id})
    except RedisError:
        raise HTTPException(503, "Receipt store unavailable") from None
    return Response(status_code=204)
