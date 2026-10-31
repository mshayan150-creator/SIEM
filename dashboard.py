"""Same-origin, session-authenticated read-only dashboard and shipper heartbeat."""
import asyncio
import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import Field, ValidationError

from auth import COOKIE, admin, collector_auth, rate_limit, same_origin, session, small_body
from cache import PREFIX, STREAMS
from monitoring import recent_status, record_status
from schemas import StrictModel

router = APIRouter()
STATIC = Path(__file__).parent / "static"
@router.get("/", include_in_schema=False)
async def page() -> FileResponse:
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})


@router.get("/assets/{name}", include_in_schema=False)
async def asset(name: str) -> FileResponse:
    if name not in {"app.js", "style.css"}:
        raise HTTPException(404)
    return FileResponse(STATIC / name)


class Login(StrictModel):
    username: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{2,63}$")]
    password: Annotated[str, Field(min_length=1, max_length=128)]


@router.post("/api/v1/dashboard/login")
async def login(request: Request) -> JSONResponse:
    same_origin(request)
    redis = request.app.state.cache.redis
    ip = request.client.host if request.client else "unknown"
    await rate_limit(request, "login-ip", ip, 30)
    try:
        data = Login.model_validate_json(await small_body(request, 2048))
    except ValidationError:
        raise HTTPException(400, "Enter a username and password") from None
    await rate_limit(request, "login-user", data.username, 10)
    async with request.app.state.password_slots:
        user = await asyncio.to_thread(request.app.state.identities.authenticate, data.username, data.password)
    if user is None:
        raise HTTPException(401, "Incorrect username or password")
    # Issue a fresh session; do not reuse a caller-supplied token.
    token = secrets.token_urlsafe(32)
    old = request.cookies.get(COOKIE, "")
    if old:
        await redis.delete(PREFIX + "session:" + hashlib.sha256(old.encode()).hexdigest())
    await redis.set(PREFIX + "session:" + hashlib.sha256(token.encode()).hexdigest(),
                    json.dumps({"username": user["username"], "version": user["version"]}), ex=28800)
    response = JSONResponse({"authenticated": True, "username": user["username"], "role": user["role"]})
    response.set_cookie(COOKIE, token, max_age=28800, httponly=True, samesite="strict",
                        secure=bool(request.app.state.settings.public_origin) or not request.app.state.settings.allow_insecure_local,
                        path="/")
    return response


@router.post("/api/v1/dashboard/logout")
async def logout(request: Request) -> Response:
    same_origin(request)
    token = request.cookies.get(COOKIE, "")
    if token:
        await request.app.state.cache.redis.delete(PREFIX + "session:" + hashlib.sha256(token.encode()).hexdigest())
    response = Response(status_code=204)
    response.delete_cookie(COOKIE, path="/")
    return response


@router.get("/api/v1/dashboard/snapshot", dependencies=[Depends(session)])
async def snapshot(request: Request, q: Annotated[str, Query(max_length=128)] = "") -> dict[str, Any]:
    user = await session(request)
    redis = request.app.state.cache.redis
    db = request.app.state.database.client
    errors: list[str] = []
    query: dict[str, Any] = {"range": {"@timestamp": {"gte": "now-24h"}}}
    if q:
        query = {"bool": {"filter": [query], "must": [{"multi_match": {
            "query": q, "fields": ["message", "user.name", "event.dataset", "host.name", "event.action"],
            "lenient": True,
        }}]}}

    async def search(index: str, **kwargs: Any) -> dict[str, Any]:
        try:
            result = await db.search(index=index, ignore_unavailable=True, allow_no_indices=True,
                                     request_timeout=5, **kwargs)
            if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
                errors.append("Elasticsearch returned incomplete results")
            return dict(result)
        except (ApiError, TransportError, TimeoutError):
            errors.append("Elasticsearch unavailable or read permission missing")
            return {}

    event_result, alert_result = await asyncio.gather(
        search("siem-events-logs-*", query=query, size=100, track_total_hits=True,
               sort=[{"@timestamp": "desc"}], aggs={
                   "timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h",
                       "min_doc_count": 0, "extended_bounds": {"min": "now-23h/h", "max": "now/h"}}},
                   "failures": {"filter": {"term": {"event.outcome": "failure"}}},
                   "hosts": {"cardinality": {"field": "host.name"}},
               }),
        search("siem-security-alerts", query={"range": {"@timestamp": {"gte": "now-24h"}}},
               size=50, track_total_hits=True, sort=[{"@timestamp": "desc"}]),
    )
    queues: dict[str, Any] = {}
    for name, stream in STREAMS.items():
        queues[name] = {"queued": await redis.xlen(stream), "dead_letters": await redis.xlen(stream + ":dlq")}
    collectors, deliveries, receipts = await asyncio.gather(
        recent_status(redis, "collectors"), recent_status(redis, "deliveries"), recent_status(redis, "receipts"))
    now = datetime.now(UTC)
    for collector in collectors:
        collector["online"] = (now - datetime.fromisoformat(collector["timestamp"])).total_seconds() < 90
    return {
        "user": {"username": user["username"], "role": user["role"]},
        "updated_at": now.isoformat(), "window": "Last 24 hours · event time", "errors": errors,
        "worker_healthy": request.app.state.engine.healthy, "queues": queues,
        "events_total": event_result.get("hits", {}).get("total", {}).get("value", 0) if event_result else None,
        "alerts_total": alert_result.get("hits", {}).get("total", {}).get("value", 0) if alert_result else None,
        "failures": event_result.get("aggregations", {}).get("failures", {}).get("doc_count", 0) if event_result else None,
        "timeline": event_result.get("aggregations", {}).get("timeline", {}).get("buckets", []),
        "events": [hit["_source"] for hit in event_result.get("hits", {}).get("hits", [])],
        "alerts": [hit["_source"] for hit in alert_result.get("hits", {}).get("hits", [])],
        "collectors": collectors, "deliveries": deliveries, "receipts": receipts,
    }


class Heartbeat(StrictModel):
    collector_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{8,64}$")]
    host: Annotated[str, Field(min_length=1, max_length=256)]
    channels: Annotated[list[str], Field(max_length=3)]
    status: Annotated[str, Field(max_length=512)]
    sent: Annotated[int, Field(ge=0)]
    local_auth: Annotated[int, Field(ge=0)]


@router.post("/api/v1/collectors/heartbeat")
async def heartbeat(request: Request) -> dict[str, bool]:
    collector = await collector_auth(request)
    try:
        data = Heartbeat.model_validate_json(await small_body(request))
    except (ValidationError, TimeoutError):
        raise HTTPException(422, "Invalid heartbeat") from None
    if data.collector_id != collector["id"] or data.host.casefold() != collector["host"].casefold():
        raise HTTPException(403, "Heartbeat identity does not match collector registration")
    await record_status(request.app.state.cache.redis, "collectors", data.collector_id,
                        data.model_dump(exclude={"collector_id"}))
    return {"accepted": True}


class CreateUser(Login):
    role: Annotated[str, Field(pattern=r"^(admin|viewer)$")] = "viewer"


class UpdateUser(StrictModel):
    enabled: bool | None = None
    password: Annotated[str, Field(min_length=15, max_length=128)] | None = None


class CreateCollector(StrictModel):
    host: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")]


@router.get("/api/v1/dashboard/admin")
async def inventory(request: Request) -> dict[str, Any]:
    await admin(request)
    return await asyncio.to_thread(request.app.state.identities.inventory)  # type: ignore[no-any-return]


@router.post("/api/v1/dashboard/admin/users", status_code=201)
async def create_user(request: Request) -> dict[str, bool]:
    actor = await admin(request)
    await rate_limit(request, "admin", actor["username"], 20)
    try:
        data = CreateUser.model_validate_json(await small_body(request, 2048))
        async with request.app.state.password_slots:
            await asyncio.to_thread(request.app.state.identities.create_user,
                                    data.username, data.password, data.role, actor["username"])
    except ValidationError:
        raise HTTPException(422, "Invalid user fields") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return {"created": True}


@router.patch("/api/v1/dashboard/admin/users/{username}")
async def update_user(request: Request, username: str) -> dict[str, bool]:
    actor = await admin(request)
    await rate_limit(request, "admin", actor["username"], 20)
    try:
        data = UpdateUser.model_validate_json(await small_body(request, 2048))
        if data.enabled is None and data.password is None:
            raise ValueError("Provide enabled or password")
        async with request.app.state.password_slots:
            await asyncio.to_thread(request.app.state.identities.update_user,
                                    username, data.enabled, data.password, actor["username"])
    except ValidationError:
        raise HTTPException(422, "Invalid user update") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return {"updated": True}


@router.post("/api/v1/dashboard/admin/collectors", status_code=201)
async def create_collector(request: Request) -> dict[str, str]:
    actor = await admin(request)
    await rate_limit(request, "admin", actor["username"], 20)
    try:
        data = CreateCollector.model_validate_json(await small_body(request, 1024))
        result: dict[str, str] = await asyncio.to_thread(request.app.state.identities.create_collector,
                                                        data.host, actor["username"])
    except ValidationError:
        raise HTTPException(422, "Invalid hostname") from None
    result["api_url"] = request.app.state.settings.public_origin or str(request.base_url).rstrip("/")
    return result


@router.delete("/api/v1/dashboard/admin/collectors/{identity}")
async def revoke_collector(request: Request, identity: str) -> dict[str, bool]:
    actor = await admin(request)
    try:
        await asyncio.to_thread(request.app.state.identities.revoke_collector, identity, actor["username"])
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    return {"revoked": True}


class ChangePassword(StrictModel):
    current_password: Annotated[str, Field(min_length=1, max_length=128)]
    new_password: Annotated[str, Field(min_length=15, max_length=128)]


@router.post("/api/v1/dashboard/password")
async def change_password(request: Request) -> dict[str, bool]:
    same_origin(request)
    user = await session(request)
    await rate_limit(request, "password", user["username"], 5)
    try:
        data = ChangePassword.model_validate_json(await small_body(request, 2048))
        async with request.app.state.password_slots:
            verified = await asyncio.to_thread(request.app.state.identities.authenticate,
                                               user["username"], data.current_password)
            if not verified:
                raise HTTPException(401, "Current password is incorrect")
            await asyncio.to_thread(request.app.state.identities.update_user,
                                    user["username"], None, data.new_password, user["username"])
    except ValidationError:
        raise HTTPException(422, "Invalid password fields") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return {"changed": True, "sign_in_again": True}
