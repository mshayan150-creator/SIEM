import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis
import httpx
import pytest
from pydantic import ValidationError

from cache import ACK_LUA, DLQ_LUA, INGEST_LUA, STREAMS, Cache, IdempotencyConflict, QueueFull
from database import Database
from engine import Dispatcher, prepare_records
from schemas import Batch, Telemetry


@pytest.fixture
async def cache(settings):
    instance = Cache(settings)
    await instance.redis.aclose()
    instance.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    instance.ingest_script = instance.redis.register_script(INGEST_LUA)
    instance.ack_script = instance.redis.register_script(ACK_LUA)
    instance.dlq_script = instance.redis.register_script(DLQ_LUA)
    await instance.initialize()
    yield instance
    await instance.redis.aclose()


def event(outcome="failure", ip="192.0.2.1", user="alice", action="login"):
    return Telemetry.model_validate({"@timestamp": datetime.now(UTC).isoformat(),
                                    "event": {"dataset": "auth", "outcome": outcome, "action": action},
                                    "source": {"ip": ip}, "user": {"name": user}, "message": "authentication"})


@pytest.mark.asyncio
async def test_brute_threshold_and_dedup(cache):
    events = [event() for _ in range(5)]
    assert await cache.ingest(events, "batch-00000000001") is False
    assert await cache.redis.xlen(STREAMS["alerts"]) == 0
    assert await cache.ingest(events, "batch-00000000001") is True
    await cache.ingest([event()], "batch-00000000002")
    await cache.ingest([event()], "batch-00000000003")
    alerts = await cache.redis.xrange(STREAMS["alerts"])
    assert len(alerts) == 1
    payload = json.loads(alerts[0][1]["payload"])
    assert payload["severity"] == "critical"
    assert payload["evidence_count"] == len(payload["evidence"]) == 6
    assert await cache.redis.xlen(STREAMS["webhooks"]) == 1
    with pytest.raises(IdempotencyConflict):
        await cache.ingest([event(ip="192.0.2.9")], "batch-00000000001")


@pytest.mark.asyncio
async def test_concurrent_threshold_is_single_transition(cache):
    await asyncio.gather(*(cache.ingest([event()], f"parallel-batch-{i:06d}") for i in range(20)))
    assert await cache.redis.xlen(STREAMS["logs"]) == 20
    assert await cache.redis.xlen(STREAMS["alerts"]) == 1


@pytest.mark.asyncio
async def test_expired_failures_rearm(cache, settings):
    batch = [event() for _ in range(6)]
    await cache.ingest(batch, "first-batch-00001")
    _, keys, _ = prepare_records(batch, "x", settings)
    members = await cache.redis.zrange(keys[0], 0, -1)
    await cache.redis.zadd(keys[0], {member: 0 for member in members})
    await cache.ingest(batch, "second-batch-0001")
    assert await cache.redis.xlen(STREAMS["alerts"]) == 2


@pytest.mark.asyncio
async def test_travel_same_ip_different_user_and_expiry(cache, settings):
    await cache.ingest([event("success"), event("success")], "travel-batch-001")
    assert await cache.redis.xlen(STREAMS["alerts"]) == 0
    await cache.ingest([event("success", "192.0.2.2", "bob")], "travel-batch-002")
    assert await cache.redis.xlen(STREAMS["alerts"]) == 0
    await cache.ingest([event("success", "192.0.2.2")], "travel-batch-003")
    alert = json.loads((await cache.redis.xrange(STREAMS["alerts"]))[0][1]["payload"])
    assert {e["source"]["ip"] for e in alert["evidence"]} == {"192.0.2.1", "192.0.2.2"}
    _, keys, hashes = prepare_records([event("success")], "x", settings)
    await cache.redis.zadd(keys[0], {"192.0.2.1": 0, "192.0.2.2": 0})
    await cache.ingest([event("success", "192.0.2.3")], "travel-batch-004")
    assert await cache.redis.xlen(STREAMS["alerts"]) == 1
    assert await cache.redis.hlen(hashes[0]) == 1


@pytest.mark.asyncio
async def test_non_auth_events_not_correlated(cache):
    await cache.ingest([event(action="file_read") for _ in range(10)], "non-auth-batch-01")
    assert await cache.redis.xlen(STREAMS["alerts"]) == 0


@pytest.mark.asyncio
async def test_backpressure_changes_nothing(cache):
    cache.settings.queue_capacity = 1
    with pytest.raises(QueueFull):
        await cache.ingest([event(), event()], "overload-batch-01")
    assert await cache.redis.xlen(STREAMS["logs"]) == 0
    assert not await cache.redis.keys("*failure*")


@pytest.mark.asyncio
async def test_ack_and_reclaim(cache):
    await cache.ingest([event()], "restart-batch-001")
    _, first = await cache.read(STREAMS["logs"], "dead-worker", "0-0")
    assert len(first) == 1
    await cache.redis.xclaim(STREAMS["logs"], "delivery-v1", "dead-worker", 0,
                             [first[0][0]], idle=180000)
    _, recovered = await cache.read(STREAMS["logs"], "replacement-worker", "0-0")
    assert recovered == first
    await cache.ack(STREAMS["logs"], [first[0][0]])
    assert await cache.redis.xlen(STREAMS["logs"]) == 0


@pytest.mark.asyncio
async def test_bulk_partial_failures(settings, cache):
    await cache.ingest([event(), event(), event()], "partial-batch-01")
    _, entries = await cache.read(STREAMS["logs"], "writer", "0-0")
    database = Database(settings)
    errors = [{"index": {"_id": entries[1][1]["id"], "status": 400}},
              {"index": {"_id": entries[2][1]["id"], "status": 429}}]
    try:
        with patch("database.async_bulk", new=AsyncMock(return_value=(1, errors))):
            await database.write(cache, STREAMS["logs"], entries)
        remaining = await cache.redis.xrange(STREAMS["logs"])
        assert [row[0] for row in remaining] == [entries[2][0]]
        assert await cache.redis.xlen(STREAMS["logs"] + ":dlq") == 1
    finally:
        await database.client.close()


@pytest.mark.asyncio
async def test_webhook_retry_and_signature(settings, cache):
    await cache.ingest([event() for _ in range(6)], "webhook-batch-01")
    raw = (await cache.redis.xrange(STREAMS["webhooks"]))[0][1]["payload"]
    received = []

    def handler(request):
        received.append(request)
        return httpx.Response(503 if len(received) == 1 else 204)

    dispatcher = Dispatcher(settings)
    await dispatcher.client.aclose()
    dispatcher.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with patch("engine.asyncio.sleep", new=AsyncMock()):
            await dispatcher.send(raw)
        assert len(received) == 2
        assert received[0].headers["Idempotency-Key"] == received[1].headers["Idempotency-Key"]
        assert received[0].headers["X-SIEM-Signature"].startswith("sha256=")
    finally:
        await dispatcher.client.aclose()


@pytest.mark.parametrize("field,value", [("message", 123), ("@timestamp", "2026-01-01T00:00:00"), ("extra", "bad")])
def test_strict_validation(field, value):
    payload = event().model_dump(mode="json", by_alias=True)
    payload[field] = value
    with pytest.raises(ValidationError):
        Batch.model_validate_json(json.dumps({"events": [payload]}))


def test_mapped_ipv6_normalization():
    assert str(event(ip="::ffff:192.0.2.1").source.ip) == "192.0.2.1"


@pytest.mark.asyncio
async def test_api_auth_validation_and_limit(settings, cache):
    from types import SimpleNamespace

    from auth import IdentityStore
    from main import app
    app.state.identities = IdentityStore(settings.identity_db_path)
    app.state.identities.initialize()
    credential = app.state.identities.create_collector('test-host')
    app.state.settings = settings
    app.state.cache = cache
    app.state.engine = SimpleNamespace(healthy=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.post("/api/v1/telemetry", json={})).status_code == 401
        headers = {"Authorization": "Bearer " + credential["token"], "Idempotency-Key": "api-batch-00000001"}
        doc = event().model_dump(mode="json", by_alias=True)
        doc["host"] = {"name": "test-host"}
        payload = {"events": [doc]}
        assert (await client.post("/api/v1/telemetry", json=payload, headers=headers)).status_code == 202
        assert (await client.post("/api/v1/telemetry", json=payload, headers=headers)).json()["duplicate"]
        assert (await client.post("/api/v1/telemetry", json={"events": []}, headers=headers)).status_code == 422
        settings.max_body_bytes = 5
        assert (await client.post("/api/v1/telemetry", json=payload, headers=headers)).status_code == 413
