import asyncio
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import fakeredis.aioredis
import httpx
import pytest
from pydantic import SecretStr

from auth import IdentityStore
from cache import ACK_LUA, DLQ_LUA, INGEST_LUA, STREAMS, Cache
from engine import Dispatcher, Engine
from main import app
from monitoring import recent_status
from tests.test_engine import event


@pytest.fixture
async def context(settings):
    app.state.identities = IdentityStore(settings.identity_db_path)
    app.state.identities.initialize()
    app.state.identities.create_user('admin', 'Correct Horse Battery Staple!', 'admin')
    app.state.password_slots = asyncio.Semaphore(2)
    cache = Cache(settings)
    await cache.redis.aclose()
    cache.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cache.ingest_script = cache.redis.register_script(INGEST_LUA)
    cache.ack_script = cache.redis.register_script(ACK_LUA)
    cache.dlq_script = cache.redis.register_script(DLQ_LUA)
    await cache.initialize()
    app.state.settings = settings
    app.state.cache = cache
    app.state.engine = SimpleNamespace(healthy=True)
    app.state.database = SimpleNamespace(client=SimpleNamespace(search=AsyncMock(return_value={
        'hits': {'total': {'value': 0}, 'hits': []}, 'aggregations': {},
    })))
    yield cache
    await cache.redis.aclose()


async def test_dashboard_auth_origin_logout(context, settings):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        assert (await client.get('/api/v1/dashboard/snapshot')).status_code == 401
        key = {'username': 'admin', 'password': 'Correct Horse Battery Staple!'}
        assert (await client.post('/api/v1/dashboard/login', json=key)).status_code == 403
        headers = {'Origin': 'http://test'}
        assert (await client.post('/api/v1/dashboard/login', json={'username': 'admin', 'password': 'bad'}, headers=headers)).status_code == 401
        response = await client.post('/api/v1/dashboard/login', json=key, headers=headers)
        assert response.status_code == 200
        assert 'HttpOnly' in response.headers['set-cookie']
        assert 'SameSite=strict' in response.headers['set-cookie']
        result = await client.get('/api/v1/dashboard/snapshot')
        assert result.status_code == 200 and result.json()['events_total'] == 0
        assert result.headers['cache-control'] == 'no-store'
        assert (await client.post('/api/v1/dashboard/logout', headers=headers)).status_code == 204
        assert (await client.get('/api/v1/dashboard/snapshot')).status_code == 401


async def test_dashboard_rate_limit(context):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        for _ in range(10):
            assert (await client.post('/api/v1/dashboard/login', json={'username': 'admin', 'password': 'bad'}, headers={'Origin': 'http://test'})).status_code == 401
        assert (await client.post('/api/v1/dashboard/login', json={'username': 'admin', 'password': 'bad'}, headers={'Origin': 'http://test'})).status_code == 429


async def test_heartbeat_auth_and_snapshot(context):
    credential = app.state.identities.create_collector('WINDOWS-PC')
    payload = {'collector_id': credential['collector_id'], 'host': 'WINDOWS-PC', 'channels': ['Security'], 'status': 'Watching', 'sent': 8, 'local_auth': 0}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        assert (await client.post('/api/v1/collectors/heartbeat', json=payload)).status_code == 401
        assert (await client.post('/api/v1/collectors/heartbeat', json=payload, headers={'Authorization': 'Bearer ' + credential['token']})).status_code == 200
    records = await recent_status(context.redis, 'collectors')
    assert records[0]['host'] == 'WINDOWS-PC'


async def test_local_and_unknown_events_do_not_trigger(context):
    await context.ingest([event(action='local_logon') for _ in range(8)], 'local-logon-batch-01')
    await context.ingest([event(outcome='unknown') for _ in range(8)], 'unknown-logon-batch-01')
    assert await context.redis.xlen(STREAMS['logs']) == 16
    assert await context.redis.xlen(STREAMS['alerts']) == 0


async def test_signed_webhook_end_to_end(context, settings, monkeypatch):
    from dev_webhook import app as receiver
    monkeypatch.setenv('SIEM_WEBHOOK_SIGNING_SECRET', settings.webhook_signing_secret.get_secret_value())
    receiver.state.redis = context.redis
    await context.ingest([event() for _ in range(6)], 'verified-webhook-batch')
    raw = (await context.redis.xrange(STREAMS['webhooks']))[0][1]['payload']
    incident_id = json.loads(raw)['id']
    dispatcher = Dispatcher(settings)
    await dispatcher.client.aclose()
    dispatcher.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=receiver))
    settings.webhook_url = SecretStr('http://receiver/incidents')
    try:
        await dispatcher.send(raw)
        receipts = await recent_status(context.redis, 'receipts')
        assert receipts[0]['id'] == incident_id
        assert receipts[0]['status'] == 'signature_verified'
        headers = {'X-SIEM-Timestamp': str(int(time.time())), 'X-SIEM-Signature': 'sha256=bad'}
        assert (await dispatcher.client.post('http://receiver/incidents', content=raw, headers=headers)).status_code == 401
        timestamp = str(int(time.time()) - 600)
        headers['X-SIEM-Timestamp'] = timestamp
        headers['X-SIEM-Signature'] = 'sha256=' + hmac.new(settings.webhook_signing_secret.get_secret_value().encode(), timestamp.encode()+b'.'+raw.encode(), hashlib.sha256).hexdigest()
        assert (await dispatcher.client.post('http://receiver/incidents', content=raw, headers=headers)).status_code == 401
    finally:
        await dispatcher.client.aclose()


async def test_worker_records_delivery_before_ack(context, settings):
    await context.ingest([event() for _ in range(6)], 'worker-webhook-batch')
    engine = Engine(settings, context, SimpleNamespace())
    engine.dispatcher.send = AsyncMock()
    original_ack = context.ack
    async def ack(stream, ids):
        assert len(await recent_status(context.redis, 'deliveries')) == 1
        await original_ack(stream, ids)
        engine.stop.set()
    context.ack = ack
    try:
        await engine.worker('webhooks', STREAMS['webhooks'])
        assert await context.redis.xlen(STREAMS['webhooks']) == 0
    finally:
        await engine.close()


def test_upgrade_preserves_existing_secrets(tmp_path, monkeypatch):
    from ops import upgrade_local
    monkeypatch.setattr(upgrade_local, '__file__', str(tmp_path / 'ops' / 'upgrade_local.py'))
    path = tmp_path / '.env.local'
    original = 'SIEM_INGEST_API_KEY=existing\nSIEM_WEBHOOK_SIGNING_SECRET=unchanged\n'
    path.write_text(original)
    upgrade_local.main()
    upgraded = path.read_text()
    assert upgraded.startswith(original)
    assert upgraded == original
    upgrade_local.main()
    assert path.read_text() == upgraded
