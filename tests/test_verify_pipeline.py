"""The smoke check must tolerate fresh shards, but never hide a broken pipeline."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from elastic_transport import ApiResponseMeta, HttpHeaders, NodeConfig
from elasticsearch import ApiError

from ops import verify_pipeline


def es_error(status):
    return ApiError('test error', ApiResponseMeta(
        status, '1.1', HttpHeaders(), 0, NodeConfig('http', 'localhost', 9200)
    ), {})


@pytest.fixture
def pipeline(monkeypatch, settings):
    monkeypatch.setattr(verify_pipeline, 'Settings', lambda: settings)
    identities = Mock()
    identities.create_collector.return_value = {'token': 'test', 'collector_id': 'test'}
    monkeypatch.setattr(verify_pipeline, 'IdentityStore', lambda _: identities)
    redis = AsyncMock()
    redis.get.return_value = '{"status": "http_2xx"}'
    monkeypatch.setattr(verify_pipeline.Redis, 'from_url', lambda *a, **k: redis)
    db = Mock(client=AsyncMock())
    db.client.search.return_value = {'hits': {'hits': [
        {'_source': {'id': 'first'}}, {'_source': {'id': 'second'}}
    ]}}
    db.client.count.return_value = {'count': 8}
    monkeypatch.setattr(verify_pipeline, 'Database', lambda _: db)
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post.return_value = Mock()
    monkeypatch.setattr(verify_pipeline.httpx, 'AsyncClient', lambda **kw: client)
    monkeypatch.setattr(verify_pipeline.asyncio, 'sleep', AsyncMock())
    return db, identities, redis


@pytest.mark.parametrize('status', [404, 503])
async def test_fresh_shard_retries_then_verifies_delivery(pipeline, status, capsys):
    db, identities, redis = pipeline
    db.client.count.side_effect = [es_error(status), {'count': 8}]
    await verify_pipeline.main()
    assert db.client.count.await_count == 2
    assert redis.get.await_count == 4
    assert 'both webhooks acknowledged' in capsys.readouterr().out
    identities.revoke_collector.assert_called_once_with('test')
    db.client.close.assert_awaited_once()


async def test_auth_error_is_not_retried(pipeline):
    db, identities, _ = pipeline
    db.client.search.side_effect = es_error(401)
    with pytest.raises(ApiError):
        await verify_pipeline.main()
    assert db.client.search.await_count == 1
    identities.revoke_collector.assert_called_once()
    db.client.close.assert_awaited_once()


async def test_unavailable_shards_still_time_out(pipeline, monkeypatch):
    db, identities, _ = pipeline
    db.client.search.side_effect = es_error(503)
    clock = iter([0, 1, 91])
    monkeypatch.setattr(verify_pipeline, 'time', SimpleNamespace(monotonic=lambda: next(clock)))
    with pytest.raises(SystemExit, match='pipeline did not complete'):
        await verify_pipeline.main()
    identities.revoke_collector.assert_called_once()
    db.client.close.assert_awaited_once()
