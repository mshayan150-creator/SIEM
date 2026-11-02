"""Browser-test fixture only; never deploy this module. Uses real auth/routes and test data."""
import asyncio
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import fakeredis.aioredis
from fastapi import Request
from fastapi.responses import JSONResponse

from auth import IdentityStore
from cache import ACK_LUA, DLQ_LUA, INGEST_LUA, Cache
from config import Settings
from main import app
from monitoring import record_status

failure_mode = False


@app.post('/qa/failure/{enabled}')
async def set_failure(enabled: bool) -> dict[str, bool]:
    global failure_mode
    failure_mode = enabled
    return {'failure': failure_mode}


@app.middleware('http')
async def simulate_failure(request: Request, call_next: Any) -> Any:
    if failure_mode and request.url.path.endswith('/snapshot'):
        return JSONResponse({'detail': 'Test dependency unavailable'}, status_code=503)
    return await call_next(request)


@asynccontextmanager
async def fixture_lifespan(application: Any) -> Any:
    with tempfile.TemporaryDirectory() as directory:
        settings = Settings(_env_file=None, redis_url='redis://localhost:6379',
                            elasticsearch_url='http://localhost:9200', elasticsearch_api_key='test',
                            webhook_url='http://localhost/hook', webhook_signing_secret='a'*32,
                            allow_insecure_local=True, identity_db_path=directory+'/identities.db')
        identities = IdentityStore(settings.identity_db_path)
        identities.initialize()
        identities.create_user('admin', 'Browser Test Password 2026!', 'admin')
        cache = Cache(settings)
        await cache.redis.aclose()
        cache.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        cache.ingest_script = cache.redis.register_script(INGEST_LUA)
        cache.ack_script = cache.redis.register_script(ACK_LUA)
        cache.dlq_script = cache.redis.register_script(DLQ_LUA)
        await cache.initialize()
        now = datetime.now(UTC).isoformat()
        events = [{
            '@timestamp': now,
            'event': {'dataset': 'windows.security', 'action': 'logon', 'outcome': outcome, 'id': f'record-{i}'},
            'host': {'name': 'OFFICE-PC'}, 'source': {'ip': f'192.0.2.{i+1}'},
            'user': {'name': 'EXAMPLE\\analyst'},
            'message': '<img src=x onerror="window.injected=true">' if i == 0 else 'Windows authentication event',
        } for i, outcome in enumerate(('failure', 'success', 'unknown'))]
        incidents = [{
            'id': 'example-alert', '@timestamp': now, 'severity': 'critical', 'rule_id': 'brute-force',
            'title': 'Repeated authentication failures',
            'description': 'Six failures in 60 seconds. Investigate this source.', 'evidence': events,
            'evidence_count': 6, 'affected_asset': {'source.ip': '192.0.2.1', 'user.name': 'EXAMPLE\\analyst'},
        }]

        async def search(index: str, **kwargs: Any) -> dict[str, Any]:
            if index == 'siem-security-alerts':
                return {'hits': {'total': {'value': 1}, 'hits': [{'_source': item} for item in incidents]}}
            query = kwargs.get('query', {}).get('bool', {}).get('must', [{}])[0].get('multi_match', {}).get('query', '')
            matching = [item for item in events if query.lower() in str(item).lower()]
            return {
                'hits': {'total': {'value': len(matching)}, 'hits': [{'_source': item} for item in matching]},
                'aggregations': {'failures': {'doc_count': sum(item['event']['outcome'] == 'failure' for item in matching)},
                                 'timeline': {'buckets': [{'key': int(datetime.now(UTC).timestamp()*1000)-(23-i)*3600000,
                                                          'doc_count': i % 7 * 3 if matching else 0} for i in range(24)]}},
            }

        application.state.settings = settings
        application.state.cache = cache
        application.state.identities = identities
        application.state.password_slots = asyncio.Semaphore(2)
        application.state.database = SimpleNamespace(client=SimpleNamespace(search=search))
        application.state.engine = SimpleNamespace(healthy=True)
        await record_status(cache.redis, 'collectors', 'example-collector',
                            {'host': 'OFFICE-PC', 'sent': 186, 'status': 'Watching Windows Event Logs'})
        await record_status(cache.redis, 'deliveries', 'example-alert', {'status': 'http_2xx'})
        await record_status(cache.redis, 'receipts', 'example-alert', {'status': 'signature_verified'})
        try:
            yield
        finally:
            await cache.redis.aclose()


app.router.lifespan_context = fixture_lifespan
