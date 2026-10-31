"""Explicit synthetic smoke check: ingestion -> ES + signed local webhook receipt."""
import asyncio
import json
import secrets
import time
from datetime import UTC, datetime

import httpx
from redis.asyncio import Redis

from auth import IdentityStore
from cache import PREFIX
from config import Settings
from database import Database


async def main() -> None:
    settings = Settings()
    identities = IdentityStore(settings.identity_db_path)
    credential = identities.create_collector('pipeline-check')
    identity = 'verify-' + secrets.token_hex(12)
    ip = '2001:db8:' + ':'.join(secrets.token_hex(2) for _ in range(6))
    events = [{
        '@timestamp': datetime.now(UTC).isoformat(),
        'event': {'dataset': 'synthetic.pipeline_check', 'outcome': 'failure' if n < 6 else 'success', 'action': 'login'},
        'host': {'name': 'pipeline-check'},
        'source': {'ip': ip if n < 7 else '192.0.2.2'},
        'user': {'name': identity}, 'message': 'SYNTHETIC pipeline verification, not a real Windows event',
    } for n in range(8)]
    redis = Redis.from_url(settings.redis_url.get_secret_value(), decode_responses=True)
    db = Database(settings)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            result = await client.post('http://127.0.0.1:8000/api/v1/telemetry', json={'events': events},
                                       headers={'Authorization': 'Bearer ' + credential['token'],
                                                'Idempotency-Key': identity})
            result.raise_for_status()
            print('Ingestion:', result.json())
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            alerts = await db.client.search(index='siem-security-alerts', query={'term': {'affected_asset.user.name': identity}}, size=10)
            ids = [item['_source']['id'] for item in alerts['hits']['hits']]
            logs = await db.client.count(index='siem-events-logs-*', query={'term': {'user.name': identity}})
            if len(ids) == 2 and logs['count'] == 8:
                delivered = [await redis.get(PREFIX + 'deliveries:' + i) for i in ids]
                received = [await redis.get(PREFIX + 'receipts:' + i) for i in ids]
                if all(item and json.loads(item)['status'] == 'http_2xx' for item in delivered):
                    print('PASS: 8 logs and 2 alerts indexed; both webhooks acknowledged with HTTP 2xx.')
                    if all(received):
                        print('PASS: local receiver independently verified both signatures.')
                    elif settings.webhook_url.get_secret_value() == 'http://webhook:8080/incidents':
                        raise SystemExit('FAIL: local receiver receipts are missing.')
                    else:
                        print('External receiver: local signature receipts are not available; inspect that receiver.')
                    return
            await asyncio.sleep(2)
        raise SystemExit('FAIL: pipeline did not complete within 90 seconds. Inspect dashboard queues and Compose logs.')
    finally:
        identities.revoke_collector(credential['collector_id'])
        await redis.aclose()
        await db.client.close()


if __name__ == '__main__':
    asyncio.run(main())
