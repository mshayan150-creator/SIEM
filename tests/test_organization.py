import asyncio
import json
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from pydantic import ValidationError

from auth import IdentityStore
from cache import STREAMS
from config import Settings
from main import app
from tests.test_dashboard import context as organization_context

context = organization_context
from tests.test_engine import event

PASSWORD = 'Correct Horse Battery Staple!'
ORIGIN = {'Origin': 'http://test'}


def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test')


async def login(c, username='admin', password=PASSWORD):
    r = await c.post('/api/v1/dashboard/login', json={'username': username, 'password': password}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    return r


async def test_independent_accounts_permissions_and_invalidation(context):
    async with client() as owner, client() as viewer:
        await login(owner)
        create = await owner.post('/api/v1/dashboard/admin/users', json={
            'username': 'analyst', 'password': PASSWORD, 'role': 'viewer'}, headers=ORIGIN)
        assert create.status_code == 201
        await login(viewer, 'analyst')
        assert (await viewer.get('/api/v1/dashboard/snapshot')).json()['user']['username'] == 'analyst'
        assert (await viewer.get('/api/v1/dashboard/admin')).status_code == 403
        assert (await viewer.post('/api/v1/dashboard/admin/users', json={
            'username': 'hacker', 'password': PASSWORD, 'role': 'admin'}, headers=ORIGIN)).status_code == 403
        assert (await viewer.post('/api/v1/dashboard/admin/collectors', json={'host': 'PC'}, headers=ORIGIN)).status_code == 403
        assert (await owner.patch('/api/v1/dashboard/admin/users/analyst', json={'enabled': False}, headers=ORIGIN)).status_code == 200
        assert (await viewer.get('/api/v1/dashboard/snapshot')).status_code == 401
        assert (await owner.get('/api/v1/dashboard/snapshot')).status_code == 200
        assert (await owner.patch('/api/v1/dashboard/admin/users/admin', json={'enabled': False}, headers=ORIGIN)).status_code == 400


async def test_password_change_revokes_all_sessions(context):
    async with client() as first, client() as second:
        await login(first)
        await login(second)
        result = await first.post('/api/v1/dashboard/password', json={
            'current_password': PASSWORD, 'new_password': 'Another unique password 2026!'}, headers=ORIGIN)
        assert result.status_code == 200
        assert (await first.get('/api/v1/dashboard/snapshot')).status_code == 401
        assert (await second.get('/api/v1/dashboard/snapshot')).status_code == 401
        assert (await first.post('/api/v1/dashboard/login', json={'username': 'admin', 'password': PASSWORD}, headers=ORIGIN)).status_code == 401
        await login(first, password='Another unique password 2026!')


async def test_multiple_computers_scoped_retries_revocation_and_host_binding(context):
    async with client() as owner, client() as machine:
        await login(owner)
        a = (await owner.post('/api/v1/dashboard/admin/collectors', json={'host': 'PC-A'}, headers=ORIGIN)).json()
        b = (await owner.post('/api/v1/dashboard/admin/collectors', json={'host': 'PC-B'}, headers=ORIGIN)).json()
        assert a['token'] != b['token']
        inventory = (await owner.get('/api/v1/dashboard/admin')).json()
        assert a['token'] not in json.dumps(inventory)
        doc = event(action='local_logon').model_dump(mode='json', by_alias=True)
        for credential in (a, b):
            doc['host'] = {'name': credential['host']}
            headers = {'Authorization': 'Bearer '+credential['token'], 'Idempotency-Key': 'same-key-two-computers'}
            result = await machine.post('/api/v1/telemetry', json={'events': [doc]}, headers=headers)
            assert result.status_code == 202, result.text
            assert result.json()['duplicate'] is False
            assert (await machine.post('/api/v1/telemetry', json={'events': [doc]}, headers=headers)).json()['duplicate'] is True
        assert await context.redis.xlen(STREAMS['logs']) == 2
        # A cannot spoof B, even with a fresh key.
        a_headers = {'Authorization': 'Bearer '+a['token'], 'Idempotency-Key': 'another-batch-key-123'}
        assert (await machine.post('/api/v1/telemetry', json={'events': [doc]}, headers=a_headers)).status_code == 403
        heartbeat = {'collector_id': b['collector_id'], 'host': b['host'], 'channels': ['System'],
                     'status': 'Watching', 'sent': 1, 'local_auth': 0}
        assert (await machine.post('/api/v1/collectors/heartbeat', json=heartbeat, headers=a_headers)).status_code == 403
        assert (await owner.delete('/api/v1/dashboard/admin/collectors/'+a['collector_id'], headers=ORIGIN)).status_code == 200
        doc['host']['name'] = 'PC-A'
        assert (await machine.post('/api/v1/telemetry', json={'events': [doc]}, headers=a_headers)).status_code == 401
        b_headers = {'Authorization': 'Bearer '+b['token'], 'Idempotency-Key': 'still-active-batch-123'}
        doc['host']['name'] = 'PC-B'
        assert (await machine.post('/api/v1/telemetry', json={'events': [doc]}, headers=b_headers)).status_code == 202


async def test_no_shared_key_or_public_signup_backdoor(context, settings):
    async with client() as c:
        assert (await c.post('/api/v1/dashboard/login', json={'key': 'a'*32}, headers=ORIGIN)).status_code == 400
        assert (await c.post('/api/v1/dashboard/admin/users', json={'username': 'bad', 'password': PASSWORD}, headers=ORIGIN)).status_code == 401
        assert (await c.post('/api/v1/telemetry', json={}, headers={'Authorization': 'Bearer '+settings.ingest_api_key.get_secret_value()})).status_code == 401


async def test_shared_https_origin_cookies_and_csrf(context, settings):
    settings.public_origin = 'https://siem.example.org'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=settings.public_origin) as c:
        # Same-origin check works behind TLS termination without trusting spoofed proxy headers.
        data = {'username': 'admin', 'password': PASSWORD}
        assert (await c.post('/api/v1/dashboard/login', json=data, headers=ORIGIN)).status_code == 403
        headers = {'Origin': settings.public_origin}
        response = await c.post('/api/v1/dashboard/login', json=data, headers=headers)
        assert response.status_code == 200
        assert 'Secure' in response.headers['set-cookie']
        assert (await c.get('/api/v1/dashboard/snapshot')).status_code == 200
        assert (await c.post('/api/v1/dashboard/admin/collectors', json={'host': 'REMOTE-PC'}, headers={'Origin': 'https://evil.example'})).status_code == 403
        created = await c.post('/api/v1/dashboard/admin/collectors', json={'host': 'REMOTE-PC'}, headers=headers)
        assert created.json()['api_url'] == settings.public_origin


def test_identity_persistence_and_no_plaintext_passwords(tmp_path):
    path = str(tmp_path/'identities.db')
    first = IdentityStore(path)
    first.initialize()
    first.create_user('admin', PASSWORD, 'admin')
    credential = first.create_collector('PC')
    second = IdentityStore(path)
    assert second.authenticate('admin', PASSWORD)['role'] == 'admin'
    assert second.collector(credential['token'])['host'] == 'PC'
    with second.connection() as db:
        assert db.execute('SELECT password FROM users').fetchone()[0] != PASSWORD
        assert db.execute('SELECT token_hash FROM collectors').fetchone()[0] != credential['token']
    second.revoke_collector(credential['collector_id'])
    assert first.collector(credential['token']) is None


def test_concurrent_disable_preserves_one_admin(tmp_path):
    store = IdentityStore(str(tmp_path/'identities.db'))
    store.initialize()
    store.create_user('alice', PASSWORD, 'admin')
    store.create_user('bob', PASSWORD, 'admin')
    def disable(name):
        try:
            store.update_user(name, enabled=False)
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(disable, ['alice', 'bob']))
    assert sum(results) == 1
    assert sum(user['enabled'] for user in store.inventory()['users']) == 1


@pytest.mark.parametrize('origin', ['http://example.org', 'https://example.org/', 'https://a:b@example.org', 'https://example.org/path'])
def test_bad_public_origins_rejected(settings, origin):
    values = settings.model_dump()
    values['public_origin'] = origin
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


async def test_two_simultaneous_collector_requests(context):
    credentials = [app.state.identities.create_collector(name) for name in ('DESKTOP', 'LAPTOP')]
    async with client() as c:
        async def send(credential):
            doc = event(action='local_logon').model_dump(mode='json', by_alias=True)
            doc['host'] = {'name': credential['host']}
            return await c.post('/api/v1/telemetry', json={'events': [doc]}, headers={
                'Authorization': 'Bearer '+credential['token'], 'Idempotency-Key': 'parallel-organization-batch'})
        replies = await asyncio.gather(*(send(credential) for credential in credentials))
        assert all(r.status_code == 202 for r in replies)
        assert await context.redis.xlen(STREAMS['logs']) == 2
