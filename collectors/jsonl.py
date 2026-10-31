"""Portable Python 3.10+ shipper for append-only, normalized ECS JSONL files.

Use --from-start only for an intentional historical import. Default starts at EOF.
Rotation/truncation and invalid records stop collection instead of silently skipping.
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def validate_config(config: dict[str, Any]) -> None:
    url = urllib.parse.urlsplit(config['api_url'])
    if url.username or url.password or url.query or url.fragment or url.path not in {'', '/'}:
        raise ValueError('Use an origin without credentials or a path')
    if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in {'127.0.0.1', 'localhost', '::1'}):
        raise ValueError('HTTPS required except on loopback; certificate verification is always enabled')
    if not all(isinstance(config.get(k), str) and config[k] for k in ('collector_id', 'token', 'host')):
        raise ValueError('Invalid enrollment configuration')


def save(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)


def post(config: dict[str, Any], endpoint: str, raw: bytes, identity: str | None = None) -> None:
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + config['token']}
    if identity:
        headers['Idempotency-Key'] = identity
    request = urllib.request.Request(config['api_url'].rstrip('/') + endpoint, data=raw, headers=headers)
    # Ignore ambient proxy settings so a local deployment's secret isn't sent via a configured proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError('Server did not acknowledge the batch')


def step(config: dict[str, Any], source: Path, state_path: Path, state: dict[str, Any]) -> int:
    stat = source.stat()
    if [stat.st_dev, stat.st_ino] != state['file_id'] or stat.st_size < state['offset']:
        raise ValueError('File rotated or truncated. Preserve state and pending data; explicitly configure the new file.')
    if not state.get('pending'):
        events: list[dict[str, Any]] = []
        size = 0
        with source.open('rb') as stream:
            stream.seek(state['offset'])
            end = state['offset']
            for _ in range(100):
                line = stream.readline(100_001)
                if not line:
                    break
                if len(line) > 100_000:
                    raise ValueError('JSONL record exceeds 100KB')
                if not line.endswith(b'\n'):
                    break  # Writer has not committed this line yet.
                doc = json.loads(line)
                if not isinstance(doc, dict):
                    raise TypeError('Each line must be one ECS event object')
                doc['host'] = {'name': config['host']}
                encoded = json.dumps(doc).encode()
                if size + len(encoded) > 1_500_000:
                    break
                size += len(encoded)
                events.append(doc)
                end = stream.tell()
        if not events:
            return 0
        state['pending'] = {'key': str(uuid.uuid4()), 'created': time.time(), 'end': end,
                            'count': len(events), 'body': json.dumps({'events': events})}
        save(state_path, state)
    pending = state['pending']
    if time.time() - pending['created'] > 23 * 3600:
        raise ValueError('Pending batch exceeds safe retry age; investigate before replaying')
    post(config, '/api/v1/telemetry', pending['body'].encode(), pending['key'])
    state['offset'] = pending['end']
    count = pending['count']
    state['sent'] += count
    state['pending'] = None
    save(state_path, state)
    return int(count)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--file', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--from-start', action='store_true')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding='utf-8-sig'))
    validate_config(config)
    source = args.file.resolve()
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # OS-managed lock releases on crashes. A second process cannot share a checkpoint.
    with args.state.with_suffix('.lock').open('a+b') as lock:
        lock.seek(0)
        lock.write(b'0')
        lock.flush()
        lock.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        scope = hashlib.sha256((config['api_url'] + config['collector_id'] + str(source)).encode()).hexdigest()
        if args.state.exists():
            state = json.loads(args.state.read_text())
            if state.get('scope') != scope:
                raise ValueError('State belongs to another server, collector or file')
        else:
            stat = source.stat()
            if stat.st_size and not args.from_start:
                with source.open('rb') as stream:
                    stream.seek(stat.st_size - 1)
                    if stream.read(1) != b'\n':
                        raise ValueError('Initial file must end with a complete newline; retry after the writer finishes')
            state = {'scope': scope, 'file_id': [stat.st_dev, stat.st_ino], 'offset': 0 if args.from_start else stat.st_size,
                     'pending': None, 'sent': 0}
            save(args.state, state)
        while True:
            status = 'Watching normalized JSONL'
            try:
                count = step(config, source, args.state, state)
                if count:
                    print(f'Accepted {count} events; total {state["sent"]}', flush=True)
            except (urllib.error.URLError, TimeoutError):
                status = 'Delivery paused; pending batch retained'
                print(status, file=sys.stderr)
                if args.once:
                    raise SystemExit(1) from None
            heartbeat = {'collector_id': config['collector_id'], 'host': config['host'], 'channels': ['jsonl'],
                         'status': status, 'sent': state['sent'], 'local_auth': 0}
            try:
                post(config, '/api/v1/collectors/heartbeat', json.dumps(heartbeat).encode())
            except (urllib.error.URLError, TimeoutError):
                print('Heartbeat unavailable', file=sys.stderr)
            if args.once:
                return
            time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, OSError) as exc:
        raise SystemExit(f'Collector stopped: {exc}') from None
