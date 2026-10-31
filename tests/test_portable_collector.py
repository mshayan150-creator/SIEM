import json
import time
import urllib.error
from unittest.mock import patch

import pytest

from collectors.jsonl import save, step, validate_config


def setup_file(tmp_path, content):
    source = tmp_path/'logs.jsonl'
    source.write_text(content)
    stat = source.stat()
    state = {'file_id': [stat.st_dev, stat.st_ino], 'offset': 0, 'pending': None, 'sent': 0}
    path = tmp_path/'state.json'
    save(path, state)
    config = {'api_url': 'https://siem.example.org', 'host': 'PC', 'collector_id': 'x', 'token': 'secret'}
    return config, source, path, state


def test_pending_batch_survives_failure_and_restart(tmp_path):
    config, source, path, state = setup_file(tmp_path, '{"message":"first"}\n')
    sent = []
    def fail(config, endpoint, raw, identity):
        sent.append((raw, identity))
        raise urllib.error.URLError('offline')
    with patch('collectors.jsonl.post', side_effect=fail), pytest.raises(urllib.error.URLError):
        step(config, source, path, state)
    restarted = json.loads(path.read_text())
    assert restarted['offset'] == 0
    with patch('collectors.jsonl.post') as post:
        assert step(config, source, path, restarted) == 1
        assert post.call_args.args[2:] == sent[0]
    assert json.loads(path.read_text())['pending'] is None
    assert restarted['sent'] == 1


def test_incomplete_line_not_advanced(tmp_path):
    config, source, path, state = setup_file(tmp_path, '{"message":"first"}')
    with patch('collectors.jsonl.post') as post:
        assert step(config, source, path, state) == 0
        assert state['offset'] == 0
        post.assert_not_called()
    with source.open('a') as out:
        out.write('\n')
    with patch('collectors.jsonl.post'):
        assert step(config, source, path, state) == 1


def test_truncation_and_old_pending_fail_closed(tmp_path):
    config, source, path, state = setup_file(tmp_path, '{}\n')
    state['offset'] = 100
    with pytest.raises(ValueError, match='rotated or truncated'):
        step(config, source, path, state)
    state['offset'] = 0
    state['pending'] = {'created': time.time()-86400}
    with pytest.raises(ValueError, match='safe retry age'):
        step(config, source, path, state)


@pytest.mark.parametrize('url', ['http://example.org', 'https://user:pass@example.org', 'https://example.org/api', 'https://example.org?secret=x'])
def test_collector_requires_safe_origin(url):
    with pytest.raises(ValueError):
        validate_config({'api_url': url, 'host': 'PC', 'collector_id': 'x', 'token': 'secret'})
