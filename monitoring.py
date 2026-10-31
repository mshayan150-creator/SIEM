"""Bounded operational records in Redis; never store credentials or evidence here."""
import json
import time
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis

from cache import PREFIX

RECORD_LUA = """
local cutoff = tonumber(ARGV[1]) - 604800
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -10001)
redis.call('SET', KEYS[2], ARGV[3], 'EX', 604800)
redis.call('EXPIRE', KEYS[1], 604800)
return 1
"""


async def record_status(redis: Redis, category: str, identity: str, fields: dict[str, Any]) -> None:
    payload = {**fields, "id": identity, "timestamp": datetime.now(UTC).isoformat()}
    await redis.register_script(RECORD_LUA)(
        keys=[PREFIX + category, PREFIX + category + ":" + identity],
        args=[str(time.time()), identity, json.dumps(payload)])


async def recent_status(redis: Redis, category: str, limit: int = 20) -> list[dict[str, Any]]:
    ids = await redis.zrevrangebyscore(PREFIX + category, "+inf", time.time() - 604800,
                                      start=0, num=limit)
    if not ids:
        return []
    values = await redis.mget([PREFIX + category + ":" + identity for identity in ids])
    return [json.loads(value) for value in values if value]
