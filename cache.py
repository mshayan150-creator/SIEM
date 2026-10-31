"""Atomic correlation and durable fan-out using a dedicated Redis keyspace.

All keys share a hash tag: correctness on Redis Cluster, but one shard per deployment.
Only this application may write the siem:{engine}: prefix.
"""
import hashlib
import json
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from config import Settings
from schemas import Telemetry

PREFIX = "siem:{engine}:"
STREAMS = {name: PREFIX + name for name in ("logs", "alerts", "webhooks")}
GROUP = "delivery-v1"

# The script uses Redis TIME, not untrusted shipper timestamps. Windows are (now-W, now].
# Each member contains a deterministic ID and the actual normalized evidence log.
INGEST_LUA = r'''
local old = redis.call('GET', KEYS[1])
if old then
  if old == ARGV[1] then return 1 else return -1 end
end
local events = cjson.decode(ARGV[2])
local capacity = tonumber(ARGV[3])
for i=2,4 do
  if redis.call('XLEN', KEYS[i]) + #events > capacity then return -2 end
end
-- Validate private key types before the first write (Lua has no rollback).
for n,_ in ipairs(events) do
  local ztype = redis.call('TYPE', KEYS[n+4]).ok
  local htype = redis.call('TYPE', KEYS[n+4+#events]).ok
  if (ztype ~= 'none' and ztype ~= 'zset') or (htype ~= 'none' and htype ~= 'hash') then
    return redis.error_reply('CORRELATION_KEY_TYPE_MISMATCH')
  end
end
local clock = redis.call('TIME')
local now = tonumber(clock[1])*1000 + math.floor(tonumber(clock[2])/1000)
for n,item in ipairs(events) do
  local doc = item.doc
  local key = KEYS[n+4]
  local evidence = {}
  local total = 0
  local rule = nil
  if item.login then
    local window = 60000
    if doc.event.outcome == 'success' then window = 300000 end
    if doc.event.outcome == 'success' then
      local expired = redis.call('ZRANGEBYSCORE', key, '-inf', now-window)
      for _,ip in ipairs(expired) do redis.call('HDEL', KEYS[n+4+#events], ip) end
    end
    redis.call('ZREMRANGEBYSCORE', key, '-inf', now-window)
    local before = redis.call('ZCARD', key)
    if doc.event.outcome == 'success' then
      -- The newest event from each IP is sufficient session evidence. Member = IP;
      -- associated evidence is in a hash, pruned with the same window.
      local previous = redis.call('ZRANGE', key, 0, 1)
      for _,ip in ipairs(previous) do
        if ip ~= doc.source.ip then
          local raw = redis.call('HGET', KEYS[n+4+#events], ip)
          if raw then table.insert(evidence, cjson.decode(raw)) end
          rule = 'concurrent-ip'
          break
        end
      end
      -- Remove expired hash fields as well; key expiry bounds idle sessions.
      local hkey = KEYS[n+4+#events]
      redis.call('ZADD', key, now, doc.source.ip)
      redis.call('HSET', hkey, doc.source.ip, cjson.encode(doc))
      redis.call('PEXPIRE', hkey, window+1000)
      if rule then table.insert(evidence, doc); total = #evidence end
    else
      redis.call('ZADD', key, now, cjson.encode({id=item.id,doc=doc}))
      total = redis.call('ZCARD', key)
      -- State transition: alert only when moving from <=5 to >5.
      if before <= 5 and total > 5 then
        rule = 'brute-force'
        for _,raw in ipairs(redis.call('ZRANGE', key, -6, -1)) do
          table.insert(evidence, cjson.decode(raw).doc)
        end
      end
    end
    redis.call('PEXPIRE', key, window+1000)
  end
  redis.call('XADD', KEYS[2], '*', 'id', item.id, 'index', item.index,
             'payload', cjson.encode(doc))
  if rule then
    local alert = item.travel
    if rule == 'brute-force' then alert = item.brute end
    alert.id = item.id .. ':' .. rule
    alert.evidence = evidence
    alert.evidence_count = total
    alert['@timestamp'] = ARGV[5]
    local payload = cjson.encode(alert)
    redis.call('XADD', KEYS[3], '*', 'id', alert.id, 'index', 'siem-security-alerts', 'payload', payload)
    redis.call('XADD', KEYS[4], '*', 'id', alert.id, 'payload', payload)
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[4])
return 0
'''

# With exactly one consumer group per stream, acknowledged entries can be deleted.
ACK_LUA = "for _,id in ipairs(ARGV) do redis.call('XACK', KEYS[1], 'delivery-v1', id); redis.call('XDEL', KEYS[1], id) end return #ARGV"
DLQ_LUA = "redis.call('XADD', KEYS[2], '*', 'source_id', ARGV[1], 'record', ARGV[2], 'reason', ARGV[3]); redis.call('XACK', KEYS[1], 'delivery-v1', ARGV[1]); redis.call('XDEL', KEYS[1], ARGV[1]); return 1"


class QueueFull(Exception):
    pass


class IdempotencyConflict(Exception):
    pass


class Cache:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.redis: Redis = Redis.from_url(
            settings.redis_url.get_secret_value(), decode_responses=True,
            socket_connect_timeout=3, socket_timeout=10, max_connections=64,
            health_check_interval=30,
        )
        self.ingest_script = self.redis.register_script(INGEST_LUA)
        self.ack_script = self.redis.register_script(ACK_LUA)
        self.dlq_script = self.redis.register_script(DLQ_LUA)

    async def initialize(self) -> None:
        await self.redis.ping()
        for stream in STREAMS.values():
            try:
                await self.redis.xgroup_create(stream, GROUP, id="0", mkstream=True)
            except ResponseError as exc:
                if not str(exc).startswith("BUSYGROUP"):
                    raise

    async def ingest(self, events: list[Telemetry], request_id: str) -> bool:
        from datetime import UTC, datetime

        from engine import prepare_records  # Avoid a module import cycle.

        canonical = json.dumps([e.model_dump(mode="json", by_alias=True) for e in events],
                               sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        identity = hashlib.sha256(request_id.encode()).hexdigest()
        records, correlation_keys, evidence_keys = prepare_records(events, identity, self.settings)
        result = await self.ingest_script(
            keys=[PREFIX + "dedup:" + identity, *STREAMS.values(), *correlation_keys, *evidence_keys],
            args=[digest, json.dumps(records), self.settings.queue_capacity,
                  self.settings.dedup_seconds, datetime.now(UTC).isoformat()],
        )
        if result == -1:
            raise IdempotencyConflict
        if result == -2:
            raise QueueFull
        return result == 1

    async def ack(self, stream: str, ids: list[str]) -> None:
        if ids:
            await self.ack_script(keys=[stream], args=ids)

    async def dead_letter(self, stream: str, entry_id: str, record: dict[str, str], reason: str) -> None:
        await self.dlq_script(keys=[stream, stream + ":dlq"],
                              args=[entry_id, json.dumps(record), reason])

    async def read(self, stream: str, consumer: str, cursor: str) -> tuple[str, list[tuple[str, dict[str, str]]]]:
        claimed: Any = await self.redis.xautoclaim(
            stream, GROUP, consumer, self.settings.reclaim_idle_ms,
            start_id=cursor, count=1 if stream == STREAMS["webhooks"] else self.settings.bulk_size,
        )
        if claimed[1]:
            return str(claimed[0]), claimed[1]
        fresh: Any = await self.redis.xreadgroup(
            GROUP, consumer, {stream: ">"}, count=1 if stream == STREAMS["webhooks"] else self.settings.bulk_size, block=1000,
        )
        return str(claimed[0]), fresh[0][1] if fresh else []
