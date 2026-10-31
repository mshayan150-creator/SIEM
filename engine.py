"""Rule metadata, restart-safe delivery workers, and signed webhook dispatch."""
import asyncio
import hashlib
import hmac
import random
import time
import uuid
from typing import Any

import httpx
import structlog
from elastic_transport import TransportError
from elasticsearch import ApiError
from redis.exceptions import RedisError

from cache import PREFIX, STREAMS, Cache
from config import Settings
from database import Database
from monitoring import record_status
from schemas import Incident, Telemetry

log = structlog.get_logger()


def prepare_records(events: list[Telemetry], identity: str, settings: Settings) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    records: list[dict[str, Any]] = []
    keys: list[str] = []
    evidence_keys: list[str] = []
    for position, event in enumerate(events):
        doc = event.model_dump(mode="json", by_alias=True)
        subject = str(event.source.ip) if event.event.outcome == "failure" else event.user.name
        kind = "failure" if event.event.outcome == "failure" else "success"
        key = PREFIX + kind + ":" + hashlib.sha256(subject.encode()).hexdigest()
        keys.append(key)
        evidence_keys.append(key + ":evidence")
        common = {
            "affected_asset": {"source.ip": str(event.source.ip), "user.name": event.user.name},
        }
        records.append({
            "doc": doc, "id": f"{identity}:{position}",
            "index": "siem-events-logs-" + event.timestamp.strftime("%Y.%m.%d"),
            "login": event.event.action in settings.login_actions and event.event.outcome in {"success", "failure"},
            "brute": {**common, "severity": "critical", "rule_id": "brute-force",
                      "title": "Repeated authentication failures",
                      "threat": {"id": "T1110", "tactic": "Credential Access", "technique": "Brute Force"},
                      "description": "Source crossed six failures in a rolling 60-second arrival-time window. Investigate account targets and authentication controls."},
            "travel": {**common, "severity": "high", "rule_id": "concurrent-ip",
                       "title": "Concurrent authentication from different IPs",
                       "threat": {"id": "T1078", "tactic": "Defense Evasion", "technique": "Valid Accounts"},
                       "description": "Successful logins from distinct IPs within 300 seconds. Possible valid-account abuse; VPN/NAT and mobile changes can explain this. Geolocation is not evaluated."},
        })
    return records, keys, evidence_keys


class PermanentWebhookError(Exception):
    pass


class Dispatcher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(8, connect=3), follow_redirects=False,
            trust_env=False, limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def send(self, raw: str) -> None:
        incident = Incident.model_validate_json(raw)
        payload = incident.model_dump_json(by_alias=True).encode()
        for attempt in range(self.settings.webhook_attempts):
            timestamp = str(int(time.time()))
            signature = hmac.new(
                self.settings.webhook_signing_secret.get_secret_value().encode(),
                timestamp.encode() + b"." + payload, hashlib.sha256,
            ).hexdigest()
            retry_after = 0.0
            try:
                # Stream the response: an untrusted receiver cannot force an unbounded body allocation.
                async with self.client.stream(
                    "POST", self.settings.webhook_url.get_secret_value(), content=payload,
                    headers={"Content-Type": "application/json", "Idempotency-Key": incident.id,
                             "X-SIEM-Timestamp": timestamp, "X-SIEM-Signature": "sha256=" + signature},
                ) as response:
                    if 200 <= response.status_code < 300:
                        return
                    if response.status_code not in {408, 425, 429} and response.status_code < 500:
                        raise PermanentWebhookError(f"http_{response.status_code}")
                    value = response.headers.get("Retry-After", "0")
                    try:
                        retry_after = max(0, min(30, float(value)))
                    except ValueError:
                        pass
            except httpx.RequestError:
                pass  # Deliberately avoid logging exception URLs / webhook secrets.
            if attempt + 1 < self.settings.webhook_attempts:
                await asyncio.sleep(max(retry_after, random.uniform(0, min(15, 2 ** attempt))))
        raise TimeoutError("webhook_retry_budget_exhausted")


class Engine:
    def __init__(self, settings: Settings, cache: Cache, database: Database) -> None:
        self.settings = settings
        self.cache = cache
        self.database = database
        self.dispatcher = Dispatcher(settings)
        self.stop = asyncio.Event()
        self.tasks: list[asyncio.Task[None]] = []
        self.consumer = uuid.uuid4().hex

    def start(self) -> None:
        self.tasks = [asyncio.create_task(self.worker(name, stream), name=name)
                      for name, stream in STREAMS.items()]

    @property
    def healthy(self) -> bool:
        return bool(self.tasks) and all(not task.done() for task in self.tasks)

    async def worker(self, name: str, stream: str) -> None:
        cursor = "0-0"
        while not self.stop.is_set():
            try:
                cursor, entries = await self.cache.read(stream, self.consumer, cursor)
                if not entries:
                    continue
                # Work deadline is below the minimum reclaim lease (60s).
                async with asyncio.timeout(45):
                    if name == "webhooks":
                        entry_id, record = entries[0]
                        try:
                            await self.dispatcher.send(record["payload"])
                        except PermanentWebhookError as exc:
                            await record_status(self.cache.redis, "deliveries", record["id"], {"status": "dead_letter", "reason": str(exc)})
                            await self.cache.dead_letter(stream, entry_id, record, str(exc))
                            log.error("webhook_dead_lettered", incident_id=record["id"], reason=str(exc))
                        else:
                            await record_status(self.cache.redis, "deliveries", record["id"], {"status": "http_2xx"})
                            await self.cache.ack(stream, [entry_id])
                    else:
                        await self.database.write(self.cache, stream, entries)
            except (RedisError, TransportError, ApiError, TimeoutError) as exc:
                log.warning("delivery_retry_pending", queue=name, error_type=type(exc).__name__)
                try:
                    await asyncio.wait_for(self.stop.wait(), timeout=2)
                except TimeoutError:
                    pass
            except Exception as exc:
                # Programming errors fail readiness, rather than silently dropping records.
                log.critical("worker_failed", queue=name, error_type=type(exc).__name__)
                raise

    async def close(self) -> None:
        self.stop.set()
        if self.tasks:
            _, pending = await asyncio.wait(self.tasks, timeout=self.settings.shutdown_seconds)
            for task in pending:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.dispatcher.client.aclose()
