"""Async Elasticsearch bulk persistence with per-item failure classification."""
import json
from typing import Any

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from cache import Cache
from config import Settings


class Database:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        tls_options: dict[str, Any] = {"ca_certs": settings.ca_certs} if settings.ca_certs else {}
        self.client = AsyncElasticsearch(
            settings.elasticsearch_url,
            api_key=settings.elasticsearch_api_key.get_secret_value(),
            verify_certs=True, **tls_options,
            request_timeout=10, max_retries=0,
        )

    async def write(self, cache: Cache, stream: str, entries: list[tuple[str, dict[str, str]]]) -> None:
        actions: list[dict[str, Any]] = [
            {"_op_type": "index", "_index": fields["index"], "_id": fields["id"],
             "_source": json.loads(fields["payload"])}
            for _, fields in entries
        ]
        _, failures = await async_bulk(
            self.client, actions, chunk_size=self.settings.bulk_size,
            max_chunk_bytes=5_000_000, raise_on_error=False,
            raise_on_exception=True, max_retries=0,
        )
        if not isinstance(failures, list):
            raise TypeError("Bulk helper did not return item failures")
        failed: dict[str, int] = {}
        for failure in failures:
            item = next(iter(failure.values()))
            failed[str(item["_id"])] = int(item["status"])
        succeeded: list[str] = []
        for entry_id, record in entries:
            status = failed.get(record["id"])
            if status is None:
                succeeded.append(entry_id)
            elif status in {400, 404, 413, 422}:
                # Do not log raw ES error text: it can contain the source document.
                await cache.dead_letter(stream, entry_id, record, f"elasticsearch_status_{status}")
            # 429, 5xx, auth and other failures stay pending for recovery.
        await cache.ack(stream, succeeded)


async def provision() -> None:
    """One-time operator command; use a separate privileged provisioning API key."""
    from pathlib import Path

    settings = Settings()
    database = Database(settings)
    try:
        root = Path(__file__).parent / "ops"
        await database.client.ilm.put_lifecycle(
            name="siem-events-retention", policy=json.loads((root / "retention-policy.json").read_text())
        )
        for name in ("events", "alerts"):
            body = json.loads((root / f"{name}-template.json").read_text())
            await database.client.indices.put_index_template(name=f"siem-{name}", body=body)
        # Additive migration for existing daily indices; templates only affect new indices.
        await database.client.indices.put_mapping(
            index="siem-events-logs-*", allow_no_indices=True, ignore_unavailable=True,
            properties={"host": {"properties": {"name": {"type": "keyword"}}},
                        "event": {"properties": {"id": {"type": "keyword"}, "code": {"type": "keyword"}}}},
        )
        if not await database.client.indices.exists(index="siem-security-alerts"):
            await database.client.indices.create(index="siem-security-alerts")
    finally:
        await database.client.close()


if __name__ == "__main__":
    import asyncio

    asyncio.run(provision())
