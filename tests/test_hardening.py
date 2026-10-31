from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr, ValidationError
from redis.exceptions import ConnectionError as RedisConnectionError

from config import Settings


@pytest.mark.parametrize("field", ["ingest_api_key", "webhook_signing_secret", "elasticsearch_api_key"])
@pytest.mark.parametrize("placeholder", ["REPLACE_WITH_RANDOM_SECRET_AT_LEAST_32_CHARS", " replace_this_secret_that_is_long_enough "])
def test_placeholder_rejected(settings, field, placeholder):
    values = settings.model_dump()
    values[field] = SecretStr(placeholder)
    with pytest.raises(ValidationError, match="placeholder"):
        Settings(_env_file=None, **values)


def test_repeated_secret_rejected_in_production(settings):
    values = settings.model_dump()
    values.update(allow_insecure_local=False, redis_url="rediss://localhost:6379",
                  elasticsearch_url="https://localhost:9200", webhook_url="https://localhost/hook")
    with pytest.raises(ValidationError, match="Repeated-character"):
        Settings(_env_file=None, **values)


@pytest.mark.asyncio
async def test_startup_failure_sanitized_and_clients_closed(settings):
    from main import StartupFailure, StartupSafeFastAPI, lifespan

    cache, database, engine = AsyncMock(), AsyncMock(), AsyncMock()
    cache.initialize.side_effect = RedisConnectionError("secret-connection-string")
    application = StartupSafeFastAPI(lifespan=lifespan)
    messages = []

    async def receive():
        return {"type": "lifespan.startup"}

    async def send(message):
        messages.append(message)

    with (patch("main.Settings", return_value=settings), patch("main.Cache", return_value=cache),
          patch("main.Database", return_value=database), patch("main.Engine", return_value=engine),
          patch("main.configure_logging"), patch("main.log") as logger):
        with pytest.raises(StartupFailure):
            await application({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["dependency"] == "redis"
    assert len(messages) == 1
    assert messages[0]["type"] == "lifespan.startup.failed"
    assert "Traceback" not in messages[0]["message"]
    assert "secret-connection-string" not in str(messages)
    cache.redis.aclose.assert_awaited_once()
    database.client.close.assert_awaited_once()
    engine.close.assert_awaited_once()


def test_local_initializer_preserves_existing_file(tmp_path, monkeypatch):
    from ops import init_local

    monkeypatch.setattr(init_local, "__file__", str(tmp_path / "ops" / "init_local.py"))
    init_local.main()
    path = tmp_path / ".env.local"
    original = path.read_bytes()
    configured = Settings(_env_file=path)
    assert configured.allow_insecure_local is True
    assert configured.ingest_api_key is None
    assert not configured.webhook_signing_secret.get_secret_value().startswith("REPLACE")
    with pytest.raises(SystemExit, match="preserved"):
        init_local.main()
    assert path.read_bytes() == original
