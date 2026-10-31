import pytest

from config import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, identity_db_path=str(tmp_path / "identities.db"), redis_url="redis://localhost:6379", elasticsearch_url="http://localhost:9200",
                    elasticsearch_api_key="test", ingest_api_key="a" * 32, webhook_url="http://localhost/hook",
                    webhook_signing_secret="b" * 32, allow_insecure_local=True)

