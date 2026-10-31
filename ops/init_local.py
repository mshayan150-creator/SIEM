"""Generate independent local secrets without printing them or replacing an existing file."""
import os
import secrets
from pathlib import Path


def main() -> None:
    path = Path(__file__).resolve().parent.parent / ".env.local"
    values = {
        "SIEM_ALLOW_INSECURE_LOCAL": "true",
        "SIEM_REDIS_URL": "redis://redis:6379/0",
        "SIEM_ELASTICSEARCH_URL": "http://elasticsearch:9200",
        # Local ES disables auth; this key is syntactically valid but unused.
        "SIEM_ELASTICSEARCH_API_KEY": secrets.token_urlsafe(32),
        "SIEM_WEBHOOK_URL": "http://webhook:8080/incidents",
        "SIEM_WEBHOOK_SIGNING_SECRET": secrets.token_urlsafe(32),
    }
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SystemExit(".env.local already exists; preserved without changes") from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write("# Local-only settings; never deploy this file to production.\n")
        output.writelines(f"{key}={value}\n" for key, value in values.items())
    print("Created .env.local with independently generated secrets")


if __name__ == "__main__":
    main()
