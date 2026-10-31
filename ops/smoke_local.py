"""Submit a local batch exercising both rules, without exposing credentials."""
import json
import secrets
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


def main() -> None:
    settings = dict(line.split("=", 1) for line in (Path(__file__).resolve().parent.parent / ".env.local").read_text().splitlines()
                    if line and not line.startswith("#"))
    events = [{"@timestamp": datetime.now(UTC).isoformat(),
               "event": {"dataset": "local.auth", "outcome": "failure" if n < 6 else "success", "action": "login"},
               "source": {"ip": "192.0.2.1" if n < 7 else "192.0.2.2"},
               "user": {"name": "local-smoke-user"}, "message": "Synthetic local smoke-test login"}
              for n in range(8)]
    request = urllib.request.Request("http://127.0.0.1:8000/api/v1/telemetry",
                                     data=json.dumps({"events": events}).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer " + settings["SIEM_INGEST_API_KEY"],
                                              "Idempotency-Key": secrets.token_hex(16)}, method="POST")
    with urllib.request.urlopen(request, timeout=15) as response:
        print(response.status, response.read().decode())


if __name__ == "__main__":
    main()
