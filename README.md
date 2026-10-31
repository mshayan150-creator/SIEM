# SIEM — shared security monitoring

A self-hosted SIEM for **one organization, multiple user accounts and multiple computers**. Collectors send logs to one central server. Viewers inspect shared logs/alerts; administrators manage users and collector credentials.

This is a single-server implementation, not a multi-tenant SaaS or a certified enterprise deployment. See [VALIDATION.md](VALIDATION.md) for exactly what has been tested and [DEPLOYMENT.md](DEPLOYMENT.md) for remote access, backups and limitations.

## What it does

- FastAPI accepts authenticated ECS JSON batches with strict schemas, byte/batch limits and idempotent retries.
- Atomic Redis sliding windows detect six failed logins in 60 seconds and successful logins for one user from different IPs within five minutes.
- Separate durable queues deliver events/alerts to Elasticsearch and signed incidents to a webhook with retries.
- Dashboard shows recent events, incidents and evidence, collector heartbeats, queue depth and webhook receipt status.
- Individual username/password accounts with admin/viewer roles, rate-limited login, secure session cookies over HTTPS, CSRF origin checks and session revocation on password reset/disable.
- Per-computer, one-time-issued collector tokens. Revocation blocks subsequent requests. Events and heartbeats must match the registered hostname; idempotency is scoped per collector.
- Windows Event Log collector; portable Python collector for normalized JSONL files. Neither requires distributing server secrets.

## Run on your own computer

Install Docker Engine + Compose v2 (Linux) or Docker Desktop (Windows/macOS). Allocate enough memory for Elasticsearch (the sample reserves a 512MB heap and a 2GB container limit). Extract the `siem` directory and open a terminal **inside it**, wherever you saved it.

Windows PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\start-local.ps1
```

Linux/macOS:

```sh
sh ./start-local.sh
```

The Windows execution-policy override applies only to that process. Both scripts generate `.env.local` if absent, preserve existing credentials and data, and start the stack. They use Docker's Python, so no host Python is needed for the server.

Create your first administrator interactively:

```sh
docker compose -f compose.yaml exec api python -m ops.admin create-user admin --role admin
```

Enter a unique 15–128 character password when prompted. There are no default passwords and no public sign-up route. Open http://127.0.0.1:8000 and sign in. In **Organization administration**, create additional viewers or administrators. Each user can change their password from the dashboard. Use `ops.admin reset-password USERNAME` for server-operator recovery.

## Connect computers

For another computer, first deploy a reachable **HTTPS server** using [DEPLOYMENT.md](DEPLOYMENT.md). `127.0.0.1` always means the computer currently using it; it will not reach somebody else's server.

1. Run `hostname` on the target machine.
2. In the dashboard, enroll that hostname and download its collector JSON configuration. The token is issued once; keep the file private. Do not upload it to GitHub or send it in screenshots.
3. Transfer that configuration and the appropriate collector script to the computer. Do not copy `.env.local`.

**Windows:** open PowerShell as Administrator in the project folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\collectors\windows.ps1 -ConfigFile "$HOME\Downloads\collector-OFFICE-PC.json"
```

Replace the filename with your actual download. The script reads new Security logon events (4624/4625), System and Application events. It skips existing history on its first run and stays running until Ctrl+C. Appropriate Security log permissions and Windows auditing are required; the script does not alter audit policy. It is a foreground collector, not an installed service. Separate per-collector checkpoints live under `%LOCALAPPDATA%\SIEM-Collector`.

**Linux/macOS/Windows applications writing normalized JSONL:** with Python 3.10+ installed:

```sh
python3 collectors/jsonl.py --config collector-APP-SERVER.json --file /path/to/events.jsonl --state /private/path/collector-state.json
```

Use `python` on Windows if that is your Python launcher. This reads append-only JSONL, one ECS object per complete line, and starts at EOF by default. It does not parse arbitrary syslog text; your application/shipper must produce the schema below. Protect the config/state directory with your OS's user-only permissions. `--from-start` is an intentional historical import and can trigger arrival-time rules; normally omit it. File rotation/truncation pauses collection and requires operator handling. `--once` processes one batch and exits.

The Windows shipper requires a matching actual computer name; the JSONL shipper stamps the registered host label. Host binding limits what a credential can label, but is not hardware attestation.

## Verify the pipeline

```sh
docker compose -f compose.yaml exec api python -m ops.verify_pipeline
```

This registers and then revokes a temporary collector, sends eight clearly labeled synthetic events, waits for eight indexed logs/two alerts, and checks webhook acknowledgements plus the included receiver's signature receipts. It does not test Windows Event Log collection. Expect two `PASS` lines. Old deliveries made before receipt tracking was introduced will not have receipt records.

Real records use `windows.*` datasets. Smoke checks use `synthetic.pipeline_check`. An HTTP 2xx confirms receiver acceptance, not that a human read the alert. Slack/Discord need a payload adapter; the default receiver understands this application's signed incident schema.

## API event format

POST `/api/v1/telemetry` with `Authorization: Bearer <collector-token>`, `Content-Type: application/json`, and a unique 16–128 character `Idempotency-Key`. Reuse the **same key and same body** when retrying a batch. A different collector may use the same key independently.

```json
{"events":[{"@timestamp":"2026-10-31T12:00:00Z","event":{"dataset":"application.auth","outcome":"failure","action":"login"},"source":{"ip":"192.0.2.1"},"user":{"name":"EXAMPLE\\alice"},"host":{"name":"OFFICE-PC"},"message":"Authentication failed"}]}
```

`host.name` must match the enrolled hostname. Optional event fields: `code`, `id`. Outcomes: `success`, `failure`, `unknown`. Unknown outcomes never enter login correlation. Nested ECS objects are required; unknown fields are rejected. 202 means durable queue acceptance subject to Redis durability, not completed Elasticsearch indexing. 401 = bad/revoked token; 403 = wrong registered host; 409 = key reused with another payload; 422 = invalid event; 503 = dependency/backpressure, retry unchanged.

## Development and publishing

```sh
python -m venv .venv
# Activate .venv for your shell, then:
pip install --require-hashes -r requirements.lock.txt
pip install -r requirements-dev.txt
pytest -q
ruff check .
mypy
node --check static/app.js
```

The GitHub Actions workflow runs tests, type/lint/syntax checks, Compose startup and the pipeline verifier; a Windows job parses PowerShell scripts. The workflow assumes the contents of this `siem` directory are the repository root. It has not run on GitHub until published.

`.gitignore` and `.dockerignore` exclude live environment files, identity databases, collector credentials, private keys, logs and build caches. Review `git diff --cached` before publishing. Never commit `.env.local`, collector JSON downloads, identity data, real logs or screenshots containing credentials.
