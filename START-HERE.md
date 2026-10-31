# Upgrade from the single-user version

Copy this package's `siem` directory contents over your existing project. Keep `.env.local` and Docker volumes. Start from the project directory with `start-local.ps1` (Windows) or `start-local.sh` (Linux/macOS).

**Authentication changes:** old shared dashboard keys and ingest keys no longer grant access. Create your first individual administrator:

```sh
docker compose -f compose.yaml exec api python -m ops.admin create-user admin --role admin
```

Sign in at http://127.0.0.1:8000 with that username/password. Create other accounts and download one enrollment configuration per computer from Organization administration. Stop the old Windows collector, then restart it with `-ConfigFile PATH-TO-DOWNLOADED-JSON`. New enrollment starts at the current log end; archive old pending/checkpoint files for investigation rather than deleting unacknowledged work. Old server environment secrets remain in `.env.local` for compatibility, but shared dashboard/ingest keys are ignored.

Run `docker compose -f compose.yaml exec api python -m ops.verify_pipeline` to check indexing and webhook delivery.

For another computer, use the central server's HTTPS address and follow [DEPLOYMENT.md](DEPLOYMENT.md). Do not send it the server's `.env.local`. See [README.md](README.md) for complete installation and enrollment steps.
