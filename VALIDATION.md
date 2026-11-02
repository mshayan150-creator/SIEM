# Dashboard usability update

The redesigned dashboard was checked at desktop (1440px) and mobile (390px) widths in Chromium. The automated browser test covers navigation, failed-event shortcuts, search/clear, outcome and severity filters, visible-row JSON export, evidence dialogs staying open through live refresh, hostile log text escaping, account creation, credential enrollment/download, revoke cancellation/confirmation, stale-state recovery, keyboard search, viewer restrictions and password changes.

The existing **49 Python tests**, Ruff, mypy and JavaScript syntax checks pass. A browser regression job is included in GitHub Actions. Browser checks use the real FastAPI routes with temporary identities and simulated Redis/Elasticsearch dependencies; this does not replace the Docker/remote integration checks below.

# Validation — shared-organization update

## Verified in this environment

- **49 Python tests passed**, with the hash-pinned runtime dependencies installed. Tests use real SQLite identity persistence, Lua-capable fakeredis and mocked Elasticsearch/external transports.
- Multi-account checks: admin/viewer authorization, independent sessions, self-service password change and account disable/reset invalidation, no legacy shared-key bypass, concurrent last-admin protection, no plaintext password/token storage.
- Multi-computer checks: two distinct collector credentials, identical batch keys scoped independently, concurrent submissions, host/heartbeat binding, token revocation without affecting the other computer.
- HTTPS-origin checks: configured origin is enforced, Secure/HttpOnly/SameSite cookies are issued, cross-origin admin mutations are rejected.
- Collector checks: JSONL pending-batch retry survives simulated restart with identical body/key, incomplete lines do not advance the checkpoint, truncation and expired retries stop, unsafe origins are rejected.
- Existing correlation, backpressure, replay, bulk-failure, startup-failure and signed-webhook tests pass.
- Ruff passes. Mypy passes across **13 application/collector/operator modules**. Python compilation and JavaScript syntax checks pass.
- **Chromium browser checks passed against the actual FastAPI routes**, with fixture Redis/Elasticsearch data: login, evidence expansion, escaped hostile log text, account creation, enrollment download, token revocation, viewer restrictions and password change. Desktop (1440px) and mobile (390px) layouts were inspected. The browser fixture data are test data, not live enterprise logs.
- Compose/workflow YAML parsing and assertions verify the loopback API binding, private dependency networks and persistent identity volume. This is not equivalent to running containers.

## Not verified here

- Docker Engine and Windows PowerShell/Event Log are unavailable here. Full Compose startup, live Windows collection, Caddy certificate issuance and access from physical remote computers have not been executed in this environment.
- GitHub Actions is included for Docker pipeline integration and PowerShell syntax parsing but has not run until the code is pushed to a repository with Actions enabled.
- No enterprise load test, failover test, security audit, SSO/MFA validation or high-availability claim is made.

## Required deployment checks

1. Start the local stack and create the first administrator.
2. Run `docker compose -f compose.yaml exec api python -m ops.verify_pipeline` and require both PASS messages for the bundled local receiver.
3. Create a viewer and confirm it can inspect logs but cannot manage accounts/tokens.
4. Deploy the HTTPS overlay and sign in from another computer at the configured hostname.
5. Enroll two real computers, start their collectors, and confirm their separate heartbeats and new real events. Revoke a disposable enrollment and confirm 401 responses without stopping the other computer.
6. Reset a test user's password and confirm its old browser sessions fail and the new password works.

See README.md and DEPLOYMENT.md for procedures and operational limits.
