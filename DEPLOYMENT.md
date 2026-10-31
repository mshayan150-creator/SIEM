# Deploy one shared organization

## Topology

All dashboard users and collectors connect to one server. All organization users can read that organization's logs; admins can manage accounts/tokens. This is not tenant isolation. Never mix unrelated customers in the same installation expecting private data boundaries.

The sample uses Caddy for browser/collector HTTPS. Redis and Elasticsearch stay on the private Docker network and publish no host ports. The API's operator port is bound to server loopback only. Use a dedicated trusted server. The sample's internal Redis/Elasticsearch have no TLS/auth: this is a **single-host trust boundary**, not a hardened multi-host deployment. `SIEM_ALLOW_INSECURE_LOCAL=true` permits those internal connections; `SIEM_PUBLIC_ORIGIN=https://...` independently forces secure browser cookies. Never open dependency ports to a LAN or the Internet.

## HTTPS setup

1. Choose a DNS hostname, such as `siem.your-domain.example`, pointing to the server. Clients must be able to reach it. Public certificate issuance needs working DNS and inbound TCP 80/443; restrict management/SSH separately. A LAN-only deployment needs a trusted internal certificate authority and a corresponding Caddy configuration; do not disable client certificate validation.
2. Run `start-local.ps1` or `start-local.sh` on the **server** to create local settings/data and bootstrap the administrator.
3. Create a file named `.env.shared` in the project root containing:

```dotenv
SIEM_DOMAIN=siem.your-domain.example
```

Replace that hostname with your own. Only put the hostname here, no scheme/path. Then run from the same directory:

```sh
docker compose --env-file .env.shared -f compose.yaml -f compose.shared.yaml up --build -d --wait --wait-timeout 240
```

Use that same `--env-file` and both `-f` arguments for future shared-deployment `up` commands. Do not run `start-local` afterward: it selects the local Compose configuration. Account-management `exec` commands can use `docker compose -f compose.yaml exec ...` because the service/project names are unchanged.

4. Open `https://YOUR-HOSTNAME` on a second computer. Sign in with its user's credentials. The downloaded enrollment configurations now contain that HTTPS origin. Re-enroll any computer that previously received a loopback configuration; the Windows collector deliberately refuses to reuse a checkpoint belonging to another server/collector.
5. Enroll each computer separately. Start its collector, check its heartbeat, then confirm actual `windows.*` or application records arrive. Test revocation on a disposable enrollment; it should receive 401 while other computers continue working.

Changing the origin requires users to sign in at the new address. Access via the old loopback dashboard URL is deliberately rejected by the configured origin policy. The internal pipeline verifier still uses its own bearer credential and server-loopback address; it has no browser cookies.

## Account lifecycle

- Bootstrap/recovery requires shell access to the server, not an unauthenticated browser route.
- Use the admin UI to create accounts, enable/disable users, enroll computers and revoke tokens.
- Users change their own password in the dashboard. An administrator/server operator can reset it with `docker compose -f compose.yaml exec api python -m ops.admin reset-password USERNAME`.
- Disable/enable/reset increments a user version, invalidating all existing sessions on the next authorized request. Revoking a collector blocks new requests; in-flight/previously accepted work may finish. The last active admin cannot be disabled, including concurrent requests.
- Passwords are salted scrypt hashes (`N=16384, r=8, p=5`); raw passwords are never persisted. Collector secrets are cryptographically random and only SHA-256 digests are stored. Session tokens are random, hashed as Redis key suffixes, expire in eight hours, and are not shared between accounts.
- Login is limited by peer IP and username. The app does not trust arbitrary forwarded headers. Behind Caddy, the IP limit is shared by the proxy's users; the username limit still applies. Tune with a trusted gateway for larger teams rather than enabling untrusted proxy headers.
- Basic access-change audit entries retain the latest 10,000 records in SQLite. They are not an immutable compliance log. No SSO, MFA or fine-grained event-level permissions are implemented.

## Data, recovery and capacity

`identity-data`, `redis-data`, `elastic-data`, `caddy-data` and `caddy-config` are named persistent volumes. Never use `down -v` when preserving data. Account data uses SQLite WAL with transactional mutations and is supported on one server's local disk. Do not place it on NFS, run independent identity databases behind a load balancer, or treat SQLite file copies during writes as a backup. Use SQLite's backup API or stop services and snapshot the complete volume including WAL files. Back up Elasticsearch and Redis using their supported snapshot/persistence procedures as well. Backups contain sensitive logs and password hashes; protect them.

Redis uses AOF and `appendfsync always` locally, but failure durability still depends on your storage. Queue acceptance/delivery is at least once. Elasticsearch document IDs and receiver receipt IDs make retries identifiable, but external webhook receivers must implement their own idempotency using `Idempotency-Key`. Do not claim exactly-once external effects.

The queues are bounded and return backpressure. Exhausted/transient webhook work stays pending for recovery; permanent HTTP failures enter a dead-letter queue. Inspect dashboard queue/dead-letter counts and logs, rather than treating silence as successful delivery. Dead letters and security-alert indices require an operator retention/recovery policy. Event indices use the supplied ILM policy. Event and alert queries are capped in the UI (24 hours, latest 100 events/50 alerts); search filters event metrics but not alerts.

## Detection and collector limits

- Rules correlate on Redis arrival time, not historical event time. The Windows collector tags remote logons already older than 60 seconds as `historical_logon` to avoid initial replay alerts. A batch delayed after normalization still retains its original body/action on retry. The JSONL shipper forwards supplied action/time unchanged.
- Concurrent IPs are a heuristic; VPNs/NAT/mobile changes can explain them. There is no geographic impossible-travel calculation. Brute force aggregates one source IP across the organization, which can group NAT users.
- Missing remote IPs on Windows become an explicit loopback placeholder and use `local_logon`, which does not trigger these IP rules. System/Application outcomes are unknown. Windows message text is truncated to 1,500 characters.
- Both collectors checkpoint only acknowledged work and retain an identical pending batch for retries. Pending data older than 23 hours pauses to avoid exceeding the default 24-hour dedup retention. Do not reduce dedup retention without changing that policy.
- Windows log wrap/clear can erase unread history. Detected record-number resets pause collection; clearing and regrowing beyond an old record number can evade that simple check. JSONL truncation/rotation pauses instead of guessing. Operators must preserve pending evidence and deliberately reinitialize affected streams.
- Collectors run in the foreground. Service installation/auto-start, centralized upgrades and backfill recovery are not implemented. Windows Event Log integration still requires testing on Windows with the organization's audit policy.

## Sources

- OWASP password storage guidance: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Caddy automatic HTTPS: https://caddyserver.com/docs/automatic-https
- Windows Event Log queries: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1
