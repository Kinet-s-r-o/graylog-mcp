# Graylog MCP operations runbook

## Health and readiness

`GET /health` verifies that the process is answering. `GET /ready` verifies
that the SQLite database has opened and migrations completed. The container
healthcheck uses `/ready`; a process can therefore be alive but not ready.
`GET /metrics` exposes counters in Prometheus text format. Keep it on a
trusted listener or restrict it at the reverse proxy.

## Backup and migration

Stop writes or use SQLite's online backup command before copying the database:

```sh
sqlite3 ./data/audit.db ".backup './data/audit.db.backup-$(date +%Y%m%d-%H%M%S)'"
```

The application applies additive migrations during startup and records applied
versions in `schema_migrations`. Back up `data/audit.db` before upgrading. To
verify a migration, start the image and check `/ready`, then inspect
`PRAGMA user_version` and the migration rows.

## Deployment and rollback

Build and start a release with:

```sh
docker compose build graylog-mcp
docker compose up -d graylog-mcp caddy
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/ready
```

The application container is non-root, read-only except for `/data`, drops all
Linux capabilities, and has a no-new-privileges policy. Caddy remains the
public entry point. For rollback, stop the stack, restore the application image
tag and database backup if the migration is not backward-compatible, then
start the previous release and verify both health endpoints.

## Authorization and proxy trust

| Surface | Authentication | Exposure |
| --- | --- | --- |
| `/health`, `/ready` | none | health checker only |
| `/metrics` | proxy/network policy | trusted monitoring only |
| `/mcp`, `/api/v1/*` | agent Bearer key; optional CIDR | MCP listener |
| WebUI and `/ui/api/*` | admin session; CSRF on writes | WebUI listener |

Only proxy networks listed in `TRUSTED_PROXY_CIDRS` may supply
`X-Forwarded-For`. Do not enable that setting for arbitrary client networks.
Use HTTPS for any untrusted network and set `UI_COOKIE_SECURE=true`.

## Security checklist

- Keep `.env`, Graylog tokens, API keys, and `data/audit.db` out of source control.
- Use a dedicated Graylog token with the minimum search permissions required.
- Set `SECRET_ENCRYPTION_KEY` and back it up separately from the database.
- Review audit retention and redaction settings for the sensitivity of logs.
- Restrict Caddy's HTTP and MCP ports with the external firewall.
- Check `/metrics` and audit logs after deployment for authentication failures,
  Graylog errors, and database failures.
