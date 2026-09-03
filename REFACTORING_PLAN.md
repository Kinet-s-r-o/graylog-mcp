# Graylog MCP refactoring plan

## Current-state audit

The application is functional, but its main risks are concentrated in two large modules:

- `graylog_mcp/server.py` combines application construction, authentication, REST and MCP routes, HTML, CSS, JavaScript, UI documentation, and service orchestration.
- `graylog_mcp/audit.py` combines schema creation, migrations, audit retention, Graylog server persistence, MCP client persistence, authentication, and query-rule persistence.

The current automated test suite contains one catalog test. There are no integration tests for authentication, CRUD operations, permissions, migrations, CIDR restrictions, audit search, or WebUI behavior.

### Important findings

- The container publishes the application directly on `0.0.0.0`, so the Caddy separation between WebUI and MCP can be bypassed through the backend port.
- `GET /api/v1/queries` is public, while the other agent-facing operations require an API key.
- `GET /api/v1/audit` exposes the shared audit log to every authenticated MCP client instead of restricting it to WebUI administrators or the owning client.
- WebUI sessions are kept in an unbounded process-local dictionary. They disappear after restart, do not work across multiple workers, have no login rate limit, and are not periodically purged.
- The session cookie is not marked `Secure`; state-changing WebUI calls do not have explicit CSRF protection.
- Graylog API tokens are stored in plaintext in SQLite. Audit payloads may contain sensitive log data and currently have no field-level redaction.
- User-supplied API keys may be weak even though generated keys have sufficient entropy.
- Agent identity is placed in a `ContextVar` by a dependency without a matching reset lifecycle.
- SQLite foreign keys are declared but `PRAGMA foreign_keys=ON` is not enabled. There is no schema version table or repeatable migration mechanism.
- The FTS table has insert/delete triggers but no update trigger or explicit index rebuild for older rows.
- Broad exception handlers return raw exception strings to the WebUI, potentially exposing internal details.
- Graylog server URLs, query-rule structures, grouping definitions, metrics, intervals, and UI payloads lack centralized validation models.
- `GraylogClient.aggregate()` can mutate a caller-provided `group_by` list when adding a time bucket.
- WebUI markup is assembled through successive string replacements over legacy markup. Duplicate function definitions and order-dependent script concatenation have already caused navigation and initialization regressions.
- The Docker image runs as root, dependencies are range-pinned without a lock file, and no CI quality/security pipeline is present.

## Step 1 — P0: security and correctness

**Status: implemented and covered by automated tests.**

Goal: close externally exploitable gaps and establish deterministic request/session behavior before moving code.

### Changes

1. Introduce a dedicated authentication/session module:
   - bounded session store with expiry cleanup and rotation;
   - configurable `Secure`, `HttpOnly`, and `SameSite=Strict` cookies;
   - POST-only logout and CSRF protection for all state-changing WebUI requests;
   - login throttling by normalized client address;
   - a dependency with a proper enter/reset lifecycle for agent context.
2. Define and enforce an authorization matrix:
   - WebUI administration endpoints require an admin session;
   - every `/api/v1` endpoint except health requires an MCP client key;
   - remove agent access to the global audit log, or scope results to the authenticated client;
   - keep WebUI audit access administrator-only.
3. Harden network exposure:
   - listen on separate native ports for MCP/agent REST and WebUI/admin routes;
   - reject cross-interface routes in the application, independently of Caddy;
   - bind the backend host port to loopback by default when Caddy is used;
   - document direct-HTTP versus reverse-proxy deployment modes;
   - define trusted-proxy handling before using forwarded client IPs for CIDR checks.
4. Add strict request models and validation:
   - allow only `http`/`https` Graylog URLs and reject embedded credentials;
   - validate names, lengths, timeouts, limits, query types, intervals, groupings, and metrics;
   - require a minimum length for user-provided MCP API keys;
   - return stable public error codes/messages and log internal exceptions separately.
5. Protect sensitive data:
   - redact authorization headers, API keys, tokens, and configured sensitive fields from audit payloads;
   - add optional encryption-at-rest for Graylog tokens with an externally supplied master key;
   - define retention defaults appropriate for potentially sensitive log content.
6. Fix database correctness:
   - enable foreign keys, WAL mode, and a busy timeout;
   - add missing FTS update/rebuild handling;
   - stop mutating caller-owned grouping lists.

### Acceptance criteria

- Permission tests cover every public, agent, and administrator route.
- CSRF, login throttling, session expiry, CIDR restrictions, and secret redaction have automated tests.
- Caddy deployments cannot reach WebUI routes through the MCP listener or bypass the proxy through a public backend port.
- Existing database files migrate without losing records.

## Step 2 — P1: maintainable architecture and WebUI extraction

**Status: implemented and covered by automated and browser smoke tests.**

Goal: remove order-dependent code generation and separate responsibilities without changing the user-visible design.

### Target structure

```text
graylog_mcp/
  app.py                    # application factory and lifespan
  settings.py               # validated configuration
  auth/
    admin.py                # WebUI sessions, CSRF, throttling
    agent.py                # API-key and CIDR authorization
  api/
    agent_routes.py         # /api/v1 routes
    admin_routes.py         # /ui/api routes
    schemas.py              # request/response models
  services/
    graylog_service.py      # client registry and use cases
    query_service.py        # validation, rendering, execution
  persistence/
    database.py             # connection and transaction lifecycle
    migrations.py           # versioned migrations
    repositories.py         # servers, clients, queries, audit
  webui/
    index.html
    login.html
    help.html
    app.css
    app.js
```

### Changes

1. Replace the 50+ KB Python HTML string and all `UI_HTML.replace(...)` patches with static versioned assets.
2. Keep one implementation of each JavaScript function and use event delegation instead of inline handlers.
3. Split rendering into small UI modules for navigation, modals, tables, sorting/filtering, API access, and notifications.
4. Add a shared API client that handles JSON errors, unauthorized responses, CSRF headers, loading states, and retry-safe refreshes.
5. Move route handlers out of `server.py`; keep a small compatibility module exporting the current entry point and MCP tools.
6. Centralize exception translation and structured logging with request/correlation IDs.

### Acceptance criteria

- `server.py` is reduced to composition/compatibility code and contains no HTML, CSS, or JavaScript.
- WebUI navigation, dark mode, login/logout, CRUD modals, dirty-form warnings, delete confirmations, filters, sorting, and audit pagination pass browser tests.
- Existing URLs, MCP tool names, environment variables, and database records remain compatible.

## Step 3 — P2: extensibility and domain boundaries

Goal: make new Graylog operations, authentication backends, and storage implementations additive instead of requiring edits throughout the application.

### Changes

1. Introduce repository protocols and service-layer use cases; route handlers must not execute SQL or manage cached clients directly.
2. Replace ad-hoc JSON query definitions with typed domain models and versioned serialization.
3. Create a query executor registry so message search, aggregation, and future query types share validation and execution rules.
4. Create a managed `GraylogClientRegistry` that invalidates clients on configuration changes and closes them deterministically.
5. Separate MCP tool adapters from REST adapters while sharing the same application services.
6. Add extension points for external secret storage, distributed sessions, and alternative audit backends without making them mandatory.
7. Define an explicit API versioning/deprecation policy and stable response envelopes.

### Acceptance criteria

- A new query type or persistence backend can be added without editing route/authentication code.
- Unit tests can construct services with in-memory/fake repositories and fake Graylog clients.
- Cached clients are never reused after server credential, TLS, URL, or timeout changes.

## Step 4 — P3: quality, delivery, and operational readiness

Goal: prevent regressions and make releases observable and reproducible.

### Changes

1. Build a test pyramid:
   - unit tests for validation, query rendering, CIDR matching, session logic, repositories, and redaction;
   - API integration tests against a temporary SQLite database;
   - browser tests for the critical WebUI workflows;
   - contract tests with a mocked Graylog server and MCP client.
2. Add `ruff`, a type checker, coverage thresholds, dependency auditing, secret scanning, and `git diff --check` to CI.
3. Add a reproducible dependency lock and automated dependency updates.
4. Harden the container:
   - non-root user, read-only root filesystem support, explicit writable data path;
   - health and readiness checks that distinguish process health from database readiness;
   - graceful shutdown and resource limits.
5. Add structured logs and basic metrics for authentication failures, Graylog latency/errors, active sessions, database failures, and audit cleanup.
6. Update documentation with an authorization matrix, migration/backup procedure, reverse-proxy trust model, security checklist, and rollback steps.

### Acceptance criteria

- CI blocks merges on failed tests, formatting, typing, dependency vulnerabilities, or secret detection.
- A clean checkout can be built and tested reproducibly.
- Backup, migration, deployment, health verification, and rollback are documented and exercised.

## Recommended delivery order

Each step should be delivered as a separate reviewable branch or commit series. Step 1 may change security defaults, so it should include migration notes and tests in the same delivery. Step 2 should preserve behavior and visual design. Steps 3 and 4 should only begin after the security contracts and compatibility tests from Steps 1 and 2 are stable.
