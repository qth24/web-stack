# Mini Web Stack Remediation — Design Spec

**Date:** 2026-05-30
**Status:** Approved

## Summary

Refactor the project into a server-centric, multi-host deployment:
- Replace custom JSON DNS protocol with standard UDP DNS packets (RFC 1035 wire format).
- Split HTTP responsibilities into gateway and app backend roles, deployable across multiple hosts.
- Back shared state with PostgreSQL.
- Move auth/history to server side; make WaterCat support real HTML form GET/POST.
- Fix concurrency, streaming I/O, TLS verification, and load-balancer demonstration.

## Architecture

### Directory Structure

```
web-stack/
├── .env
├── requirements.txt              # +dnslib, psycopg[binary], cryptography
├── start.py                      # Orchestrates all roles on single host
├── dns/                          # DNS server (rewritten)
│   ├── wire.py                   # RFC 1035 packet encode/decode
│   ├── server.py                 # UDP loop with bounded ThreadPoolExecutor
│   ├── resolver.py               # Static-only authoritative resolver
│   ├── cache.py                  # TTL cache (ported)
│   ├── rate_limiter.py           # Per-IP sliding window (ported)
│   ├── records.json              # Static A records
│   └── tests/
├── server/                       # Unified server package (replaces http-server/)
│   ├── config.py
│   ├── main.py                   # Dispatches to gateway/app based on HTTP_ROLE
│   ├── gateway/
│   │   ├── server.py             # TLS termination, reverse proxy
│   │   ├── proxy.py              # Round-robin + failover
│   │   ├── balancer.py           # Health checks, backend pool
│   │   └── metrics.py            # Connection counters, /status
│   ├── app/
│   │   ├── server.py             # HTTP listener for app routes
│   │   ├── router.py             # Route dispatcher
│   │   ├── auth.py               # PBKDF2 + session management
│   │   ├── models.py             # DB operations for users, sessions, messages, history
│   │   ├── middleware.py         # Security headers, CORS, session auth
│   │   └── db.py                 # PostgreSQL connection pool
│   ├── shared/
│   │   ├── parser.py             # HTTP/1.1 parser + chunked decoding
│   │   ├── response.py           # Response builder + streaming
│   │   ├── security.py           # Security headers + WAF
│   │   ├── mime.py               # MIME type lookup
│   │   ├── static.py             # Static file serving with chunk streaming
│   │   └── workers.py            # ThreadPoolExecutor factory
│   └── tests/
├── vpn/                          # VPN server (refactored concurrency)
├── browser/                      # WaterCat (extended)
│   ├── core/
│   │   ├── dns_client.py         # Wire-format DNS client
│   │   ├── http_client.py        # +form POST, chunked decoding, verified TLS
│   │   ├── form_handler.py       # Form interception and submission (NEW)
│   │   └── session.py            # Server session state tracking (NEW)
├── deploy/
│   ├── runbooks/
│   ├── systemd/
│   └── demo/
└── docs/superpowers/specs/
```

### Process Model (Single-Host Dev)

```
┌──────────────────────────────────────────────────────┐
│  start.py (orchestrator)                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │ DNS (:53)│  │ Gateway  │  │ App A    │  │ App B │ │
│  │          │  │ :8443    │  │ :8081    │  │ :8082 │ │
│  └──────────┘  └────┬─────┘  └────┬─────┘  └───┬───┘ │
│                     └──────┬──────┴──────┬──────┘     │
│                     ┌──────┴─────────────┴──────┐     │
│                     │  PostgreSQL (:5432)        │     │
│                     └───────────────────────────┘     │
└──────────────────────────────────────────────────────┘
```

### Multi-Host Prod

| Host | Role                     |
| ---- | ------------------------ |
| 1    | DNS + Gateway HTTPS + VPN |
| 2    | App Backend A            |
| 3    | App Backend B            |
| 4    | PostgreSQL               |

## DNS Rewrite

### Wire Protocol (`dns/wire.py`)

Replace `dns/protocol.py` with RFC 1035 binary wire format using `dnslib`:

- `encode_query(domain, qtype="A") → bytes` — builds standard DNS query
- `decode_query(packet) → QueryInfo | None` — parses incoming query
- `encode_response(query_info, answers, rcode) → bytes` — builds answer
- `encode_error(query_info, rcode) → bytes` — error response

### Behavior

- Authoritative-only, static records from `dns/records.json`
- Single-question `IN A` queries only
- Domain in zone with record → `NOERROR` + A answers
- Domain in zone without record → `NXDOMAIN`
- Domain outside zone → `NXDOMAIN`
- Unsupported qtype/qclass → `NOTIMP`
- Rate-limited → silent drop

### Server

- Port 53 UDP with bounded `ThreadPoolExecutor` (`DNS_MAX_WORKERS=8`)
- Explicit socket ownership: pass `(sock, addr)` to workers

### WaterCat Client

- Sends/receives wire-format DNS packets via `dnslib.DNSRecord`
- Default port changes from 5336 → 53

## HTTP Role Split

### Env Vars

```bash
HTTP_ROLE=gateway|app
HTTP_NODE_ID=gateway-1|app-a|app-b
DATABASE_URL=postgresql://user:pass@localhost:5432/watercat
HTTP_MAX_WORKERS=16
TLS_CERT_PATH=/etc/certs/fullchain.pem
TLS_KEY_PATH=/etc/certs/privkey.pem
HTTP_BACKENDS=localhost:8081,localhost:8082
HTTP_DEV_INSECURE_TLS=false
SESSION_COOKIE_NAME=wc_session
SESSION_TTL_SECONDS=86400
```

### Gateway Role

- HTTPS only (TLS termination with real cert, fail-fast if missing)
- `/health` → gateway health
- `/status` → backend pool health + metrics
- Everything else → reverse proxy to app backends
- Round-robin + failover across `HTTP_BACKENDS`
- `X-Upstream-Node` header added to proxied requests
- Connection counter per active connection

### App Backend Role

- Plain HTTP on `HTTP_PORT`
- Routes:
  - `GET /health`, `GET /login`, `GET /register`
  - `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`
  - `GET /api/messages`, `POST /api/messages`
  - `GET /api/history`, `POST /api/history`
  - `GET /static/*`

## Database & Auth

### PostgreSQL Schema

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY, username VARCHAR(64) UNIQUE NOT NULL,
    display_name VARCHAR(128), password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(), expires_at TIMESTAMP NOT NULL
);
CREATE TABLE messages (
    id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE history (
    id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL, title TEXT, visited_at TIMESTAMP DEFAULT NOW()
);
```

Connection pooling via `psycopg_pool`. Pool size = `HTTP_MAX_WORKERS // 2`.

### Auth

- PBKDF2-HMAC-SHA256 password hashing (210,000 iterations)
- Session tokens: `secrets.token_urlsafe(32)`, stored as SHA-256 hash in DB
- Cookie: `wc_session=<token>; HttpOnly; Secure; SameSite=Lax; Path=/`
- Register: validate → hash → insert user → create session → set cookie
- Login: lookup → verify → create session → set cookie
- Logout: delete session → clear cookie
- Me: validate session via cookie hash lookup → return user or 401
- Session middleware on all `/api/*` routes

### Browser-Local Cleanup

- Remove `AuthDialog` from main flow, users table from SQLite
- Keep local storage for settings, bookmarks, shortcuts only
- History moved to server-side `POST /api/history`

## Concurrency

- Replace all `threading.Thread(...).start()` with bounded `ThreadPoolExecutor`
- `DNS_MAX_WORKERS=8`, `HTTP_MAX_WORKERS=16`, `VPN_MAX_WORKERS=8`
- Explicit socket ownership: pass as args to `executor.submit()`
- Graceful shutdown: `threading.Event()` + `executor.shutdown(wait=True)`
- Streamed response abstraction: `Response.body: bytes | BodyIterator`
- Static files streamed in 8KB chunks

## TLS & Crypto

- Gateway: real cert from `TLS_CERT_PATH`/`TLS_KEY_PATH`, fail-fast if missing
- WaterCat HTTP client: `ssl.create_default_context()` with hostname verification
- VPN upstream: `ssl.create_default_context()`
- Dev override: `HTTP_DEV_INSECURE_TLS=true` → unverified context
- XOR stream cipher removed; local encrypted payloads use AES-GCM via `cryptography`

## Browser Integration

### Form Handler

- Inject JS into custom-loaded pages to intercept `<form>` submissions
- Capture method, action, fields → route through Qt bridge → custom loader
- Support `GET` (query string) and `POST` (`application/x-www-form-urlencoded`)
- `multipart/form-data` returns 501

### HTTP Client Extensions

- Form POST body support
- Chunked transfer decoding (`Transfer-Encoding: chunked`)
- Verified TLS by default

### Session State

- `SessionManager` class: login, register, logout, check_auth, post_history
- After authenticated navigation, post history event to `/api/history`

## Load Balancing & Observability

- `BackendPool` with round-robin cursor + health checks
- `GET /status` returns node info, active connections, backend health
- `X-Upstream-Node` header on all proxied responses
- Demo page shows upstream node in corner badge

## Deployment

### Single-Host Dev

`python3 start.py` launches DNS, Gateway, App A, App B, VPN. Requires local PostgreSQL.

### Multi-Host Prod

systemd units in `deploy/systemd/`. Runbooks in `deploy/runbooks/`.

## Dependencies

```
PySide6>=6.7
google-genai
dnslib>=0.9.25
psycopg[binary]>=3.2
cryptography>=42.0
```

## Test Plan

- DNS: packet encode/decode, NXDOMAIN/NOTIMP, cache TTL, rate-limit
- Auth: register/login/logout/me, invalid password, duplicate user, session expiry
- Browser: login form via custom loader, session reuse, GET/POST forms, chunked decoding
- Concurrency: bounded workers under load, static file streaming, connection metrics
- Load balancing: rotation across backends, failover, X-Upstream-Node, /status
- Deployment: LAN resolution, internet TLS-valid page load
