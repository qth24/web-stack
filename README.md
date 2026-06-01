# WaterCat Mini Web Stack

![alt text](image.png)

WaterCat Mini Web Stack is a from-scratch Python web stack used to demonstrate how a browser, DNS server, gateway, application nodes, VPN-style tunnel, and PostgreSQL database can work together without a web framework.

The current system has six main runtime pieces:

- `browser/`: a PySide6 desktop browser with custom DNS, raw HTTP loading, optional VPN routing, cookies, cache, phishing checks, and encrypted profile sync.
- `dns/`: an asyncio UDP DNS server that answers RFC 1035 `A` record queries from `dns/dns_records.json`.
- `server/gateway/`: an asyncio gateway and round-robin load balancer.
- `server/app/`: asyncio backend app nodes that serve static files and API routes.
- `vpn/`: an application-layer HTTP tunnel used by the browser.
- PostgreSQL: a separate database node that stores user data, sessions, messages, history, and encrypted browser profile records.

`http-server/public/` is still active: app nodes serve static assets from this directory. The current HTTP runtime lives under `server/`, not under an old `http-server/src` layout.

## Current Architecture

```text
WaterCat Browser
  -> Custom DNS Server
  -> direct HTTP request OR Mini VPN tunnel
  -> Gateway / Load Balancer
  -> App Node app-a / App Node app-b
  -> PostgreSQL Database Node
  -> response returns through App Node -> Gateway -> Browser
```

PostgreSQL is an independent database node. It is not inside an app node and is not a backend HTTP service. Each app node connects to it through `DATABASE_URL`.

## Components

| Component | Entry point | Role | Default local port |
| --- | --- | --- | --- |
| DNS server | `python3 -m dns.server` | Answers static RFC 1035 `A` record lookups from `dns/dns_records.json` | UDP `5336` with `.env.example`, UDP `53` by code default |
| App node | `HTTP_ROLE=app python3 -m server.main` | Serves static files and app APIs, reads/writes PostgreSQL | TCP `8081` / `8082` in local cluster |
| Gateway | `HTTP_ROLE=gateway python3 -m server.main` | Exposes `/health` and `/status`, proxies other requests to app nodes | TCP `8443` |
| VPN tunnel | `python3 -m vpn.vpn_server` | Forwards raw HTTP requests from the browser through a JSON-line tunnel | TCP `9443` |
| Browser | `python3 browser/gui/browser_gui.py` | Desktop browser and client for DNS, HTTP, VPN, auth, cache, cookies, and encrypted profile sync | GUI |
| PostgreSQL | external service | Stores user database records | TCP `5432` |

## Request Workflow

1. The user enters a URL in the WaterCat browser.
2. The browser parses the URL and decides whether to use its custom loader or Qt WebEngine directly.
3. For custom-loaded hosts, the browser asks the DNS server for an `A` record.
4. The DNS server checks its TTL cache, then static records in `dns/dns_records.json`, and returns an IP or `NXDOMAIN`.
5. The browser builds a raw HTTP request.
6. If VPN is disabled, the browser sends the request directly to the resolved endpoint.
7. If VPN is enabled, the browser sends the raw HTTP request to the Mini VPN server in a JSON-line frame. The VPN server validates the token, opens the upstream TCP/TLS connection, forwards the request, and returns the raw response.
8. The gateway receives the HTTP request, handles `/health` and `/status` internally, or proxies other requests to an app node.
9. The gateway chooses an app node with `BackendPool` round-robin routing.
10. The app node parses the request, runs a small WAF inspection, routes static/auth/profile/history/message APIs, and reads or writes PostgreSQL when needed.
11. The response returns to the browser through the app node and gateway.
12. The browser stores cookies, updates HTTP cache when eligible, runs phishing/content checks, injects runtime metadata, and renders the page with Qt WebEngine.
13. When signed in, settings, bookmarks, shortcuts, and synced history are encrypted in the browser and synced through app APIs into PostgreSQL.

## Data Storage

Server-side data lives in PostgreSQL:

- `users`
- `sessions`
- `messages`
- `history`
- `browser_profile_keys`
- `browser_profile_entries`

Browser-local runtime data lives under `BROWSER_STATE_DIR`:

- cookies
- HTTP cache
- browser window/runtime state
- remembered encrypted-profile unlock material for the local device

Profile data is not stored as plaintext on the server. The browser encrypts profile entries client-side and the server stores ciphertext plus key-wrapping metadata.

## Repository Layout

```text
browser/              PySide6 browser, local state, DNS/HTTP/VPN clients
deploy/               systemd examples and deployment runbooks
dns/                  RFC 1035 DNS server, cache, static resolver, wire helpers
http-server/public/   static files served by app nodes
server/app/           backend app node, routes, auth, models, DB pool
server/gateway/       gateway, load balancer, proxy, metrics
server/shared/        HTTP parser/response/static/security helpers
vpn/                  JSON-line tunnel protocol and VPN server
start.py              local development launcher for server-side services
```

## Requirements

- Python `3.11+`
- PostgreSQL `15+`
- A GUI-capable Linux or macOS environment for the browser
- `pip`
- Root or `CAP_NET_BIND_SERVICE` only if binding DNS to UDP port `53`
- TLS certificate and key only if you want the gateway to serve HTTPS

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Configuration

Copy the template:

```bash
cp .env.example .env
```

The modules load configuration as follows:

- `dns/`, `vpn/`, and `server/` load the root `.env`.
- `browser/` loads `browser/.env` first, then the root `.env`.
- Shell environment variables override file values.

For local development, the important values are:

```env
DATABASE_URL=postgresql://watercat:watercat@localhost:5432/watercat

DNS_BIND_HOST=127.0.0.1
DNS_PORT=5336
DNS_RECORDS_PATH=dns/dns_records.json

HTTP_HOST=127.0.0.1
HTTP_HTTPS_PORT=8443
HTTP_PUBLIC_DIR=/absolute/path/to/web-stack/http-server/public

VPN_BIND_HOST=127.0.0.1
VPN_PORT=9443
VPN_TOKEN=demo-token

BROWSER_DNS_HOST=127.0.0.1
BROWSER_DNS_PORT=5336
BROWSER_HTTP_DEFAULT_PORT=8443
BROWSER_ACCOUNT_BASE_URL=http://127.0.0.1:8443
BROWSER_ENABLE_VPN=false
BROWSER_VPN_HOST=127.0.0.1
BROWSER_VPN_PORT=9443
BROWSER_VPN_TOKEN=demo-token
BROWSER_ENABLE_AI_ASSISTANT=false
```

Use an absolute `HTTP_PUBLIC_DIR`. This avoids path differences between manual launches, `start.py`, and systemd.

Note: `.env.example` still contains a few compatibility variables from earlier iterations. In the current source, the DNS server resolves static `A` records from `dns/dns_records.json`; forwarded DNS resolver modes are not implemented in `dns/resolver.py`.

## Local Setup

### 1. Create PostgreSQL database

```bash
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE USER watercat WITH PASSWORD 'watercat';"
sudo -u postgres psql -c "CREATE DATABASE watercat OWNER watercat;"
```

The app schema is created automatically when an app node starts.

### 2. Start the local server-side stack

`start.py` is intended to start:

1. DNS server
2. App node `app-a` on `8081`
3. App node `app-b` on `8082`
4. Gateway on `8443`
5. VPN server on `9443`

Run from the repository root:

```bash
python3 start.py
```

Then start the browser in a second terminal:

```bash
python3 browser/gui/browser_gui.py
```

### 3. Local URLs to try

The default `dns/dns_records.json` maps local demo hostnames to `127.0.0.1`.

Try:

- `http://myweb.local/`
- `http://example.local/`
- `http://myweb.local/login`
- `http://myweb.local/register`

## Manual Startup

Run each service in its own terminal from the repository root.

DNS:

```bash
python3 -m dns.server
```

App node A:

```bash
HTTP_ROLE=app \
HTTP_PORT=8081 \
HTTP_NODE_ID=app-a \
python3 -m server.main
```

App node B:

```bash
HTTP_ROLE=app \
HTTP_PORT=8082 \
HTTP_NODE_ID=app-b \
python3 -m server.main
```

Gateway:

```bash
HTTP_ROLE=gateway \
HTTP_HTTPS_PORT=8443 \
HTTP_BACKENDS=127.0.0.1:8081,127.0.0.1:8082 \
python3 -m server.main
```

VPN:

```bash
python3 -m vpn.vpn_server
```

Browser:

```bash
python3 browser/gui/browser_gui.py
```

## Verification

DNS:

```bash
dig @127.0.0.1 -p 5336 myweb.local
```

App node:

```bash
curl http://127.0.0.1:8081/health
```

Gateway:

```bash
curl http://127.0.0.1:8443/health
curl http://127.0.0.1:8443/status
```

Register a user through an app node:

```bash
curl -i \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo123"}' \
  http://127.0.0.1:8081/auth/register
```

Register through the gateway:

```bash
curl -i \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo2","password":"demo123"}' \
  http://127.0.0.1:8443/auth/register
```

VPN check:

1. Open the browser.
2. Enable the VPN toggle.
3. Visit `http://myweb.local/`.
4. Open the browser DevTools panel and confirm the network route shows `vpn`.

## API Surface

### DNS

- UDP RFC 1035 DNS wire format
- `A` records only
- Static records from `dns/dns_records.json`
- TTL cache and per-client rate limiting

### Gateway

- `GET /health`
- `GET /status`
- All other HTTP requests are proxied to app backends.

The gateway only serves TLS when both `TLS_CERT_PATH` and `TLS_KEY_PATH` are set. Otherwise, the gateway serves plain HTTP even if the listen port is named `HTTP_HTTPS_PORT`.

### App backend

- `GET /health`
- `GET /`
- `GET /login`
- `GET /register`
- `GET /static/*`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/logout`
- `GET /auth/me`
- `GET /api/profile/bootstrap`
- `POST /api/profile/key`
- `POST /api/profile/entries`
- `GET /api/history`
- `POST /api/history`
- `GET /api/messages`
- `POST /api/messages`

### VPN

- TCP JSON-line protocol
- `connect` operation for raw HTTP request/response forwarding
- `stream_connect` operation for bidirectional TCP stream forwarding
- Token authentication with `VPN_TOKEN`

## Multi-Node Deployment Shape

The intended deployment shape is:

```text
Browser clients
  -> DNS node
  -> optional VPN node
  -> gateway node
  -> app node A / app node B
  -> shared PostgreSQL database node
```

Each app node should have:

- `HTTP_ROLE=app`
- a unique `HTTP_NODE_ID`
- its own `HTTP_PORT`
- the same shared `DATABASE_URL`
- an absolute `HTTP_PUBLIC_DIR`

The gateway should have:

- `HTTP_ROLE=gateway`
- `HTTP_BACKENDS` pointing at app nodes
- optional `TLS_CERT_PATH` and `TLS_KEY_PATH`

The PostgreSQL node should be reachable from every app node through `DATABASE_URL`.

The DNS node should map application domains to the gateway IP.

The VPN node is optional. If exposed outside a trusted lab, set a strong `VPN_TOKEN` and be careful with `VPN_ALLOW_PRIVATE_TARGETS`.

Example app node:

```bash
export HTTP_ROLE=app
export HTTP_NODE_ID=app-a
export HTTP_PORT=8081
export DATABASE_URL=postgresql://watercat:watercat@db.local:5432/watercat
export HTTP_PUBLIC_DIR=/opt/web-stack/http-server/public
python3 -m server.main
```

Example gateway:

```bash
export HTTP_ROLE=gateway
export HTTP_NODE_ID=gateway-1
export HTTP_HOST=0.0.0.0
export HTTP_HTTPS_PORT=443
export HTTP_BACKENDS=10.0.0.11:8081,10.0.0.12:8082
export TLS_CERT_PATH=/etc/letsencrypt/live/example.com/fullchain.pem
export TLS_KEY_PATH=/etc/letsencrypt/live/example.com/privkey.pem
python3 -m server.main
```

Example DNS record:

```json
{
  "myweb.local": { "ip": "203.0.113.10", "ttl": 60 }
}
```

Example browser client configuration:

```env
BROWSER_DNS_HOST=DNS_NODE_IP
BROWSER_DNS_PORT=53
BROWSER_HTTP_DEFAULT_PORT=80
BROWSER_HTTPS_DEFAULT_PORT=443
BROWSER_ACCOUNT_BASE_URL=https://gateway.example.com
BROWSER_ENABLE_VPN=true
BROWSER_VPN_HOST=VPN_NODE_IP
BROWSER_VPN_PORT=9443
BROWSER_VPN_TOKEN=replace-this-with-a-real-secret
```

## Key Environment Variables

### Database

- `DATABASE_URL`: PostgreSQL connection string used by app nodes.

### DNS

- `DNS_BIND_HOST`
- `DNS_PORT`
- `DNS_RECORDS_PATH`
- `DNS_RATE_LIMIT_MAX_QUERIES`
- `DNS_RATE_LIMIT_WINDOW_SECONDS`

### App and Gateway

- `HTTP_ROLE`: `app` or `gateway`
- `HTTP_HOST`
- `HTTP_PORT`: app-node listen port
- `HTTP_HTTPS_PORT`: gateway listen port
- `HTTP_BACKENDS`: comma-separated `host:port` backend list for the gateway
- `HTTP_NODE_ID`
- `HTTP_PUBLIC_DIR`
- `TLS_CERT_PATH`
- `TLS_KEY_PATH`

### VPN

- `VPN_BIND_HOST`
- `VPN_PORT`
- `VPN_TOKEN`
- `VPN_CONNECT_TIMEOUT`
- `VPN_READ_TIMEOUT`
- `VPN_ALLOW_PRIVATE_TARGETS`

### Browser

- `BROWSER_DNS_HOST`
- `BROWSER_DNS_PORT`
- `BROWSER_HTTP_DEFAULT_PORT`
- `BROWSER_HTTPS_DEFAULT_PORT`
- `BROWSER_ACCOUNT_BASE_URL`
- `BROWSER_ENABLE_VPN`
- `BROWSER_VPN_HOST`
- `BROWSER_VPN_PORT`
- `BROWSER_VPN_TOKEN`
- `BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS`
- `BROWSER_WEBENGINE_PROXY_HOST`
- `BROWSER_WEBENGINE_PROXY_PORT`
- `BROWSER_STATE_DIR`
- `BROWSER_ENABLE_AI_ASSISTANT`

## Troubleshooting

- `start.py` says PostgreSQL is not ready but you use a remote database.
  Set `SKIP_DB_CHECK=1`; the preflight check only probes `localhost:5432`.
- Static pages return `404`.
  Check that `HTTP_PUBLIC_DIR` points to the real `http-server/public` directory.
- `curl https://127.0.0.1:8443` fails locally.
  Unless TLS cert/key variables are set, the gateway on `8443` is plain HTTP. Use `http://127.0.0.1:8443`.
- Browser login/register fails.
  Check that `BROWSER_ACCOUNT_BASE_URL` points to a reachable gateway/app URL and that the hostname can be resolved by the browser path you selected.
- DNS returns `NXDOMAIN`.
  Add or fix the domain in `dns/dns_records.json`; the current DNS server does not forward misses to public DNS.

## Related Docs

- [browser/README.md](browser/README.md)
- [dns/README.md](dns/README.md)
- [vpn/README.md](vpn/README.md)
- [deploy/runbooks/single-host.md](deploy/runbooks/single-host.md)
- [deploy/runbooks/multi-host.md](deploy/runbooks/multi-host.md)

Some module-level READMEs describe earlier iterations. This top-level README is the authoritative description of the current system layout.
