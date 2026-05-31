# Mini Web Stack

Mini Web Stack is a from-scratch Python web stack with five active runtime pieces:

- `dns/`: custom DNS server
- `server/app`: async application backend nodes
- `server/gateway`: async gateway and load balancer
- `vpn/`: application-layer HTTP tunnel
- `browser/`: PySide6 desktop browser

The server side uses PostgreSQL. The browser keeps only device-local runtime state on disk; profile data is encrypted client-side and synced through the app API into PostgreSQL. The active entrypoints today are:

```bash
python3 -m dns.server
python3 -m server.main
python3 -m vpn.vpn_server
python3 browser/gui/browser_gui.py
python3 start.py
```

`start.py` starts the server-side stack for local development. It does not launch the browser.

## Architecture

| Component | Entry point | Default role in the stack | Default local port |
| --- | --- | --- | --- |
| DNS server | `python3 -m dns.server` | Resolves `A` records from `dns/dns_records.json` and optional forwarded lookups | UDP `5336` locally, `53` in deployment |
| App node | `HTTP_ROLE=app python3 -m server.main` | Serves static files and app APIs; persists users/sessions/history/messages in PostgreSQL | TCP `8081` / `8082` in local cluster |
| Gateway | `HTTP_ROLE=gateway python3 -m server.main` | Round-robin proxy in front of app nodes; exposes `/health` and `/status` | TCP `8443` locally |
| VPN tunnel | `python3 -m vpn.vpn_server` | Browser-facing tunnel for raw HTTP requests | TCP `9443` |
| Browser | `python3 browser/gui/browser_gui.py` | Custom browser with DNS client, HTTP client, optional VPN, cache, cookies, and encrypted PostgreSQL-backed profile sync | GUI |

High-level request flow:

```text
Browser GUI
  -> custom DNS query -> DNS server
  -> HTTP/HTTPS page request -> gateway -> app node -> PostgreSQL
  -> optional VPN tunnel -> VPN server -> gateway/app target
  -> local cookies/cache/device key -> ~/.mini_web_browser
  -> auth/profile sync -> BROWSER_ACCOUNT_BASE_URL -> gateway/app -> PostgreSQL
```

## Repo Layout

- `browser/`: GUI app, local storage, DNS/HTTP/VPN clients
- `deploy/`: runbooks and example systemd units
- `dns/`: DNS server, cache, resolver, wire-format handling
- `http-server/public/`: static assets served by app nodes
- `server/`: app backend, gateway, shared HTTP parsing/response code
- `vpn/`: tunnel protocol and server

`http-server/public/` is still an active asset directory. The current HTTP runtime is under `server/`, not `http-server/src/`.

## Prerequisites

- Python `3.11+`
- PostgreSQL `15+`
- A GUI-capable Linux or macOS environment for the browser
- `pip` and the ability to install the packages in `requirements.txt`
- If you want DNS on port `53`, root or `CAP_NET_BIND_SERVICE`
- If you want TLS on the gateway, a certificate and private key

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Configuration Loading

- `dns/`, `vpn/`, and `server/` load the root `.env`
- `browser/` loads `browser/.env` first, then the root `.env`
- Shell environment variables override file values

Two setup details matter in practice:

- Set `HTTP_PUBLIC_DIR` to an absolute path. That avoids working-directory differences between `start.py`, manual launches, and systemd.
- Set `BROWSER_ACCOUNT_BASE_URL` to the HTTP or HTTPS endpoint you want the browser to use for `/login`, `/register`, and encrypted profile sync. For local runs, `http://127.0.0.1:8443` is the safest default.

## Data Stores

- Server-side state: PostgreSQL via `DATABASE_URL`
- Browser device-local state: cookies, cache, window state, and remembered profile key under `BROWSER_STATE_DIR`

Browser profile data is no longer stored in SQLite. Settings, bookmarks, shortcuts, and synced history are encrypted in the browser and stored in PostgreSQL through the app API.

## Local Setup

### 1. Create the database

```bash
sudo systemctl start postgresql
sudo -u postgres createuser watercat --pwprompt
sudo -u postgres createdb watercat -O watercat
```

If you want a one-command local demo user/password, this also works:

```bash
sudo -u postgres psql -c "CREATE USER watercat WITH PASSWORD 'watercat';"
sudo -u postgres psql -c "CREATE DATABASE watercat OWNER watercat;"
```

The app schema is created automatically the first time an app node starts.

### 2. Create `.env`

Copy the template:

```bash
cp .env.example .env
```

Then make sure these values exist in `.env`:

```env
DATABASE_URL=postgresql://watercat:watercat@localhost:5432/watercat

DNS_BIND_HOST=127.0.0.1
DNS_PORT=5336
DNS_RECORDS_PATH=dns/dns_records.json
DNS_RESOLVER_MODE=hybrid

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

Notes:

- `BROWSER_HTTP_DEFAULT_PORT=8443` points the browser at the local gateway cluster, which is what `start.py` brings up.
- `BROWSER_ACCOUNT_BASE_URL` can point at either an `http://` or `https://` endpoint that the browser can reach for `/login`, `/register`, and encrypted profile sync.
- The browser still keeps cookies and cache under `BROWSER_STATE_DIR`, but profile data is synced through PostgreSQL instead of a local SQLite database.
- If you set `BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS=true`, public hostnames are still rendered in Qt WebEngine through the local proxy path. `BROWSER_WEBENGINE_PROXY_HOST` and `BROWSER_WEBENGINE_PROXY_PORT` control that local proxy bind address.
- If you also create `browser/.env`, it takes precedence over the browser-related keys in the root `.env`.

### 3. Start the local stack

`start.py` starts:

1. DNS server
2. App node `app-a` on `8081`
3. App node `app-b` on `8082`
4. Gateway on `8443`
5. VPN server on `9443`

Run it from the repo root:

```bash
python3 start.py
```

Then start the browser in a second terminal:

```bash
python3 browser/gui/browser_gui.py
```

### 4. Local URLs to try

With the env above, these should work from the browser:

- `http://myweb.local/`
- `http://example.local/`
- `http://myweb.local/login`
- `http://myweb.local/register`

The built-in DNS records in `dns/dns_records.json` already map `myweb.local`, `example.local`, `web.local`, `api.local`, and `test.local` to `127.0.0.1`.

### 5. Verify each service

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

Register a user directly against one app node:

```bash
curl -i \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo123"}' \
  http://127.0.0.1:8081/auth/register
```

VPN:

- Open the browser
- Enable the VPN toggle
- Visit `http://myweb.local/`
- Open DevTools in the browser and confirm the request route shows `vpn`

### 6. Manual startup, if you want each service in its own terminal

From the repo root:

```bash
python3 -m dns.server
```

```bash
HTTP_ROLE=app \
HTTP_PORT=8081 \
HTTP_NODE_ID=app-a \
HTTP_PUBLIC_DIR=/absolute/path/to/web-stack/http-server/public \
python3 -m server.main
```

```bash
HTTP_ROLE=app \
HTTP_PORT=8082 \
HTTP_NODE_ID=app-b \
HTTP_PUBLIC_DIR=/absolute/path/to/web-stack/http-server/public \
python3 -m server.main
```

```bash
HTTP_ROLE=gateway \
HTTP_HTTPS_PORT=8443 \
HTTP_BACKENDS=127.0.0.1:8081,127.0.0.1:8082 \
python3 -m server.main
```

```bash
python3 -m vpn.vpn_server
```

```bash
python3 browser/gui/browser_gui.py
```

## Multi-Node Deployment

The intended multi-node layout is:

```text
clients
  -> DNS node
  -> optional VPN node
  -> gateway node
  -> app node A
  -> app node B
  -> shared PostgreSQL
```

The sample systemd units in `deploy/systemd/` already reflect this model.

### 1. Shared preparation

On each server that runs code:

```bash
python3 -m pip install -r requirements.txt
```

Use a stable project path such as `/opt/web-stack` and keep `http-server/public/` present on every app node.

### 2. PostgreSQL node

Create the database and user on the database host:

```bash
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE USER watercat WITH PASSWORD 'watercat';"
sudo -u postgres psql -c "CREATE DATABASE watercat OWNER watercat;"
```

Example connection string:

```text
postgresql://watercat:watercat@db.local:5432/watercat
```

### 3. App nodes

Each app node needs:

- `HTTP_ROLE=app`
- a unique `HTTP_NODE_ID`
- its own `HTTP_PORT`
- the shared `DATABASE_URL`
- an absolute `HTTP_PUBLIC_DIR`

Example for app node A:

```bash
export HTTP_ROLE=app
export HTTP_NODE_ID=app-a
export HTTP_PORT=8081
export DATABASE_URL=postgresql://watercat:watercat@db.local:5432/watercat
export HTTP_PUBLIC_DIR=/opt/web-stack/http-server/public
python3 -m server.main
```

Example for app node B:

```bash
export HTTP_ROLE=app
export HTTP_NODE_ID=app-b
export HTTP_PORT=8082
export DATABASE_URL=postgresql://watercat:watercat@db.local:5432/watercat
export HTTP_PUBLIC_DIR=/opt/web-stack/http-server/public
python3 -m server.main
```

Health check each node directly:

```bash
curl http://APP_NODE_IP:8081/health
curl http://APP_NODE_IP:8082/health
```

### 4. Gateway node

The gateway sits in front of the app nodes and proxies requests round-robin.

Example:

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

Important:

- `HTTP_HTTPS_PORT` is just the gateway listen port.
- It only speaks TLS if both `TLS_CERT_PATH` and `TLS_KEY_PATH` are set.
- Without those files, the gateway serves plain HTTP on that port.

Verify:

```bash
curl -k https://gateway.example.com/health
curl -k https://gateway.example.com/status
```

If you are not using TLS on the gateway, use plain `http://`.

### 5. DNS node

Set `DNS_RECORDS_PATH` so your application domains point to the gateway IP, then start:

```bash
export DNS_BIND_HOST=0.0.0.0
export DNS_PORT=53
export DNS_RECORDS_PATH=/opt/web-stack/dns/dns_records.json
python3 -m dns.server
```

Example record:

```json
{
  "myweb.local": { "ip": "203.0.113.10", "ttl": 60 }
}
```

For port `53`, either run under systemd with the supplied capability settings in `deploy/systemd/dns.service` or use another privileged binding strategy.

### 6. VPN node

Example:

```bash
export VPN_BIND_HOST=0.0.0.0
export VPN_PORT=9443
export VPN_TOKEN=replace-this-with-a-real-secret
export VPN_ALLOW_PRIVATE_TARGETS=false
python3 -m vpn.vpn_server
```

Use `VPN_ALLOW_PRIVATE_TARGETS=true` only if the VPN server must forward to RFC1918 or loopback targets inside your lab.

### 7. Browser clients

The browser needs to know where DNS, optional VPN, and the server-backed auth API live.

Example client config:

```env
BROWSER_DNS_HOST=DNS_NODE_IP
BROWSER_DNS_PORT=53
BROWSER_HTTP_DEFAULT_PORT=80
BROWSER_HTTPS_DEFAULT_PORT=443
BROWSER_ENABLE_VPN=true
BROWSER_VPN_HOST=VPN_NODE_IP
BROWSER_VPN_PORT=9443
BROWSER_VPN_TOKEN=replace-this-with-a-real-secret
BROWSER_ACCOUNT_BASE_URL=https://gateway.example.com
```

If you want all public hostnames to resolve through the project DNS server too, enable:

```env
BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS=true
BROWSER_WEBENGINE_PROXY_HOST=127.0.0.1
BROWSER_WEBENGINE_PROXY_PORT=8899
```

In that mode, public pages still render in Qt WebEngine, but the hostname resolution step is forced through the project DNS server and the browser routes WebEngine traffic through its local proxy.

### 8. Systemd examples

Example unit files live in `deploy/systemd/`:

- `app@.service`
- `gateway.service`
- `dns.service`
- `vpn.service`

Treat them as templates. Edit `WorkingDirectory`, `DATABASE_URL`, backend IPs, and TLS paths for your environment before enabling them.

## API and Runtime Surface

### DNS

- RFC 1035 wire format over UDP
- `A` records only
- Static file: `dns/dns_records.json`
- Resolver modes: `static`, `forward`, `hybrid`

### Gateway

- `GET /health`
- `GET /status`
- Proxies all other requests to app backends

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
- Authenticated with `VPN_TOKEN`
- Forwards raw HTTP payloads to upstream TCP/TLS targets

## Key Environment Variables

### Core

- `DATABASE_URL`: PostgreSQL connection string for app nodes
- `HTTP_PUBLIC_DIR`: absolute path to `http-server/public`
- `SKIP_DB_CHECK=1`: skip the hardcoded localhost PostgreSQL probe in `start.py`

### DNS

- `DNS_BIND_HOST`
- `DNS_PORT`
- `DNS_RECORDS_PATH`
- `DNS_RESOLVER_MODE`
- `DNS_FORWARD_TTL_SECONDS`

### App and gateway

- `HTTP_ROLE`: `app` or `gateway`
- `HTTP_HOST`
- `HTTP_PORT`: app-node port
- `HTTP_HTTPS_PORT`: gateway listen port
- `HTTP_BACKENDS`: comma-separated app backends for the gateway
- `HTTP_NODE_ID`
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
- `BROWSER_ENABLE_VPN`
- `BROWSER_VPN_HOST`
- `BROWSER_VPN_PORT`
- `BROWSER_VPN_TOKEN`
- `BROWSER_WEBENGINE_PROXY_HOST`
- `BROWSER_WEBENGINE_PROXY_PORT`
- `BROWSER_ACCOUNT_BASE_URL`
- `BROWSER_ENABLE_AI_ASSISTANT`

If you enable the AI assistant, also set the Google Vertex / `google-genai` environment variables shown in `.env.example`.

## Troubleshooting

- `start.py` reports PostgreSQL is not ready even though your DB is remote.
  Set `SKIP_DB_CHECK=1`. The probe inside `start.py` only checks `localhost:5432`.
- Static pages return `404` even though the app process is up.
  Check `HTTP_PUBLIC_DIR`. Use an absolute path.
- `curl https://...:8443` fails locally.
  The gateway only speaks TLS when `TLS_CERT_PATH` and `TLS_KEY_PATH` are both set. Otherwise `8443` is plain HTTP.
- Browser Sign In / Create Account fails only when `BROWSER_ACCOUNT_BASE_URL` points at an unreachable host or one your forced custom DNS path cannot resolve.
  Use a reachable `http://` or `https://` endpoint, and if `BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS=true`, make sure your DNS server can resolve that hostname.

## Related Docs

- [browser/README.md](browser/README.md)
- [dns/README.md](dns/README.md)
- [vpn/README.md](vpn/README.md)
- [deploy/runbooks/single-host.md](deploy/runbooks/single-host.md)

The module-level READMEs are useful for internals, but this top-level README is the authoritative setup guide for the current stack layout.
