# Mini Web Stack

Mini Web Stack is a from-scratch Python web stack that simulates four core pieces of the web:

- a UDP JSON DNS server,
- a raw-socket HTTP/HTTPS server,
- an application-layer VPN tunnel server,
- a PySide6/Qt WebEngine browser.

Most networking code is implemented directly with Python stdlib sockets. The browser GUI uses PySide6, and the optional AI assistant uses `google-genai` only when enabled.

## Modules

| Module | Default local address | Protocol | Description |
| --- | --- | --- | --- |
| [DNS Server](dns/README.md) | `0.0.0.0:5336` | UDP + JSON v1 | Static/hybrid/forward DNS resolver with TTL cache and per-IP rate limiting |
| [HTTP Server](http-server/README.md) | `0.0.0.0:8000`, HTTPS `0.0.0.0:8443` | TCP + HTTP/1.1 | Static file server, security headers, WAF, ETag/cache, reverse proxy |
| [VPN Server](vpn/README.md) | `0.0.0.0:9443` | TCP + JSON-line tunnel | Application-layer tunnel that forwards browser raw HTTP requests to upstream servers |
| [Browser](browser/README.md) | GUI | PySide6 Qt WebEngine | Browser with tabs, custom DNS, Mini VPN toggle, cache, cookies, incognito, DevTools, phishing detection, optional AI assistant |

## Current Features

### DNS Server

- UDP JSON v1 request/response contract.
- Supports only `A` records.
- Domain normalization and validation.
- Static records loaded from `dns/dns_records.json`.
- Resolver modes:
  - `static`: local records only.
  - `forward`: system resolver only.
  - `hybrid`: local records first, then system resolver.
- In-memory TTL cache with lazy expiry.
- Sliding-window rate limiting per client IP.
- Structured error statuses: `BAD_REQUEST`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_QTYPE`, `NXDOMAIN`, `RATE_LIMITED`, `ERROR`.

### HTTP Server

- Raw TCP HTTP/1.1 server on port `8000`.
- HTTPS server on port `8443` with generated self-signed certificate.
- Thread-per-client connection handling.
- Static files from `http-server/public`.
- `GET /` serves `index.html`.
- `GET /health` returns JSON health data.
- `404`, `405`, `400`, `500`, `501`, `502`, and `504` handling.
- Static cache with `Cache-Control`, ETag, and `304 Not Modified`.
- Security headers on responses, including CSP by default.
- Optional HSTS for HTTPS responses.
- Basic WAF for traversal, sensitive path probes, null bytes, and simple script injection probes.
- Reverse proxy/load balancer with host/path route matching, round-robin upstreams, failover, and `X-Forwarded-*` headers.

### Browser

- URL parser for `http` and `https`.
- Custom DNS loader for `localhost`, `.local`, and IPv4 hosts by default.
- Optional `BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS=true` to route all hostnames through the custom DNS client.
- Raw HTTP client for custom-loaded pages.
- Mini VPN client for routing custom-loaded requests through `vpn/vpn_server.py`.
- Toolbar/menu VPN toggle, VPN settings, and DevTools route/VPN columns.
- TLS support for HTTPS custom-loaded pages using an unverified context, useful for the local self-signed HTTPS demo.
- Multi-tab GUI with back, forward, reload, home, bookmarks, history, downloads, settings, and print to PDF.
- Normal and incognito tabs.
- Persistent cookies/session for normal browsing; in-memory cookies for incognito.
- Browser HTTP cache with freshness, ETag/Last-Modified revalidation, LRU eviction, and clear-cache action.
- DevTools panel for Network, Headers, Cookies, Inspector, Console, History, and Bookmarks.
- Phishing detection for URL and HTML content.
- Optional page-aware AI assistant backed by Gemini on Vertex AI.

### VPN Server

- TCP JSON-line tunnel protocol.
- Token authentication.
- Forwards embedded raw HTTP requests to target TCP/TLS upstreams.
- Returns raw HTTP responses to the browser.
- Private/loopback targets are allowed by default for local demos.
- Intended as an educational application-layer VPN-like tunnel, not an OS-level TUN/TAP VPN.

## Local Demo

This demo runs DNS, HTTP server, VPN server, and browser locally. AI assistant is disabled, so no Google Cloud or Gemini setup is required.

### 1. Install dependencies

```bash
cd /home/thinhdq/SourceCode/LTM/web-stack
python3 -m pip install 'PySide6>=6.7'
```

For the local demo, PySide6 is enough. `requirements.txt` also installs `google-genai` for the optional AI assistant, but that is not required when `BROWSER_ENABLE_AI_ASSISTANT=false`.

### 2. Create local `.env`

```bash
cp .env.example .env
```

Make sure these local demo values are present:

```env
DNS_BIND_HOST=0.0.0.0
DNS_PORT=5336
DNS_RECORDS_PATH=dns/dns_records.json
DNS_RESOLVER_MODE=hybrid

HTTP_HOST=0.0.0.0
HTTP_PORT=8000
HTTP_HTTPS_PORT=8443
HTTP_PUBLIC_DIR=public

VPN_BIND_HOST=0.0.0.0
VPN_PORT=9443
VPN_TOKEN=demo-token

BROWSER_DNS_HOST=127.0.0.1
BROWSER_DNS_PORT=5336
BROWSER_HTTP_DEFAULT_PORT=8000
BROWSER_HTTPS_DEFAULT_PORT=443
BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS=false
BROWSER_ENABLE_VPN=false
BROWSER_VPN_HOST=127.0.0.1
BROWSER_VPN_PORT=9443
BROWSER_VPN_TOKEN=demo-token
BROWSER_VPN_MODE=all
BROWSER_ENABLE_AI_ASSISTANT=false
```

If `BROWSER_ENABLE_AI_ASSISTANT` is not in `.env`, add it manually:

```bash
printf '\nBROWSER_ENABLE_AI_ASSISTANT=false\n' >> .env
```

### 3. Start all services

```bash
python3 start.py
```

`start.py` starts services in this order:

1. `dns/dns_server.py`
2. `http-server/src/server.py`
3. `vpn/vpn_server.py`
4. `browser/gui/browser_gui.py`

### 4. Open local demo pages

In the browser URL bar, try:

```text
http://myweb.local/
http://example.local/
http://myweb.local/health
http://myweb.local/nonexistent
```

Expected behavior:

- `myweb.local` and `example.local` resolve through the local DNS server to `127.0.0.1`.
- The browser connects to the HTTP server on port `8000` because `BROWSER_HTTP_DEFAULT_PORT=8000`.
- `/` renders `http-server/public/index.html`.
- `/health` returns JSON.
- `/nonexistent` returns a browser-rendered error page for HTTP `404`.

To demo the Mini VPN tunnel, click the `VPN` button in the browser toolbar, then open `http://httpbin.org/ip` or use Menu -> `Check VPN IP`. DevTools Network should show `Route = vpn` for custom-loaded HTTP requests.

The Mini VPN is an application-layer HTTP tunnel for this project, not a system VPN. HTTPS pages and normal Qt WebEngine tabs still use the machine network directly, so external IP checker sites opened as regular HTTPS pages can show the local IP.

Stop the stack with `Ctrl+C` in the terminal running `start.py`.

## Request Flow

When the user opens `http://myweb.local/`:

```text
User enters URL
  -> Browser URL parser
  -> Browser custom DNS decision for .local host
  -> Browser DNS client sends UDP JSON v1 query to 127.0.0.1:5336
  -> DNS server checks rate limit, TTL cache, static records, then optional forward resolver
  -> DNS server returns IP + TTL
  -> If VPN is off: Browser raw HTTP client connects to 127.0.0.1:8000
  -> If VPN is on: Browser sends the raw HTTP request through 127.0.0.1:9443
  -> VPN server forwards GET / HTTP/1.1 with Host: myweb.local to 127.0.0.1:8000
  -> HTTP server parses request, runs WAF, checks proxy routes, serves static file
  -> HTTP response returns with security/cache headers
  -> Browser handles cookies/cache/phishing checks and renders through Qt WebEngine
```

Example DNS request:

```json
{
  "version": "v1",
  "id": "req-1",
  "op": "resolve",
  "domain": "myweb.local",
  "qtype": "A"
}
```

Example successful DNS response:

```json
{
  "version": "v1",
  "id": "req-1",
  "status": "OK",
  "domain": "myweb.local",
  "qtype": "A",
  "ip": "127.0.0.1",
  "ttl": 60
}
```

## Demo Domains

The main local domains in `dns/dns_records.json` currently point to `127.0.0.1`:

| Domain | IP | TTL |
| --- | --- | --- |
| `myweb.local` | `127.0.0.1` | 60s |
| `example.local` | `127.0.0.1` | 60s |
| `web.local` | `127.0.0.1` | 60s |
| `api.local` | `127.0.0.1` | 60s |
| `test.local` | `127.0.0.1` | 60s |

The records file also contains many public domains with static IP/TTL values for resolver demos. In `hybrid` mode, domains missing from the static file can be resolved through the host operating system resolver and cached with `DNS_FORWARD_TTL_SECONDS`.

## Configuration

All four modules load the root `.env` file. Environment variables override file values.

| Variable | Default in `.env.example` | Description |
| --- | --- | --- |
| `DNS_BIND_HOST` | `0.0.0.0` | UDP bind host |
| `DNS_PORT` | `5336` | UDP DNS port for local development |
| `DNS_RECORDS_PATH` | `dns/dns_records.json` | Static record file |
| `DNS_DEFAULT_TTL` | `5` | Fallback TTL for simple string records |
| `DNS_RESOLVER_MODE` | `hybrid` | `static`, `forward`, or `hybrid` |
| `DNS_FORWARD_TTL_SECONDS` | `60` | TTL for forwarded answers |
| `DNS_RATE_LIMIT_MAX_QUERIES` | `10` | Queries allowed per window per IP |
| `DNS_RATE_LIMIT_WINDOW_SECONDS` | `10` | Rate-limit window in seconds |
| `HTTP_HOST` | `0.0.0.0` | HTTP/HTTPS bind host |
| `HTTP_PORT` | `8000` | HTTP port |
| `HTTP_HTTPS_PORT` | `8443` | HTTPS port |
| `HTTP_PUBLIC_DIR` | `public` | Static file directory relative to `http-server/` |
| `HTTP_CACHE_TTL` | `60` | Static cache max-age and in-memory TTL |
| `HTTP_ENABLE_CSP` | `true` | Add Content-Security-Policy |
| `HTTP_ENABLE_WAF` | `true` | Enable basic WAF checks |
| `HTTP_PROXY_ROUTES_PATH` | `proxy_routes.json` | Reverse proxy route file relative to `http-server/` |
| `VPN_BIND_HOST` | `0.0.0.0` | VPN tunnel TCP bind host |
| `VPN_PORT` | `9443` | VPN tunnel TCP port |
| `VPN_TOKEN` | `demo-token` | Shared token required by browser clients |
| `VPN_ALLOW_PRIVATE_TARGETS` | `true` | Allow loopback/private upstream targets for local demos |
| `BROWSER_DNS_HOST` | `127.0.0.1` | DNS server used by browser custom loader |
| `BROWSER_DNS_PORT` | `5336` | DNS UDP port used by browser |
| `BROWSER_ENABLE_DNS_CACHE` | `true` | Browser-side DNS TTL cache |
| `BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS` | `false` | Route every hostname through custom DNS |
| `BROWSER_HTTP_DEFAULT_PORT` | `8000` | Default port for `http://host/` custom-loaded URLs |
| `BROWSER_HTTPS_DEFAULT_PORT` | `443` | Default port for `https://host/` custom-loaded URLs |
| `BROWSER_ENABLE_VPN` | `false` | Route custom-loaded requests through Mini VPN |
| `BROWSER_VPN_HOST` | `127.0.0.1` | VPN server host used by the browser |
| `BROWSER_VPN_PORT` | `9443` | VPN server TCP port used by the browser |
| `BROWSER_VPN_TOKEN` | `demo-token` | Browser token sent to VPN server |
| `BROWSER_VPN_MODE` | `all` | `all` or `domains` routing mode for custom-loaded requests |
| `BROWSER_VPN_DOMAINS` | `.local,localhost` | Domain rules used when `BROWSER_VPN_MODE=domains` |
| `BROWSER_ENABLE_HTTP_CACHE` | `true` | Browser disk-backed HTTP cache |
| `BROWSER_ENABLE_PHISHING_DETECTION` | `true` | Browser phishing checks |
| `BROWSER_ENABLE_AI_ASSISTANT` | `false` | Keep disabled for local demo without Google Cloud/Gemini setup |

## Run Modules Separately

DNS only:

```bash
python3 dns/dns_server.py --host 0.0.0.0 --port 5336
```

HTTP/HTTPS server only:

```bash
python3 http-server/src/server.py
```

VPN server only:

```bash
python3 vpn/vpn_server.py
```

Browser only:

```bash
python3 browser/gui/browser_gui.py
```

## Tests

The repo uses `unittest` tests under each module.

Run all tests:

```bash
python3 -m unittest discover -s dns -p 'test*.py'
python3 -m unittest discover -s http-server/src -p 'test*.py'
python3 -m unittest discover -s vpn -p 'test*.py'
python3 -m unittest discover -s browser -p 'test*.py'
```

Coverage includes:

- DNS cache, resolver modes, protocol validation, request handler errors, rate limiting, and UDP smoke test.
- HTTP parser/response builder, routing, static files, MIME types, ETag/304, security headers, WAF, reverse proxy, round-robin, and proxy errors.
- VPN protocol, token auth, TCP tunnel forwarding, and browser VPN client parsing.
- Browser DNS client, host routing, cookies, HTTP cache, VPN route selection, phishing detection, and assistant prompt/context helpers.

## Project Structure

```text
web-stack/
├── README.md
├── .env.example
├── requirements.txt
├── start.py
├── dns/
│   ├── README.md
│   ├── config.py
│   ├── dns_cache.py
│   ├── dns_records.json
│   ├── dns_resolver.py
│   ├── dns_server.py
│   ├── protocol.py
│   ├── rate_limiter.py
│   └── test_dns.py
├── http-server/
│   ├── README.md
│   ├── proxy_routes.json
│   ├── public/
│   │   ├── index.html
│   │   └── styles.css
│   └── src/
│       ├── config.py
│       ├── http_parser.py
│       ├── http_response.py
│       ├── mime_types.py
│       ├── proxy.py
│       ├── router.py
│       ├── security.py
│       ├── server.py
│       ├── static_cache.py
│       └── test_http_server.py
├── vpn/
│   ├── README.md
│   ├── __init__.py
│   ├── config.py
│   ├── protocol.py
│   ├── test_vpn.py
│   └── vpn_server.py
└── browser/
    ├── README.md
    ├── test_dns_client.py
    ├── test_host_routing.py
    ├── assets/
    ├── core/
    │   ├── assistant.py
    │   ├── config.py
    │   ├── cookies.py
    │   ├── dns_client.py
    │   ├── host_routing.py
    │   ├── http_cache.py
    │   ├── http_client.py
    │   ├── phishing.py
    │   ├── url_parser.py
    │   └── vpn_client.py
    ├── gui/
    │   └── browser_gui.py
    └── tests/
```
