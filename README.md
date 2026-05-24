# Mini Web Stack

A from-scratch web stack built with Python stdlib only. Three modules simulate the core pieces of the web: a DNS server, an HTTP server, and a GUI browser.

No frameworks. No libraries (except PySide6 for the browser GUI). Just sockets, JSON, and raw HTTP/1.1.

## Modules

| Module | Port | Protocol | Description |
|--------|------|----------|-------------|
| [DNS Server](dns/README.md) | `127.0.0.1:5336` | UDP + JSON | Static DNS resolver with TTL cache |
| [HTTP Server](http-server/README.md) | `127.0.0.1:8000` | TCP + HTTP/1.1 | Serves static files from `public/` |
| [Browser](browser/README.md) | GUI | PySide6 Qt WebEngine | Chrome-like browser with tabs, history, bookmarks, DevTools |

## Architecture

### Startup Order

Start services in this order:

```
1. DNS Server    (python3 dns/dns_server.py)
2. HTTP Server   (python3 http-server/src/server.py)
3. Browser       (python3 browser/gui/browser_gui.py)
```

### Request Flow

When the user enters `http://myweb.local/` in the browser:

```
┌─────────┐
│  User   │  enters http://myweb.local/
└────┬────┘
     │
     ▼
┌─────────────────┐
│  URL Parser     │  host=myweb.local, port=8000, path=/
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│  DNS Client     │  UDP JSON {"domain": "myweb.local"} → 127.0.0.1:5336
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│  DNS Server     │  resolves from dns_records.json → {"status":"OK","ip":"127.0.0.1"}
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│  TCP Connect    │  connect to 127.0.0.1:8000
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│  HTTP Client    │  GET / HTTP/1.1\r\nHost: myweb.local
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│  HTTP Server    │  serves public/index.html
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│  Qt WebEngine   │  renders HTML + CSS + JS
└─────────────────┘
```

### Demo Domain

The primary demo domain is `myweb.local`, which resolves to `127.0.0.1`. Additional domains are configured in [dns/dns_records.json](dns/dns_records.json):

| Domain | IP | TTL |
|--------|-----|-----|
| `myweb.local` | `127.0.0.1` | 60s |
| `example.local` | `127.0.0.1` | 5s |
| `web.local` | `127.0.0.1` | 5s |
| `api.local` | `127.0.0.1` | 8s |
| `test.local` | `192.168.1.5` | 5s |
| `httpforever.com` | `146.190.62.39` | 60s |
| `info.cern.ch` | `188.184.67.127` | 60s |
| `example.com` | `104.20.23.154` | 60s |
| `example.org` | `104.20.26.136` | 60s |
| `httpbin.org` | `34.234.10.121` | 60s |

## Quick Start

### Prerequisites

- Python 3.8+
- PySide6 (for the browser GUI)

### 1. DNS Server

```bash
cp dns/.env.example dns/.env
python3 dns/dns_server.py
```

### 2. HTTP Server

```bash
python3 http-server/src/server.py
```

### 3. Browser

```bash
pip install -r browser/requirements.txt
cp browser/.env.example browser/.env
python3 browser/gui/browser_gui.py
```

Then enter `http://myweb.local/` in the browser URL bar.

## Configuration

Each module uses a `.env` file for configuration. Copy `.env.example` to `.env` and edit as needed.

### DNS Server (`dns/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_BIND_HOST` | `0.0.0.0` | Host to bind UDP socket |
| `DNS_PORT` | `5336` | UDP port |
| `DNS_RECORDS_PATH` | `dns/dns_records.json` | Path to DNS records file |
| `DNS_DEFAULT_TTL` | `5` | Default TTL in seconds |

### HTTP Server (`http-server/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_HOST` | `0.0.0.0` | Host to bind TCP socket |
| `HTTP_PORT` | `8000` | TCP port |
| `HTTP_PUBLIC_DIR` | `public/` | Static files directory |

### Browser (`browser/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `BROWSER_DNS_HOST` | `127.0.0.1` | DNS server host |
| `BROWSER_DNS_PORT` | `5336` | DNS server port |
| `BROWSER_HTTP_DEFAULT_PORT` | `8000` | Default HTTP port for URLs without explicit port |

Environment variables override `.env` file values.

## Demo Scenarios

### Basic Page Load

1. Start all three modules in order.
2. Open the browser and enter `http://myweb.local/`.
3. Watch the page render from `public/index.html`.

### DNS Resolution

1. Enter `http://example.local/` in the browser.
2. The browser sends a UDP JSON query to the DNS server.
3. DNS resolves from `dns_records.json` and returns `127.0.0.1`.
4. The browser connects to the HTTP server and loads the page.

### 404 Handling

1. Enter `http://myweb.local/nonexistent` in the browser.
2. The HTTP server returns `404 Not Found`.
3. The browser displays its built-in error page.

### Health Check

1. Enter `http://myweb.local/health` in the browser.
2. The HTTP server returns a JSON response.

### External Domains

The DNS records include real external domains like `example.com` and `httpbin.org`. These resolve to their real IPs, so the browser can attempt to reach them (though the HTTP server only serves local content).

## Integration Test

Run the full integration smoke test (DNS + HTTP servers in-process):

```bash
python3 -m pytest tests/test_integration.py -v
```

Tests cover:
- **Happy paths**: DNS resolution, HTTP root page, health endpoint, static file with cache headers
- **Failure paths**: Unknown domain (NXDOMAIN), 404, rate limiting, method not allowed (405)

Uses test ports `5337` (DNS) and `8001` (HTTP) to avoid conflicts with dev servers.

## Failure Paths

These scenarios demonstrate error handling in the stack:

| Scenario | Command | Expected Result |
|----------|---------|-----------------|
| Unknown domain | DNS query `{"domain": "unknown.local"}` | `{"status": "NXDOMAIN"}` |
| Missing page | `curl http://127.0.0.1:8001/nonexistent` | `404 Not Found` |
| Rate limit exceeded | 11+ rapid DNS queries from same IP | `{"status": "RATE_LIMITED"}` |
| Wrong HTTP method | `curl -X POST http://127.0.0.1:8001/` | `405 Method Not Allowed` |
| Invalid JSON | Send non-JSON UDP packet to DNS | `{"status": "BAD_REQUEST"}` |
| Empty domain | DNS query `{"domain": ""}` | `{"status": "BAD_REQUEST"}` |

## Project Structure

```
web-stack/
├── README.md
├── demo.sh
├── tests/
│   └── test_integration.py
├── dns/
│   ├── README.md
│   ├── dns_server.py
│   ├── dns_cache.py
│   ├── dns_resolver.py
│   ├── rate_limiter.py
│   └── dns_records.json
├── http-server/
│   ├── README.md
│   ├── src/
│   │   ├── server.py
│   │   ├── http_parser.py
│   │   ├── http_response.py
│   │   ├── router.py
│   │   ├── config.py
│   │   └── mime_types.py
│   └── public/
│       ├── index.html
│       └── styles.css
└── browser/
    ├── README.md
    ├── gui/
    │   └── browser_gui.py
    └── core/
        ├── url_parser.py
        ├── dns_client.py
        └── http_client.py
```
