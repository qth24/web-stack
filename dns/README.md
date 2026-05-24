# DNS Module (Mini Web Stack)

## Goal

This module simulates a simple DNS server for the Mini Web Stack project.

- Receives UDP JSON v1 requests from clients/browsers.
- Resolves `domain -> ip` from a static records table.
- Supports TTL cache with lazy deletion.
- Returns JSON responses for easy client parsing.

## Directory Structure

```text
dns/
  __init__.py
  dns_server.py
  dns_cache.py
  protocol.py
  dns_resolver.py
  test_dns.py
  dns_records.json
```

## File Responsibilities

- `dns/dns_server.py`: network and handler layer
  - `while True` + `socket.recvfrom()` loop
  - safely parses incoming UDP JSON v1 requests
  - calls cache and resolver
  - returns JSON responses
- `dns/protocol.py`: JSON contract layer
  - validates `version`, `id`, `op`, `domain`, and `qtype`
  - normalizes request fields
  - builds success/error response payloads
- `dns/dns_cache.py`: cache layer
  - `CacheEntry(ip, expire_at, ttl)`
  - `DNSCache.get()` returns `HIT/MISS/EXPIRED`
  - lazy deletion for expired records
- `dns/dns_resolver.py`: resolver layer
  - loads records from `dns_records.json`
  - normalizes/validates domain names
  - resolves only from the static records table
- `dns/dns_records.json`: static domain mapping table

## Request Processing Flow

1. Client sends UDP JSON v1:
   `{"version":"v1","id":"req-1","op":"resolve","domain":"example.local","qtype":"A"}`
2. Server parses and validates the request envelope
3. Normalize domain (`strip + lower + remove trailing dot`)
4. Check cache
   - HIT: return immediately
   - EXPIRED: remove stale record
   - MISS: resolve through resolver
5. Resolver checks the static table
6. If resolved: update cache with `expire_at = now + ttl`
7. If still not found: return `NXDOMAIN`

## Request/Response Examples

Request:

```json
{
  "version": "v1",
  "id": "req-1",
  "op": "resolve",
  "domain": "example.local",
  "qtype": "A"
}
```

Successful response:

```json
{
  "version": "v1",
  "id": "req-1",
  "status": "OK",
  "domain": "example.local",
  "qtype": "A",
  "ip": "127.0.0.1",
  "ttl": 60
}
```

NXDOMAIN error response:

```json
{
  "version": "v1",
  "id": "req-2",
  "status": "NXDOMAIN",
  "domain": "foo.local",
  "qtype": "A",
  "ip": null,
  "ttl": null,
  "message": "Domain not found"
}
```

## How to Run

From the project root:

```bash
cp .env.example .env
python3 dns/dns_server.py
```

Edit `.env` to configure the server:

```env
DNS_BIND_HOST=0.0.0.0
DNS_PORT=5336
DNS_RECORDS_PATH=dns/dns_records.json
DNS_DEFAULT_TTL=5
```

Environment variables override values in `.env`. CLI arguments still work for one-off overrides.

Use `DNS_PORT=5336` for local development without `sudo`. Use `DNS_PORT=53` on a VPS/production DNS server.

Bind to a specific address/port:

```bash
python3 dns/dns_server.py --host 0.0.0.0 --port 53
```

Use another records file:

```bash
python3 dns/dns_server.py --records /path/to/dns_records.json
```

## VPS Usage

1. Put this DNS module on the VPS.
2. Copy `.env.example` to `.env`.
3. Edit `.env` and `dns_records.json` so each domain points to the HTTP server IP.
4. Run `python3 dns/dns_server.py`.
5. Open the configured UDP port in the VPS firewall/security group.
6. Configure the browser with the VPS IP in `.env`, for example:

```env
BROWSER_DNS_HOST=YOUR_VPS_IP
BROWSER_DNS_PORT=53
```

On Linux, binding to UDP port `53` may require elevated permission or a service capability.

## Stability Notes

- Single-threaded; no background cleanup thread.
- UDP packet size is limited.
- Strict UTF-8/JSON parsing prevents exceptions from crashing the server loop.
- This server is intentionally authoritative/static-only; unknown domains return `NXDOMAIN`.
- Only `qtype: "A"` is supported in the current JSON v1 contract.
