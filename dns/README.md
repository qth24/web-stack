# DNS Module (Mini Web Stack)

## Goal

This module simulates a simple DNS server for the Mini Web Stack project.

- Receives UDP requests from clients/browsers.
- Resolves `domain -> ip` from static records first, then falls back to upstream DNS (`8.8.8.8`, `1.1.1.1`).
- Supports TTL cache with lazy deletion.
- Returns JSON responses for easy client parsing.

## Directory Structure

```text
dns/
  __init__.py
  dns_server.py
  dns_cache.py
  dns_resolver.py
  dns_records.json
```

## File Responsibilities

- `dns/dns_server.py`: network and handler layer
  - `while True` + `socket.recvfrom()` loop
  - safely parses incoming requests
  - calls cache and resolver
  - returns JSON responses
- `dns/dns_cache.py`: cache layer
  - `CacheEntry(ip, expire_at, ttl)`
  - `DNSCache.get()` returns `HIT/MISS/EXPIRED`
  - lazy deletion for expired records
- `dns/dns_resolver.py`: resolver layer
  - loads records from `dns_records.json`
  - normalizes/validates domain names
  - resolves static records first, then public DNS fallback
- `dns/dns_records.json`: static domain mapping table

## Request Processing Flow

1. Client sends UDP JSON: `{"domain": "example.local"}`
2. Server parses and validates the request
3. Normalize domain (`strip + lower`)
4. Check cache
   - HIT: return immediately
   - EXPIRED: remove stale record
   - MISS: resolve through resolver
5. Resolver order
   - static table lookup
   - upstream DNS lookup (A record) if static miss
6. If resolved: update cache with `expire_at = now + ttl`
7. If still not found: return `NXDOMAIN`

## Request/Response Examples

Request:

```json
{"domain": "example.local"}
```

Successful response:

```json
{"status": "OK", "domain": "example.local", "ip": "127.0.0.1", "expire_at": 1712656800.5}
```

NXDOMAIN error response:

```json
{"status": "NXDOMAIN", "domain": "foo.local", "ip": null, "message": "Domain not found"}
```

## How to Run

From the project root:

```bash
python3 dns/dns_server.py
```

Disable upstream fallback (static-only mode):

```bash
python3 dns/dns_server.py --disable-upstream
```

Customize upstream DNS servers:

```bash
python3 dns/dns_server.py --upstream-servers 8.8.8.8,1.1.1.1 --upstream-timeout 2.0
```

Default settings:

- host: `127.0.0.1`
- port: `5200`
- upstream DNS: `8.8.8.8`, `1.1.1.1`

## Stability Notes

- Single-threaded; no background cleanup thread.
- UDP packet size is limited.
- Strict UTF-8/JSON parsing prevents exceptions from crashing the server loop.
