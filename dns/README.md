# DNS Module (Mini Web Stack)

## Muc tieu

Module nay mo phong DNS server don gian cho do an Mini Web Stack.

- Nhan request UDP tu client/browser.
- Phan giai `domain -> ip` tu static records.
- Co cache TTL va lazy deletion.
- Tra JSON response de client parse de dang.

## Cau truc thu muc

```text
dns/
  __init__.py
  dns_server.py
  dns_cache.py
  dns_resolver.py
  dns_records.json
```

## Vai tro tung file

- `dns/dns_server.py`: network + handler layer
  - `while True` + `socket.recvfrom()`
  - parse request an toan
  - goi cache va resolver
  - tra response JSON
- `dns/dns_cache.py`: cache layer
  - `CacheEntry(ip, expire_at, ttl)`
  - `DNSCache.get()` tra ve `HIT/MISS/EXPIRED`
  - lazy deletion khi record het han
- `dns/dns_resolver.py`: resolver layer
  - load records tu `dns_records.json`
  - normalize/validate domain
  - resolve static records
- `dns/dns_records.json`: bang domain tinh

## Flow xu ly request

1. Client gui UDP JSON: `{"domain": "example.local"}`
2. Server parse + validate request
3. Normalize domain (`strip + lower`)
4. Check cache
   - HIT: tra ngay
   - EXPIRED: xoa stale record
   - MISS: lookup resolver
5. Neu resolve duoc: update cache voi `expire_at = now + ttl`
6. Neu khong co domain: tra `NXDOMAIN`

## Mau request/response

Request:

```json
{"domain": "example.local"}
```

Response thanh cong:

```json
{"status": "OK", "domain": "example.local", "ip": "127.0.0.1", "expire_at": 1712656800.5}
```

Response loi NXDOMAIN:

```json
{"status": "NXDOMAIN", "domain": "foo.local", "ip": null, "message": "Domain not found"}
```

## Cach chay

Tu root project:

```bash
python3 dns/dns_server.py
```

Test client:

```bash
python3 test_client.py --mode demo
```

Mac dinh:

- host: `127.0.0.1`
- port: `5200`

## Demo nhanh cho buoi bao ve

1. Chay DNS server.
2. Chay `test_client.py --mode demo`.
3. Trinh bay 4 case:
   - Lan 1: `CACHE MISS`
   - Lan 2: `CACHE HIT`
   - Sau TTL: `CACHE EXPIRED` -> resolve lai
   - Domain khong ton tai: `NXDOMAIN`

## Ghi chu on dinh

- Single-thread, khong dung background cleanup thread.
- Co gioi han kich thuoc UDP packet.
- Parse UTF-8/JSON chat, khong de exception lam crash server loop.
