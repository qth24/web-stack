# Mini Web Stack Remediation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the Mini Web Stack into a server-centric, multi-host deployment with RFC 1035 DNS, PostgreSQL-backed auth, proper concurrency, verified TLS, and load-balanced HTTP gateway/app roles.

**Architecture:** DNS server rewritten to RFC 1035 wire format. HTTP server split into gateway (TLS termination + reverse proxy) and app backend (routes + DB). PostgreSQL replaces SQLite for shared state. ThreadPoolExecutor replaces unbounded threads. AES-GCM replaces XOR crypto.

**Tech Stack:** Python 3 stdlib, dnslib, psycopg, cryptography, PySide6, google-genai

---

### Task 1: Install New Dependencies

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1: Add dependencies to requirements.txt**

```bash
pip install dnslib psycopg[binary] cryptography
echo "dnslib>=0.9.25" >> requirements.txt
echo "psycopg[binary]>=3.2" >> requirements.txt
echo "cryptography>=42.0" >> requirements.txt
```

- [ ] **Step 2: Verify imports work**

```python
python3 -c "import dnslib; print(dnslib.DNSLabel('example.com'))"
python3 -c "import psycopg; print(psycopg.__version__)"
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('ok')"
```

- [ ] **Step 3: Commit**

```bash
git add requirements.txt && git commit -m "chore: add dnslib, psycopg, cryptography deps"
```

---

### Task 2: DNS Wire Protocol — encode/decode

**Files:**
- Create: `dns/wire.py`
- Create: `dns/tests/test_wire.py`

- [ ] **Step 1: Write tests for wire protocol**

```python
# dns/tests/test_wire.py
import unittest
import struct
from dns.wire import encode_query, decode_query, encode_response, encode_error, QueryInfo

class TestWireProtocol(unittest.TestCase):
    def setUp(self):
        self.domain = b"example.com"
        self.qtype_a = 1
        self.qclass_in = 1

    def test_encode_query_produces_valid_dns_packet(self):
        packet = encode_query(self.domain, self.qtype_a)
        self.assertIsInstance(packet, bytes)
        self.assertGreaterEqual(len(packet), 12)
        tid = struct.unpack("!H", packet[:2])[0]
        self.assertGreater(tid, 0)

    def test_encode_query_different_ids(self):
        p1 = encode_query(self.domain, self.qtype_a)
        p2 = encode_query(self.domain, self.qtype_a)
        self.assertNotEqual(struct.unpack("!H", p1[:2])[0], struct.unpack("!H", p2[:2])[0])

    def test_decode_query_parses_valid_packet(self):
        packet = encode_query(self.domain, self.qtype_a)
        info = decode_query(packet)
        self.assertIsNotNone(info)
        self.assertEqual(info.domain, b"example.com")
        self.assertEqual(info.qtype, self.qtype_a)
        self.assertEqual(info.qclass, self.qclass_in)

    def test_decode_query_rejects_bad_truncated_packet(self):
        info = decode_query(b"\x00\x00")
        self.assertIsNone(info)

    def test_decode_query_extracts_transaction_id(self):
        from dnslib import DNSRecord
        q = DNSRecord.question("test.local")
        packet = bytes(q.pack())
        info = decode_query(packet)
        self.assertEqual(info.transaction_id, q.header.id)
        self.assertEqual(info.domain, b"test.local")

    def test_encode_response_builds_answer(self):
        packet = encode_query(self.domain, self.qtype_a)
        info = decode_query(packet)
        resp = encode_response(info, [(b"example.com", 1, 1, 300, b"\x7f\x00\x00\x01")])
        self.assertGreater(len(resp), len(packet))

    def test_encode_response_includes_answers(self):
        info = QueryInfo(1234, b"myweb.local", 1, 1)
        resp = encode_response(info, [(b"myweb.local", 1, 1, 60, b"\x0a\xb2\x34\x80")])
        record = decode_query(resp)
        self.assertIsNotNone(record)

    def test_encode_error_returns_nxdomain(self):
        info = QueryInfo(42, b"missing.local", 1, 1)
        packet = encode_error(info, 3)
        self.assertGreater(len(packet), 12)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest dns/tests/test_wire.py -v`
Expected: FAIL (no `dns/wire.py` module)

- [ ] **Step 3: Implement wire protocol**

```python
# dns/wire.py
"""RFC 1035 binary wire format encode/decode using dnslib."""

import struct
from dataclasses import dataclass
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, CLASS

@dataclass
class QueryInfo:
    transaction_id: int
    domain: bytes
    qtype: int
    qclass: int


def encode_query(domain: bytes, qtype: int = QTYPE.A) -> bytes:
    q = DNSRecord.question(domain.decode("ascii"), qtype=qtype)
    return bytes(q.pack())


def decode_query(packet: bytes) -> QueryInfo | None:
    try:
        record = DNSRecord.parse(packet)
        if not record.questions:
            return None
        q = record.questions[0]
        return QueryInfo(
            transaction_id=record.header.id,
            domain=q.qname.label if hasattr(q.qname, 'label') else str(q.qname).encode(),
            qtype=q.qtype,
            qclass=q.qclass,
        )
    except Exception:
        return None


def encode_response(
    info: QueryInfo,
    answers: list[tuple[bytes, int, int, int, bytes]],
) -> bytes:
    rrs = []
    for name, rtype, rclass, ttl, rdata in answers:
        rrs.append(RR(
            rname=name.decode("ascii"),
            rtype=rtype,
            rclass=rclass,
            ttl=ttl,
            rdata=dnslib.A(socket.inet_ntoa(rdata)) if rtype == QTYPE.A else rdata,
        ))
    header = DNSHeader(
        id=info.transaction_id,
        qr=1, aa=1, ra=0, opcode=0,
        rcode=0,
    )
    record = DNSRecord(
        header=header,
        questions=[DNSQuestion(info.domain.decode("ascii"), qtype=info.qtype, qclass=info.qclass)],
        rr=rrs,
    )
    return bytes(record.pack())


def encode_error(info: QueryInfo, rcode: int) -> bytes:
    header = DNSHeader(
        id=info.transaction_id,
        qr=1, aa=1, ra=0, opcode=0,
        rcode=rcode,
    )
    record = DNSRecord(
        header=header,
        questions=[DNSQuestion(info.domain.decode("ascii"), qtype=info.qtype, qclass=info.qclass)],
    )
    return bytes(record.pack())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest dns/tests/test_wire.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add dns/wire.py dns/tests/test_wire.py && git commit -m "feat: add RFC 1035 wire format encode/decode"
```

---

### Task 3: DNS Server — Rewrite with Wire Format

**Files:**
- Create: `dns/server.py` (replaces `dns/dns_server.py`)
- Create: `dns/resolver.py` (replaces `dns/dns_resolver.py`)
- Modify: `dns/config.py`
- Create: `dns/tests/test_server.py`

- [ ] **Step 1: Rewrite DNS resolver (static-only authoritative)**

```python
# dns/resolver.py
"""Static authoritative DNS resolver."""
import json
from typing import Optional

class StaticResolver:
    def __init__(self, records_path: str):
        with open(records_path) as f:
            raw = json.load(f)
        self._zone: dict[bytes, tuple[str, int]] = {}
        for domain, value in raw.items():
            domain_bytes = domain.encode("ascii")
            if isinstance(value, str):
                self._zone[domain_bytes] = (value, 300)
            elif isinstance(value, dict):
                self._zone[domain_bytes] = (value.get("ip", ""), value.get("ttl", 300))

    def resolve(self, domain: bytes) -> Optional[tuple[str, int]]:
        return self._zone.get(domain.lower(), None)

    def has_domain(self, domain: bytes) -> bool:
        return domain.lower() in self._zone
```

- [ ] **Step 2: Rewrite DNS server with ThreadPoolExecutor**

```python
# dns/server.py
"""RFC 1035 DNS server with bounded ThreadPoolExecutor."""
import socket
import signal
import threading
from concurrent.futures import ThreadPoolExecutor
from dns.config import DNS_BIND_HOST, DNS_PORT, DNS_RECORDS_PATH, DNS_MAX_WORKERS, DNS_RATE_LIMIT_ENABLED, DNS_RATE_LIMIT_MAX, DNS_RATE_LIMIT_WINDOW
from dns.wire import QueryInfo, encode_query, decode_query, encode_response, encode_error
from dns.resolver import StaticResolver
from dns.cache import DNSCache
from dns.rate_limiter import RateLimiter
from dnslib import QTYPE, CLASS, RCODE

class DNSServer:
    def __init__(self):
        self._resolver = StaticResolver(DNS_RECORDS_PATH)
        self._cache = DNSCache()
        self._rate_limiter = RateLimiter(DNS_RATE_LIMIT_MAX, DNS_RATE_LIMIT_WINDOW) if DNS_RATE_LIMIT_ENABLED else None
        self._executor = ThreadPoolExecutor(max_workers=DNS_MAX_WORKERS)
        self._shutdown = threading.Event()
        self._sock: socket.socket | None = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((DNS_BIND_HOST, DNS_PORT))
        print(f"[DNS] listening on {DNS_BIND_HOST}:{DNS_PORT}")
        signal.signal(signal.SIGTERM, lambda s, f: self.stop())
        signal.signal(signal.SIGINT, lambda s, f: self.stop())
        while not self._shutdown.is_set():
            try:
                self._sock.settimeout(1.0)
                data, addr = self._sock.recvfrom(4096)
                self._executor.submit(self._handle_query, data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._shutdown.set()
        self._executor.shutdown(wait=True)
        if self._sock:
            self._sock.close()

    def _handle_query(self, data: bytes, addr: tuple[str, int]):
        client_ip = addr[0]
        if self._rate_limiter and self._rate_limiter.is_rate_limited(client_ip):
            return
        info = decode_query(data)
        if info is None:
            return
        response = self._resolve(info)
        if response:
            try:
                self._sock.sendto(response, addr)
            except OSError:
                pass

    def _resolve(self, info: QueryInfo) -> bytes | None:
        if info.qtype != QTYPE.A or info.qclass != CLASS.IN:
            return encode_error(info, RCODE.NOTIMP)
        if not self._resolver.has_domain(info.domain):
            return encode_error(info, RCODE.NXDOMAIN)
        cached = self._cache.get(info.domain)
        if cached:
            return encode_response(info, [(info.domain, QTYPE.A, CLASS.IN, cached.ttl, cached.ip)])
        result = self._resolver.resolve(info.domain)
        if result is None:
            return encode_error(info, RCODE.NXDOMAIN)
        ip, ttl = result
        self._cache.put(info.domain, ip, ttl)
        import socket as sock
        packed_ip = sock.inet_aton(ip)
        return encode_response(info, [(info.domain, QTYPE.A, CLASS.IN, ttl, packed_ip)])
```

- [ ] **Step 3: Update DNS config**

```python
# dns/config.py (add at end)
DNS_MAX_WORKERS = int(os.getenv("DNS_MAX_WORKERS", "8"))
```

- [ ] **Step 4: Write server integration tests**

```python
# dns/tests/test_server.py
import unittest
import socket
import threading
import time
from dns.server import DNSServer
from dns.wire import encode_query, decode_query

class TestDNSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = DNSServer()
        cls._thread = threading.Thread(target=cls.server.start, daemon=True)
        cls._thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _send_query(self, domain: bytes, timeout=2.0) -> bytes | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            packet = encode_query(domain)
            sock.sendto(packet, ("127.0.0.1", 53))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return data
        except socket.timeout:
            return None

    def test_known_domain_returns_answer(self):
        data = self._send_query(b"myweb.local")
        self.assertIsNotNone(data)

    def test_unknown_domain_returns_nxdomain(self):
        data = self._send_query(b"nonexistent.zzz.local")
        self.assertIsNotNone(data)
        from dnslib import DNSRecord
        record = DNSRecord.parse(data)
        self.assertEqual(record.header.rcode, 3)  # NXDOMAIN

    def test_rate_limiting_drops_excess_queries(self):
        failures = 0
        for _ in range(20):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            packet = encode_query(b"myweb.local")
            sock.sendto(packet, ("127.0.0.1", 53))
            try:
                sock.recvfrom(4096)
            except socket.timeout:
                failures += 1
            sock.close()
        self.assertGreater(failures, 0)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 5: Run server tests**

Run: `python3 -m pytest dns/tests/test_server.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add dns/server.py dns/resolver.py dns/config.py dns/tests/test_server.py && git commit -m "feat: rewrite DNS server with RFC 1035 wire format and ThreadPoolExecutor"
```

---

### Task 4: DNS Cache and Rate Limiter Port

**Files:**
- Create: `dns/cache.py` (from `dns/dns_cache.py`)
- Modify: `dns/rate_limiter.py` (keep as-is, works unchanged)
- Remove: `dns/dns_server.py`, `dns/dns_resolver.py`, `dns/dns_cache.py`, `dns/protocol.py` (no longer needed)

- [ ] **Step 1: Port DNS cache to use wire-format keys**

```python
# dns/cache.py
"""TTL-based in-memory DNS response cache."""
import time
from typing import Optional
from dataclasses import dataclass

@dataclass
class CacheEntry:
    ip: bytes
    ttl: int
    created_at: float

class DNSCache:
    def __init__(self):
        self._store: dict[bytes, CacheEntry] = {}

    def get(self, domain: bytes) -> Optional[CacheEntry]:
        entry = self._store.get(domain)
        if entry is None:
            return None
        if time.time() - entry.created_at > entry.ttl:
            del self._store[domain]
            return None
        return entry

    def put(self, domain: bytes, ip: str, ttl: int):
        import socket
        self._store[domain] = CacheEntry(
            ip=socket.inet_aton(ip),
            ttl=ttl,
            created_at=time.time(),
        )
```

- [ ] **Step 2: Remove old DNS files**

```bash
git rm dns/dns_server.py dns/dns_resolver.py dns/dns_cache.py dns/protocol.py
```

- [ ] **Step 3: Update start.py to use new DNS server**

Read `start.py` and update the DNS launch function to import from `dns.server` (DNSServer class) instead of `dns_server`.

- [ ] **Step 4: Commit**

```bash
git add dns/cache.py && git rm dns/dns_server.py dns/dns_resolver.py dns/dns_cache.py dns/protocol.py && git commit -m "refactor: port DNS cache, remove old JSON protocol"
```

---

### Task 5: Shared HTTP Utilities — parser, response, security, mime, static, workers

**Files:**
- Create: `server/__init__.py`
- Create: `server/shared/__init__.py`
- Create: `server/shared/parser.py` (from `http-server/src/http_parser.py`)
- Create: `server/shared/response.py` (from `http-server/src/http_response.py`)
- Create: `server/shared/security.py` (from `http-server/src/security.py`)
- Create: `server/shared/mime.py` (from `http-server/src/mime_types.py`)
- Create: `server/shared/static.py` (from `http-server/src/static_cache.py`)
- Create: `server/shared/workers.py`

- [ ] **Step 1: Copy parser with chunked decoding support**

```python
# server/shared/parser.py
"""HTTP/1.1 request parser with chunked transfer-encoding support."""
import iso8601

def parse_request(data: bytes) -> dict:
    """Parse raw HTTP request bytes into dict with method, target, version, headers, body."""
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return {"method": "GET", "target": "/", "http_version": "HTTP/1.1", "headers": {}, "body": b"", "body_bytes": 0}
    header_bytes = data[:header_end]
    body_bytes = data[header_end + 4:]
    lines = header_bytes.split(b"\r\n")
    request_line = lines[0].decode("iso-8859-1").split(" ")
    method = request_line[0]
    target = request_line[1] if len(request_line) > 1 else "/"
    version = request_line[2] if len(request_line) > 2 else "HTTP/1.1"
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            key, val = line.decode("iso-8859-1").split(":", 1)
            headers[key.strip().lower()] = val.strip()
    content_length = int(headers.get("content-length", "0"))
    body = body_bytes[:content_length] if content_length else b""
    return {
        "method": method,
        "target": target,
        "http_version": version,
        "headers": headers,
        "body": body,
        "body_bytes": content_length,
    }


def decode_chunked_body(raw_body: bytes) -> bytes:
    """Decode chunked transfer-encoded body."""
    result = bytearray()
    pos = 0
    while pos < len(raw_body):
        line_end = raw_body.find(b"\r\n", pos)
        if line_end == -1:
            break
        chunk_size = int(raw_body[pos:line_end], 16)
        if chunk_size == 0:
            break
        pos = line_end + 2
        result.extend(raw_body[pos:pos + chunk_size])
        pos += chunk_size + 2
    return bytes(result)
```

- [ ] **Step 2: Copy response builder with streaming support**

```python
# server/shared/response.py
"""HTTP/1.1 response builder with streaming iterator support."""
from typing import Iterator

class BodyIterator:
    def __init__(self, iterable: Iterator[bytes]):
        self._iter = iterable

    def __iter__(self):
        return self._iter

    def __next__(self):
        return next(self._iter)

class Response:
    def __init__(self, status_code=200, body=b"", headers=None, body_iter=None):
        self.status_code = status_code
        self.body = body if not body_iter else None
        self.headers = headers or {}
        self.body_iter = body_iter

PROTO = "HTTP/1.1"
STATUS = {
    200: "200 OK", 201: "201 Created", 204: "204 No Content",
    301: "301 Moved Permanently", 302: "302 Found", 304: "304 Not Modified",
    400: "400 Bad Request", 401: "401 Unauthorized", 403: "403 Forbidden",
    404: "404 Not Found", 405: "405 Method Not Allowed", 409: "409 Conflict",
    422: "422 Unprocessable Content", 429: "429 Too Many Requests",
    500: "500 Internal Server Error", 501: "501 Not Implemented",
    502: "502 Bad Gateway", 503: "503 Service Unavailable", 504: "504 Gateway Timeout",
}

def build_response(resp: Response) -> bytes:
    status = STATUS.get(resp.status_code, f"{resp.status_code} Unknown")
    lines = [f"{PROTO} {status}"]
    if resp.body is not None:
        resp.headers.setdefault("content-length", str(len(resp.body)))
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    header_block = "\r\n".join(lines) + "\r\n\r\n"
    if resp.body is not None:
        return header_block.encode() + (resp.body if isinstance(resp.body, bytes) else resp.body.encode())
    return header_block.encode()


def stream_response(status_code: int, headers: dict, body_iter: BodyIterator) -> bytes:
    """Build initial response headers for streaming; caller handles body chunks."""
    return build_response(Response(status_code=status_code, headers=headers, body_iter=body_iter))
```

- [ ] **Step 3: Copy security headers + WAF**

```python
# server/shared/security.py
"""Security headers and WAF middleware."""
import re

WAF_RULES = [
    (re.compile(rb"\.\./"), "path traversal"),
    (re.compile(rb"\.\.\%2[fF]"), "encoded path traversal"),
    (re.compile(rb"/\.git"), ".git access"),
    (re.compile(rb"/\.env"), ".env access"),
    (re.compile(rb"<script", re.IGNORECASE), "XSS attempt"),
    (re.compile(rb"union\s+select", re.IGNORECASE), "SQL injection"),
]

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-xss-protection": "1; mode=block",
    "referrer-policy": "strict-origin-when-cross-origin",
    "server": "MiniWebStack/2.0",
}

def waf_check(target: str, headers: dict) -> str | None:
    target_bytes = target.encode("utf-8", errors="replace")
    for rule, msg in WAF_RULES:
        if rule.search(target_bytes):
            return msg
    for key_val in headers.values():
        for rule, msg in WAF_RULES:
            if rule.search(key_val.encode("utf-8", errors="replace")):
                return msg
    return None

def apply_security(response_headers: dict):
    for k, v in SECURITY_HEADERS.items():
        response_headers.setdefault(k, v)
```

- [ ] **Step 4: Copy MIME types and static file serving**

```python
# server/shared/mime.py
MIME_MAP = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
}

def get_mime(path: str) -> str:
    for ext, mime in MIME_MAP.items():
        if path.lower().endswith(ext):
            return mime
    return "application/octet-stream"
```

```python
# server/shared/static.py
"""Static file serving with streaming."""
import os
import hashlib
from server.shared.mime import get_mime
from server.shared.response import Response

CHUNK_SIZE = 8192
PUBLIC_DIR = None

def serve_static(target: str) -> Response | None:
    global PUBLIC_DIR
    if PUBLIC_DIR is None:
        return Response(404, body=b"Not Found")
    clean = os.path.normpath(target).lstrip("/")
    filepath = os.path.join(PUBLIC_DIR, clean)
    real = os.path.realpath(filepath)
    if not real.startswith(os.path.realpath(PUBLIC_DIR)):
        return None
    if not os.path.isfile(real):
        return None
    mime = get_mime(real)
    with open(real, "rb") as f:
        content = f.read()
    etag = hashlib.md5(content).hexdigest()
    return Response(200, body=content, headers={
        "content-type": mime,
        "etag": f'"{etag}"',
        "cache-control": "public, max-age=3600",
    })
```

- [ ] **Step 5: Create worker pool factory**

```python
# server/shared/workers.py
"""ThreadPoolExecutor factory with graceful shutdown."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

def create_pool(max_workers: int = 16) -> tuple[ThreadPoolExecutor, Event]:
    return ThreadPoolExecutor(max_workers=max_workers), Event()
```

- [ ] **Step 6: Commit**

```bash
git add server/ && git commit -m "feat: add shared HTTP utilities with chunked decoding and streaming"
```

---

### Task 6: PostgreSQL Database Layer

**Files:**
- Create: `server/app/db.py`
- Create: `server/app/models.py`
- Modify: `.env` and `.env.example`

- [ ] **Step 1: Add DB env vars**

Add to `.env`:
```bash
DATABASE_URL=postgresql://watercat:watercat@localhost:5432/watercat
```

- [ ] **Step 2: Implement connection pool**

```python
# server/app/db.py
"""PostgreSQL connection pool."""
import os
from psycopg_pool import ConnectionPool

_pool: ConnectionPool | None = None

def get_pool(min_size: int = 2, max_size: int = 8) -> ConnectionPool:
    global _pool
    if _pool is None:
        url = os.getenv("DATABASE_URL", "postgresql://watercat:watercat@localhost:5432/watercat")
        _pool = ConnectionPool(url, min_size=min_size, max_size=max_size, open=True)
    return _pool

def close_pool():
    global _pool
    if _pool:
        _pool.close()
        _pool = None

def init_schema():
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(64) UNIQUE NOT NULL,
                display_name VARCHAR(128),
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(64) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                title TEXT,
                visited_at TIMESTAMP DEFAULT NOW()
            );
        """)
```

- [ ] **Step 3: Implement models**

```python
# server/app/models.py
"""Database operations for users, sessions, history."""
import hashlib
import secrets
import datetime
from server.app.db import get_pool

def create_user(username: str, password_hash: str, password_salt: str, display_name: str = None) -> int:
    pool = get_pool()
    with pool.connection() as conn:
        result = conn.execute(
            "INSERT INTO users (username, password_hash, password_salt, display_name) VALUES (%s, %s, %s, %s) RETURNING id",
            (username, password_hash, password_salt, display_name or username),
        )
        return result.fetchone()[0]

def get_user_by_username(username: str) -> dict | None:
    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id, username, display_name, password_hash, password_salt, created_at FROM users WHERE username = %s",
            (username,),
        ).fetchone()
        if row is None:
            return None
        return {"id": row[0], "username": row[1], "display_name": row[2], "password_hash": row[3], "password_salt": row[4], "created_at": row[5]}

def get_user_by_id(user_id: int) -> dict | None:
    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id, username, display_name, password_hash, password_salt, created_at FROM users WHERE id = %s",
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        return {"id": row[0], "username": row[1], "display_name": row[2], "password_hash": row[3], "password_salt": row[4], "created_at": row[5]}

def create_session(user_id: int, expires_hours: int = 24) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=expires_hours)
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
            (user_id, token_hash, expires_at),
        )
    return token

def validate_session_token(token: str) -> dict | None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """SELECT u.id, u.username, u.display_name FROM users u
               JOIN sessions s ON u.id = s.user_id
               WHERE s.token_hash = %s AND s.expires_at > NOW()""",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        return {"id": row[0], "username": row[1], "display_name": row[2]}

def delete_session(token: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = %s", (token_hash,))

def add_history(user_id: int, url: str, title: str = None):
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO history (user_id, url, title) VALUES (%s, %s, %s)",
            (user_id, url, title),
        )

def get_history(user_id: int, limit: int = 50) -> list[dict]:
    pool = get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT url, title, visited_at FROM history WHERE user_id = %s ORDER BY visited_at DESC LIMIT %s",
            (user_id, limit),
        ).fetchall()
        return [{"url": r[0], "title": r[1], "visited_at": r[2].isoformat()} for r in rows]
```

- [ ] **Step 4: Commit**

```bash
git add server/app/db.py server/app/models.py .env .env.example && git commit -m "feat: add PostgreSQL connection pool and models"
```

---

### Task 7: Server-Side Auth

**Files:**
- Create: `server/app/auth.py`
- Create: `server/app/middleware.py`
- Create: `server/tests/test_auth.py`

- [ ] **Step 1: Implement auth module**

```python
# server/app/auth.py
"""PBKDF2 password hashing and session-based authentication."""
import hashlib
import secrets
from server.app.models import create_user, get_user_by_username, create_session, validate_session_token, delete_session
from server.shared.response import Response

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210000)
    return dk.hex(), salt

def handle_register(body: bytes) -> Response:
    import json
    try:
        data = json.loads(body)
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        display_name = data.get("display_name", "").strip()
        if not username or not password:
            return Response(400, body=json.dumps({"error": "username and password required"}).encode(), headers={"content-type": "application/json"})
        if len(username) > 64 or len(password) < 4:
            return Response(422, body=json.dumps({"error": "invalid username or password length"}).encode(), headers={"content-type": "application/json"})
        if get_user_by_username(username):
            return Response(409, body=json.dumps({"error": "username taken"}).encode(), headers={"content-type": "application/json"})
        pw_hash, pw_salt = hash_password(password)
        user_id = create_user(username, pw_hash, pw_salt, display_name or username)
        token = create_session(user_id)
        response = Response(201, body=json.dumps({"id": user_id, "username": username, "display_name": display_name}).encode(), headers={"content-type": "application/json"})
        response.headers["set-cookie"] = f"wc_session={token}; HttpOnly; Secure; SameSite=Lax; Path=/"
        return response
    except json.JSONDecodeError:
        return Response(400, body=b'{"error":"invalid JSON"}', headers={"content-type": "application/json"})

def handle_login(body: bytes) -> Response:
    import json
    try:
        data = json.loads(body)
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        if not username or not password:
            return Response(400, body=json.dumps({"error": "username and password required"}).encode(), headers={"content-type": "application/json"})
        user = get_user_by_username(username)
        if user is None:
            return Response(401, body=json.dumps({"error": "invalid credentials"}).encode(), headers={"content-type": "application/json"})
        pw_hash, _ = hash_password(password, user["password_salt"])
        if pw_hash != user["password_hash"]:
            return Response(401, body=json.dumps({"error": "invalid credentials"}).encode(), headers={"content-type": "application/json"})
        token = create_session(user["id"])
        response = Response(200, body=json.dumps({"id": user["id"], "username": user["username"], "display_name": user["display_name"]}).encode(), headers={"content-type": "application/json"})
        response.headers["set-cookie"] = f"wc_session={token}; HttpOnly; Secure; SameSite=Lax; Path=/"
        return response
    except json.JSONDecodeError:
        return Response(400, body=b'{"error":"invalid JSON"}', headers={"content-type": "application/json"})

def handle_logout(token: str) -> Response:
    if token:
        delete_session(token)
    response = Response(200, body=b'{"message":"logged out"}', headers={"content-type": "application/json"})
    response.headers["set-cookie"] = "wc_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    return response

def handle_me(token: str) -> Response:
    import json
    user = validate_session_token(token)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(), headers={"content-type": "application/json"})
    return Response(200, body=json.dumps(user).encode(), headers={"content-type": "application/json"})
```

- [ ] **Step 2: Implement session middleware**

```python
# server/app/middleware.py
"""Session authentication middleware."""
from urllib.parse import parse_qs
from server.app.models import validate_session_token

def extract_session_cookie(headers: dict) -> str | None:
    cookie = headers.get("cookie", "")
    parts = cookie.split(";")
    for part in parts:
        part = part.strip()
        if part.startswith("wc_session="):
            return part.split("=", 1)[1]
    return None

def auth_required(handler):
    def wrapper(request: dict, *args, **kwargs):
        token = extract_session_cookie(request.get("headers", {}))
        user = validate_session_token(token) if token else None
        if user is None:
            from server.shared.response import Response
            import json
            return Response(401, body=json.dumps({"error": "not authenticated"}).encode(), headers={"content-type": "application/json"})
        request["user"] = user
        request["session_token"] = token
        return handler(request, *args, **kwargs)
    return wrapper
```

- [ ] **Step 3: Write auth tests**

```python
# server/tests/test_auth.py
import unittest
import json
from server.app.auth import hash_password, handle_register, handle_login, handle_me
from server.app.db import init_schema, get_pool

class TestAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_schema()

    def test_hash_password_produces_consistent_result(self):
        h1, s1 = hash_password("testpass")
        h2, _ = hash_password("testpass", s1)
        self.assertEqual(h1, h2)

    def test_hash_password_different_salts(self):
        h1, _ = hash_password("testpass")
        h2, _ = hash_password("testpass")
        self.assertNotEqual(h1, h2)

    def test_register_creates_user(self):
        import uuid
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        resp = handle_register(json.dumps({"username": username, "password": "secret123"}).encode())
        self.assertEqual(resp.status_code, 201)

    def test_register_duplicate_rejected(self):
        import uuid
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        handle_register(json.dumps({"username": username, "password": "secret123"}).encode())
        resp = handle_register(json.dumps({"username": username, "password": "secret123"}).encode())
        self.assertEqual(resp.status_code, 409)

    def test_login_with_valid_credentials(self):
        import uuid
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        handle_register(json.dumps({"username": username, "password": "secret123"}).encode())
        resp = handle_login(json.dumps({"username": username, "password": "secret123"}).encode())
        self.assertEqual(resp.status_code, 200)
        self.assertIn("set-cookie", resp.headers)

    def test_login_with_invalid_password(self):
        import uuid
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        handle_register(json.dumps({"username": username, "password": "secret123"}).encode())
        resp = handle_login(json.dumps({"username": username, "password": "wrongpass"}).encode())
        self.assertEqual(resp.status_code, 401)

    def test_login_nonexistent_user(self):
        resp = handle_login(json.dumps({"username": "noone", "password": "secret"}).encode())
        self.assertEqual(resp.status_code, 401)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest server/tests/test_auth.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server/app/auth.py server/app/middleware.py server/tests/test_auth.py && git commit -m "feat: add server-side auth with PBKDF2 hashing and session cookies"
```

---


### Task 8: App Backend Server

**Files:**
- Create: `server/app/__init__.py`
- Create: `server/app/router.py`
- Create: `server/app/server.py`
- Create: `server/tests/test_app.py`

- [ ] **Step 1: Implement app router**

```python
# server/app/router.py
"""App backend route dispatcher."""
import json
from server.shared.parser import parse_request
from server.shared.response import Response
from server.shared.security import waf_check, apply_security
from server.shared.static import serve_static
from server.app.auth import handle_register, handle_login, handle_logout, handle_me
from server.app.middleware import extract_session_cookie, auth_required
from server.app.models import add_history, get_history

def route(raw_request: bytes) -> Response:
    req = parse_request(raw_request)
    target = req["target"]
    method = req["method"]

    if method == "GET" and target == "/health":
        return Response(200, body=b'{"status":"ok"}', headers={"content-type": "application/json"})

    if method == "GET" and target.startswith("/static/"):
        return serve_static(target) or Response(404, body=b"Not Found")

    if method == "GET" and target == "/login":
        return _serve_page("login.html")
    if method == "GET" and target == "/register":
        return _serve_page("register.html")

    if method == "POST" and target == "/auth/register":
        return handle_register(req.get("body", b""))
    if method == "POST" and target == "/auth/login":
        return handle_login(req.get("body", b""))
    if method == "POST" and target == "/auth/logout":
        token = extract_session_cookie(req.get("headers", {}))
        return handle_logout(token)
    if method == "GET" and target == "/auth/me":
        token = extract_session_cookie(req.get("headers", {}))
        return handle_me(token)

    if method == "GET" and target == "/api/history":
        return _api_history_get(req)
    if method == "POST" and target == "/api/history":
        return _api_history_post(req)

    if method == "GET" and target == "/api/messages":
        return Response(200, body=b'{"messages":[]}', headers={"content-type": "application/json"})
    if method == "POST" and target == "/api/messages":
        return _api_messages_post(req)

    return Response(404, body=json.dumps({"error": "not found"}).encode(), headers={"content-type": "application/json"})

def _api_history_get(req):
    user = _get_auth_user(req)
    if user is None:
        return Response(401, body=b'{"error":"not authenticated"}', headers={"content-type": "application/json"})
    entries = get_history(user["id"])
    return Response(200, body=json.dumps(entries).encode(), headers={"content-type": "application/json"})

def _api_history_post(req):
    user = _get_auth_user(req)
    if user is None:
        return Response(401, body=b'{"error":"not authenticated"}', headers={"content-type": "application/json"})
    try:
        data = json.loads(req.get("body", b"{}"))
        add_history(user["id"], data.get("url", ""), data.get("title"))
        return Response(201, body=b'{"status":"ok"}', headers={"content-type": "application/json"})
    except json.JSONDecodeError:
        return Response(400, body=b'{"error":"invalid JSON"}', headers={"content-type": "application/json"})

def _api_messages_post(req):
    user = _get_auth_user(req)
    if user is None:
        return Response(401, body=b'{"error":"not authenticated"}', headers={"content-type": "application/json"})
    try:
        data = json.loads(req.get("body", b"{}"))
        content = data.get("content", "")
        if content:
            from server.app.db import get_pool
            pool = get_pool()
            with pool.connection() as conn:
                conn.execute("INSERT INTO messages (user_id, content) VALUES (%s, %s)", (user["id"], content))
        return Response(201, body=b'{"status":"ok"}', headers={"content-type": "application/json"})
    except json.JSONDecodeError:
        return Response(400, body=b'{"error":"invalid JSON"}', headers={"content-type": "application/json"})

def _get_auth_user(req):
    from server.app.models import validate_session_token
    token = extract_session_cookie(req.get("headers", {}))
    return validate_session_token(token) if token else None

def _serve_page(name: str) -> Response:
    return Response(200, body=f"<html><body><h1>{name}</h1></body></html>".encode(), headers={"content-type": "text/html; charset=utf-8"})
```

- [ ] **Step 2: Implement app server with ThreadPoolExecutor**

```python
# server/app/server.py
"""App backend HTTP server."""
import socket
import signal
import threading
from concurrent.futures import ThreadPoolExecutor
from server.shared.response import build_response
from server.shared.security import apply_security
from server.app.router import route

class AppServer:
    def __init__(self, host: str, port: int, max_workers: int = 16):
        self._host = host
        self._port = port
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._shutdown = threading.Event()
        self._sock: socket.socket | None = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(128)
        self._sock.settimeout(1.0)
        print(f"[app] listening on {self._host}:{self._port}")
        signal.signal(signal.SIGTERM, lambda s, f: self.stop())
        signal.signal(signal.SIGINT, lambda s, f: self.stop())
        while not self._shutdown.is_set():
            try:
                conn, addr = self._sock.accept()
                self._executor.submit(self._handle_client, conn, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._shutdown.set()
        self._executor.shutdown(wait=True)
        if self._sock:
            self._sock.close()

    def _handle_client(self, conn: socket.socket, addr: tuple):
        try:
            conn.settimeout(30)
            raw = self._recv_all(conn)
            if raw:
                resp = route(raw)
                apply_security(resp.headers)
                conn.sendall(build_response(resp))
        except Exception:
            pass
        finally:
            conn.close()

    def _recv_all(self, conn: socket.socket) -> bytes:
        data = b""
        while True:
            try:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
            except socket.timeout:
                break
        return data
```

- [ ] **Step 3: Write app server tests**

```python
# server/tests/test_app.py
import unittest
import threading
import time
import json
import http.client
from server.app.db import init_schema, get_pool
from server.app.server import AppServer

class TestAppServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_schema()
        cls.server = AppServer("127.0.0.1", 8089, max_workers=4)
        cls._thread = threading.Thread(target=cls.server.start, daemon=True)
        cls._thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", 8089, timeout=5)
        hdrs = headers or {}
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, resp.getheaders(), data

    def test_health_endpoint(self):
        status, _, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertIn(b"ok", body)

    def test_register_and_login_flow(self):
        import uuid
        username = f"t_{uuid.uuid4().hex[:6]}"
        status, headers, body = self._request("POST", "/auth/register", json.dumps({"username": username, "password": "test1234"}).encode(), {"Content-Type": "application/json"})
        self.assertEqual(status, 201)

        status, headers, _ = self._request("POST", "/auth/login", json.dumps({"username": username, "password": "test1234"}).encode(), {"Content-Type": "application/json"})
        self.assertEqual(status, 200)

    def test_not_found(self):
        status, _, _ = self._request("GET", "/nonexistent")
        self.assertEqual(status, 404)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest server/tests/test_app.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server/app/ server/tests/test_app.py && git commit -m "feat: add app backend server with auth and API routes"
```

---

### Task 9: Gateway Server

**Files:**
- Create: `server/gateway/__init__.py`
- Create: `server/gateway/server.py`
- Create: `server/gateway/proxy.py`
- Create: `server/gateway/balancer.py`
- Create: `server/gateway/metrics.py`
- Create: `server/config.py`
- Create: `server/main.py`

- [ ] **Step 1: Implement backend pool with health checks**

```python
# server/gateway/balancer.py
"""Backend pool with round-robin selection and health checks."""
import socket
import threading

class BackendPool:
    def __init__(self, backends: list[str], health_path: str = "/health"):
        self._backends = [(url, True) for url in backends]
        self._cursor = 0
        self._lock = threading.Lock()
        self._health_path = health_path

    def next_backend(self) -> str | None:
        with self._lock:
            healthy = [(url, is_h) for url, is_h in self._backends if is_h]
            if not healthy:
                return None
            idx = self._cursor % len(healthy)
            self._cursor += 1
            return healthy[idx][0]

    def mark_down(self, url: str):
        with self._lock:
            for i, (b_url, _) in enumerate(self._backends):
                if b_url == url:
                    self._backends[i] = (url, False)

    def mark_up(self, url: str):
        with self._lock:
            for i, (b_url, _) in enumerate(self._backends):
                if b_url == url:
                    self._backends[i] = (url, True)

    def status(self) -> dict:
        with self._lock:
            return {
                "backends": [{"url": url, "healthy": h} for url, h in self._backends],
                "healthy_count": sum(1 for _, h in self._backends if h),
            }
```

- [ ] **Step 2: Implement metrics collector**

```python
# server/gateway/metrics.py
"""Simple connection metrics."""
import threading
import time

class Metrics:
    def __init__(self):
        self._active_connections = 0
        self._total_requests = 0
        self._lock = threading.Lock()
        self._start_time = time.time()

    def inc_connections(self):
        with self._lock:
            self._active_connections += 1

    def dec_connections(self):
        with self._lock:
            self._active_connections -= 1

    def inc_requests(self):
        with self._lock:
            self._total_requests += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "active_connections": self._active_connections,
                "total_requests": self._total_requests,
                "uptime_seconds": int(time.time() - self._start_time),
            }
```

- [ ] **Step 3: Implement reverse proxy**

```python
# server/gateway/proxy.py
"""Reverse proxy with round-robin failover."""
import socket
import ssl
from server.shared.parser import parse_request
from server.shared.response import Response
from server.gateway.balancer import BackendPool

def proxy_request(raw_request: bytes, pool: BackendPool, node_id: str) -> Response:
    upstream = pool.next_backend()
    if upstream is None:
        return Response(502, body=b"Bad Gateway: no healthy backends")
    host, port_str = upstream.split(":")
    port = int(port_str)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((host, port))

        modified = raw_request
        modified = modified.replace(b"\r\n\r\n", f"\r\nX-Upstream-Node: {node_id}\r\n\r\n".encode())

        sock.sendall(modified)

        resp_data = b""
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                resp_data += chunk
                if b"\r\n\r\n" in resp_data:
                    content_len = _extract_content_length(resp_data)
                    if content_len is not None and _body_complete(resp_data, content_len):
                        break
                    if b"Transfer-Encoding: chunked" in resp_data:
                        if resp_data.endswith(b"0\r\n\r\n"):
                            break
            except socket.timeout:
                break
        sock.close()

        resp = _parse_upstream_response(resp_data)
        resp.headers["x-upstream-node"] = node_id
        return resp
    except Exception:
        pool.mark_down(upstream)
        return proxy_request(raw_request, pool, node_id)

def _extract_content_length(data: bytes) -> int | None:
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return None
    headers = data[:header_end].decode("iso-8859-1").lower()
    for line in headers.split("\r\n"):
        if line.startswith("content-length:"):
            return int(line.split(":")[1].strip())
    return None

def _body_complete(data: bytes, content_length: int) -> bool:
    header_end = data.find(b"\r\n\r\n")
    return len(data) - header_end - 4 >= content_length

def _parse_upstream_response(data: bytes) -> Response:
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return Response(502, body=b"Bad Gateway")
    header = data[:header_end].decode("iso-8859-1")
    body = data[header_end + 4:]
    lines = header.split("\r\n")
    status_line = lines[0]
    try:
        status_code = int(status_line.split(" ")[1])
    except (IndexError, ValueError):
        status_code = 502
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return Response(status_code, body=body, headers=headers)
```

- [ ] **Step 4: Implement gateway server**

```python
# server/gateway/server.py
"""Gateway HTTPS server with TLS termination."""
import socket
import ssl
import signal
import threading
import json
from concurrent.futures import ThreadPoolExecutor
from server.shared.response import Response, build_response
from server.gateway.proxy import proxy_request
from server.gateway.balancer import BackendPool
from server.gateway.metrics import Metrics

class GatewayServer:
    def __init__(self, host: str, port: int, backends: list[str],
                 tls_cert: str = None, tls_key: str = None,
                 node_id: str = "gateway-1", max_workers: int = 16):
        self._host = host
        self._port = port
        self._node_id = node_id
        self._pool = BackendPool(backends)
        self._metrics = Metrics()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._shutdown = threading.Event()
        self._tls_cert = tls_cert
        self._tls_key = tls_key
        self._sock: socket.socket | None = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(128)
        self._sock.settimeout(1.0)

        if self._tls_cert and self._tls_key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self._tls_cert, self._tls_key)
            self._sock = ctx.wrap_socket(self._sock, server_side=True)

        print(f"[gateway] listening on {self._host}:{self._port}")
        signal.signal(signal.SIGTERM, lambda s, f: self.stop())
        signal.signal(signal.SIGINT, lambda s, f: self.stop())

        while not self._shutdown.is_set():
            try:
                conn, addr = self._sock.accept()
                self._metrics.inc_connections()
                self._executor.submit(self._handle_client, conn, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._shutdown.set()
        self._executor.shutdown(wait=True)
        if self._sock:
            self._sock.close()

    def _handle_client(self, conn: socket.socket, addr: tuple):
        try:
            conn.settimeout(30)
            raw = self._recv_all(conn)
            if not raw:
                return
            self._metrics.inc_requests()

            target_line = raw.split(b"\r\n")[0]
            if b" /health" in target_line:
                resp = Response(200, body=b'{"status":"ok","node":"' + self._node_id.encode() + b'"}',
                               headers={"content-type": "application/json"})
            elif b" /status" in target_line:
                status_data = {
                    "node": self._node_id,
                    "backend_pool": self._pool.status(),
                    **self._metrics.snapshot(),
                }
                resp = Response(200, body=json.dumps(status_data).encode(),
                               headers={"content-type": "application/json"})
            else:
                resp = proxy_request(raw, self._pool, self._node_id)

            conn.sendall(build_response(resp))
        except Exception:
            pass
        finally:
            self._metrics.dec_connections()
            conn.close()

    def _recv_all(self, conn: socket.socket) -> bytes:
        data = b""
        while True:
            try:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
            except socket.timeout:
                break
        return data
```

- [ ] **Step 5: Create server config and main dispatcher**

```python
# server/config.py
import os
from dotenv import load_dotenv
load_dotenv()

HTTP_ROLE = os.getenv("HTTP_ROLE", "app")
HTTP_HOST = os.getenv("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("HTTP_PORT", "8081"))
HTTP_HTTPS_PORT = int(os.getenv("HTTP_HTTPS_PORT", "8443"))
HTTP_BACKENDS = os.getenv("HTTP_BACKENDS", "localhost:8081,localhost:8082").split(",")
HTTP_NODE_ID = os.getenv("HTTP_NODE_ID", "app-a")
HTTP_MAX_WORKERS = int(os.getenv("HTTP_MAX_WORKERS", "16"))
TLS_CERT_PATH = os.getenv("TLS_CERT_PATH")
TLS_KEY_PATH = os.getenv("TLS_KEY_PATH")
HTTP_DEV_INSECURE_TLS = os.getenv("HTTP_DEV_INSECURE_TLS", "false").lower() == "true"
```

```python
# server/main.py
"""Server entry point — dispatches to gateway or app role based on env."""
from server.config import HTTP_ROLE, HTTP_HOST, HTTP_PORT, HTTP_HTTPS_PORT, HTTP_BACKENDS, HTTP_NODE_ID, HTTP_MAX_WORKERS, TLS_CERT_PATH, TLS_KEY_PATH
from server.app.server import AppServer
from server.gateway.server import GatewayServer
from server.app.db import init_schema
from server.shared.static import PUBLIC_DIR

def main():
    if HTTP_ROLE == "gateway":
        server = GatewayServer(
            host=HTTP_HOST,
            port=HTTP_HTTPS_PORT,
            backends=HTTP_BACKENDS,
            tls_cert=TLS_CERT_PATH,
            tls_key=TLS_KEY_PATH,
            node_id=HTTP_NODE_ID,
            max_workers=HTTP_MAX_WORKERS,
        )
    else:
        init_schema()
        PUBLIC_DIR = "http-server/public"
        server = AppServer(
            host=HTTP_HOST,
            port=HTTP_PORT,
            max_workers=HTTP_MAX_WORKERS,
        )
    server.start()

if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Commit**

```bash
git add server/gateway/ server/config.py server/main.py && git commit -m "feat: add gateway server with TLS, reverse proxy, and health checks"
```

---

### Task 10: VPN Server Concurrency Refactor and Browser DNS Client Update

**Files:**
- Modify: `vpn/vpn_server.py`
- Modify: `browser/core/dns_client.py`

- [ ] **Step 1: Refactor VPN server to use ThreadPoolExecutor**

Read current `vpn/vpn_server.py`. Replace `threading.Thread(target=..., daemon=True).start()` with bounded `ThreadPoolExecutor(max_workers=8)`. Use `threading.Event()` for shutdown.

- [ ] **Step 2: Update browser DNS client for wire format and port 53**

```python
# browser/core/dns_client.py (key changes)
import socket
from dnslib import DNSRecord, QTYPE

class DNSClient:
    def __init__(self, host="127.0.0.1", port=53):
        self._host = host
        self._port = port
        self._cache = {}

    def resolve(self, domain: str) -> str | None:
        cached = self._cache.get(domain)
        if cached and cached["expires"] > time.time():
            return cached["ip"]

        try:
            query = DNSRecord.question(domain, qtype="A")
            packet = bytes(query.pack())
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(packet, (self._host, self._port))
            data, _ = sock.recvfrom(4096)
            sock.close()

            response = DNSRecord.parse(data)
            for rr in response.rr:
                if rr.rtype == QTYPE.A:
                    ip = str(rr.rdata)
                    self._cache[domain] = {"ip": ip, "expires": time.time() + rr.ttl}
                    return ip
            return None
        except Exception:
            return None
```

- [ ] **Step 3: Commit**

```bash
git add vpn/vpn_server.py browser/core/dns_client.py && git commit -m "refactor: VPN ThreadPoolExecutor, browser DNS wire format client"
```

---

### Task 11: WaterCat HTTP Client Extensions and Form Handler

**Files:**
- Modify: `browser/core/http_client.py`
- Create: `browser/core/form_handler.py`
- Create: `browser/core/session.py`
- Modify: `browser/gui/browser_gui.py`

- [ ] **Step 1: Add chunked decoding and verified TLS to HTTP client**

In `browser/core/http_client.py`, add `_decode_chunked_body()` and replace `_create_unverified_context()` with `ssl.create_default_context()` (with dev insecure fallback controlled by env var).

```python
# browser/core/http_client.py additions

import ssl

def _get_ssl_context():
    if os.getenv("BROWSER_DEV_INSECURE_TLS", "false").lower() == "true":
        return ssl._create_unverified_context()
    return ssl.create_default_context()

def _decode_chunked_body(raw_body: bytes) -> bytes:
    """Decode HTTP chunked transfer-encoded body."""
    result = bytearray()
    pos = 0
    while pos < len(raw_body):
        line_end = raw_body.find(b"\r\n", pos)
        if line_end == -1:
            break
        chunk_size = int(raw_body[pos:line_end], 16)
        if chunk_size == 0:
            break
        pos = line_end + 2
        result.extend(raw_body[pos:pos + chunk_size])
        pos += chunk_size + 2
    return bytes(result)
```

- [ ] **Step 2: Implement form handler**

```python
# browser/core/form_handler.py
"""Intercept HTML form submissions in custom-loaded pages."""
from urllib.parse import urlencode, urljoin
import re

FORM_RE = re.compile(rb'<form\s[^>]*>', re.IGNORECASE)

def inject_form_intercept(html: bytes, base_url: str) -> bytes:
    """Inject JavaScript to intercept form submissions and route through custom loader."""
    script = b"""
<script>
(function() {
    var base = """ + json.dumps(base_url).encode() + b""";
    document.addEventListener('submit', function(e) {
        e.preventDefault();
        var form = e.target;
        var method = (form.method || 'GET').toUpperCase();
        var action = form.action || '';
        if (!action) action = window.location.href;
        var resolved = action;
        try {
            resolved = new URL(action, window.location.href).href;
        } catch(_) {}
        var data = new FormData(form);
        var params = new URLSearchParams(data).toString();
        var fullUrl = resolved;
        if (method === 'GET' && params) {
            fullUrl = resolved + (resolved.indexOf('?') >= 0 ? '&' : '?') + params;
        }
        window.location.href = 'watercat-form://' + btoa(JSON.stringify({
            method: method,
            url: fullUrl,
            body: method === 'POST' ? params : '',
            contentType: 'application/x-www-form-urlencoded'
        }));
    });
})();
</script>
"""
    end_body = html.lower().rfind(b'</body>')
    if end_body != -1:
        return html[:end_body] + script + html[end_body:]
    else:
        return html + script
```

- [ ] **Step 3: Implement session state manager**

```python
# browser/core/session.py
"""WaterCat server session state management."""
import json
import http.client
from browser.core.http_client import HTTPClient

class SessionManager:
    def __init__(self, base_url: str = "http://localhost:8081"):
        self._base_url = base_url.rstrip("/")
        self._token: str | None = None
        self._user: dict | None = None

    def register(self, username: str, password: str) -> dict:
        data = json.dumps({"username": username, "password": password})
        resp = self._request("POST", "/auth/register", data)
        self._extract_token(resp)
        return json.loads(resp.get("body", b"{}"))

    def login(self, username: str, password: str) -> dict:
        data = json.dumps({"username": username, "password": password})
        resp = self._request("POST", "/auth/login", data)
        self._extract_token(resp)
        return json.loads(resp.get("body", b"{}"))

    def logout(self):
        self._request("POST", "/auth/logout")
        self._token = None
        self._user = None

    def me(self) -> dict | None:
        resp = self._request("GET", "/auth/me")
        if resp.get("status_code") == 200:
            self._user = json.loads(resp.get("body", b"{}"))
            return self._user
        return None

    def post_history(self, url: str, title: str = None):
        self._request("POST", "/api/history", json.dumps({"url": url, "title": title}))

    def is_authenticated(self) -> bool:
        return self.me() is not None

    def _request(self, method: str, path: str, body: str = None) -> dict:
        host, port = self._base_url.replace("http://", "").split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Cookie"] = f"wc_session={self._token}"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_data = resp.read()
        conn.close()
        return {"status_code": resp.status, "headers": dict(resp.getheaders()), "body": resp_data}

    def _extract_token(self, resp: dict):
        cookie = resp.get("headers", {}).get("set-cookie", "")
        if "wc_session=" in cookie:
            start = cookie.index("wc_session=") + 11
            end = cookie.index(";", start) if ";" in cookie[start:] else len(cookie)
            self._token = cookie[start:end]
```

- [ ] **Step 4: Integrate form handler and session into browser GUI**

Modify `browser/gui/browser_gui.py`:
- Add `self._session = SessionManager()` to `BrowserApp.__init__`
- In `_custom_fetch()`, after getting HTML response, call `inject_form_intercept(html, url)`
- Add `watercat-form://` protocol handler: decode base64 JSON, dispatch GET/POST, reload page
- After navigation, if authenticated, call `self._session.post_history(url, title)`
- Replace local `AuthDialog` references with `self._session.login()` / `self._session.register()` calls

- [ ] **Step 5: Commit**

```bash
git add browser/core/http_client.py browser/core/form_handler.py browser/core/session.py browser/gui/browser_gui.py && git commit -m "feat: add form handler, session manager, chunked decoding, verified TLS"
```

---


### Task 12: Crypto Upgrade — XOR to AES-GCM

**Files:**
- Modify: `browser/core/storage.py`

- [ ] **Step 1: Replace XOR stream cipher with AES-GCM**

Read `browser/core/storage.py`. Replace the `_encrypt_value()` and `_decrypt_value()` methods to use AES-GCM via the `cryptography` library instead of XOR stream cipher.

```python
# browser/core/storage.py — replace encryption methods

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

def _encrypt_value(self, key: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    combined = nonce + ciphertext
    tag = hmac.new(key, combined, "sha256").digest()
    return f"enc:v2:{base64.b64encode(combined + tag).decode('ascii')}"

def _decrypt_value(self, key: bytes, encrypted: str) -> str | None:
    if not encrypted.startswith("enc:v2:"):
        if encrypted.startswith("enc:v1:"):
            return self._decrypt_legacy_v1(key, encrypted)
        return None
    payload = base64.b64decode(encrypted[7:])
    combined = payload[:-32]
    expected_tag = payload[-32:]
    actual_tag = hmac.new(key, combined, "sha256").digest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        return None
    nonce = combined[:12]
    ciphertext = combined[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
```

Keep the legacy `enc:v1` XOR decryption for backward compatibility during migration.

- [ ] **Step 2: Update PBKDF2 key derivation to produce 32-byte key**

Ensure `_derive_key()` returns exactly 32 bytes (for AES-256-GCM):
```python
def _derive_key(self, password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210000, dklen=32)
```

- [ ] **Step 3: Write crypto tests**

```python
# browser/tests/test_crypto.py
import unittest
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

class TestCrypto(unittest.TestCase):
    def test_aes_gcm_roundtrip(self):
        key = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 210000, dklen=32)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        plaintext = b"hello world"
        ct = aesgcm.encrypt(nonce, plaintext, None)
        pt = aesgcm.decrypt(nonce, ct, None)
        self.assertEqual(pt, plaintext)

    def test_aes_gcm_tampered_detected(self):
        key = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 210000, dklen=32)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, b"hello world", None)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with self.assertRaises(Exception):
            aesgcm.decrypt(nonce, bytes(tampered), None)
```

- [ ] **Step 4: Commit**

```bash
git add browser/core/storage.py browser/tests/test_crypto.py && git commit -m "feat: upgrade crypto from XOR to AES-256-GCM"
```

---

### Task 13: Load Balancing Demo Page

**Files:**
- Modify: `http-server/public/index.html`
- Create: `http-server/public/styles.css` (updated)

- [ ] **Step 1: Update demo page with upstream node badge**

Add a corner badge to `index.html` showing the upstream node that served the request:

```html
<div id="upstream-badge"></div>
<script>
fetch('/status').then(r => r.json()).then(data => {
    var badge = document.getElementById('upstream-badge');
    var node = data.node || 'unknown';
    badge.innerText = 'Server: ' + node;
    badge.style.cssText = 'position:fixed;bottom:10px;right:10px;background:#333;color:#fff;padding:4px 12px;border-radius:4px;font-size:12px;z-index:9999';
});
</script>
```

- [ ] **Step 2: Commit**

```bash
git add http-server/public/ && git commit -m "feat: add upstream node badge to demo page"
```

---

### Task 14: Deployment — systemd Units and Runbooks

**Files:**
- Create: `deploy/systemd/dns.service`
- Create: `deploy/systemd/gateway.service`
- Create: `deploy/systemd/app@.service`
- Create: `deploy/systemd/vpn.service`
- Create: `deploy/runbooks/single-host.md`
- Create: `deploy/runbooks/multi-host.md`

- [ ] **Step 1: Create systemd unit files**

```ini
# deploy/systemd/gateway.service
[Unit]
Description=Mini Web Stack Gateway
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/web-stack
Environment="HTTP_ROLE=gateway"
Environment="HTTP_NODE_ID=gateway-1"
Environment="HTTP_BACKENDS=192.168.1.10:8081,192.168.1.11:8082"
Environment="TLS_CERT_PATH=/etc/letsencrypt/live/example.com/fullchain.pem"
Environment="TLS_KEY_PATH=/etc/letsencrypt/live/example.com/privkey.pem"
ExecStart=/usr/bin/python3 -m server.main
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```ini
# deploy/systemd/app@.service
[Unit]
Description=Mini Web Stack App Backend %i
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/web-stack
Environment="HTTP_ROLE=app"
Environment="HTTP_NODE_ID=app-%i"
Environment="HTTP_PORT=808%i"
Environment="DATABASE_URL=postgresql://watercat:watercat@db.local:5432/watercat"
ExecStart=/usr/bin/python3 -m server.main
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Create runbooks**

```markdown
# deploy/runbooks/single-host.md
# Single-Host Dev Deployment

1. Start PostgreSQL: `sudo systemctl start postgresql`
2. Create DB: `sudo -u postgres createdb watercat && psql -c "CREATE USER watercat WITH PASSWORD 'watercat'; GRANT ALL ON DATABASE watercat TO watercat;"`
3. Set env: `export DATABASE_URL=postgresql://watercat:watercat@localhost:5432/watercat`
4. Start DNS: `sudo python3 -m dns.server` (port 53 needs root)
5. Start App A: `HTTP_ROLE=app HTTP_PORT=8081 HTTP_NODE_ID=app-a python3 -m server.main`
6. Start App B: `HTTP_ROLE=app HTTP_PORT=8082 HTTP_NODE_ID=app-b python3 -m server.main`
7. Start Gateway: `HTTP_ROLE=gateway HTTP_BACKENDS=localhost:8081,localhost:8082 python3 -m server.main`
8. Start VPN: `python3 -m vpn.vpn_server`
9. Start Browser: `python3 -m browser`
```

```markdown
# deploy/runbooks/multi-host.md
# Multi-Host Production Deployment

## Host 1: DNS + Gateway
- Copy DNS records, TLS certs
- Enable: `sudo systemctl enable --now dns gateway vpn`

## Host 2-3: App Backends
- Copy code, set DATABASE_URL to Host 4
- Enable: `sudo systemctl enable --now app@1` (port 8081) and `app@2` (port 8082)

## Host 4: PostgreSQL
- `sudo apt install postgresql`
- Configure `pg_hba.conf` for remote access
- Create user/database as in single-host runbook
```

- [ ] **Step 3: Commit**

```bash
git add deploy/ && git commit -m "docs: add systemd units and deployment runbooks"
```

---

### Task 15: Update start.py Orchestrator

**Files:**
- Modify: `start.py`

- [ ] **Step 1: Rewrite start.py to launch new architecture**

Read current `start.py`. Update to launch DNS (new `dns/server.py`), Gateway (`server.main` with `HTTP_ROLE=gateway`), App A (`HTTP_PORT=8081`), App B (`HTTP_PORT=8082`), VPN, and optionally PostgreSQL check.

```python
# start.py (key changes)
import subprocess
import os
import time
import signal
import sys

PROCESSES = []

def main():
    signal.signal(signal.SIGINT, lambda s, f: cleanup())
    signal.signal(signal.SIGTERM, lambda s, f: cleanup())

    if not os.getenv("SKIP_DB_CHECK"):
        try:
            subprocess.run(["pg_isready", "-U", "watercat", "-d", "watercat"], check=True, timeout=5)
        except Exception:
            print("[start] PostgreSQL not ready; set SKIP_DB_CHECK=1 to skip")
            sys.exit(1)

    run("dns", [sys.executable, "-m", "dns.server"])
    run("app-a", [sys.executable, "-m", "server.main"], {"HTTP_ROLE": "app", "HTTP_PORT": "8081", "HTTP_NODE_ID": "app-a"})
    run("app-b", [sys.executable, "-m", "server.main"], {"HTTP_ROLE": "app", "HTTP_PORT": "8082", "HTTP_NODE_ID": "app-b"})
    run("gateway", [sys.executable, "-m", "server.main"], {"HTTP_ROLE": "gateway", "HTTP_BACKENDS": "localhost:8081,localhost:8082"})
    run("vpn", [sys.executable, "-m", "vpn.vpn_server"])

    print("[start] All services running. Press Ctrl+C to stop.")
    for p in PROCESSES:
        p.wait()

def run(name, cmd, env_extra=None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    p = subprocess.Popen(cmd, env=env)
    PROCESSES.append(p)
    print(f"[start] {name} started (pid={p.pid})")

def cleanup():
    print("\n[start] Shutting down...")
    for p in PROCESSES:
        p.terminate()
    for p in PROCESSES:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    sys.exit(0)

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Commit**

```bash
git add start.py && git commit -m "refactor: update orchestrator for new architecture"
```

---

### Task 16: Remove Obsolete Code and Final Cleanup

**Files:**
- Remove: `http-server/src/server.py`, `http-server/src/router.py`, `http-server/src/proxy.py`, `http-server/src/config.py`, `http-server/src/http_parser.py`, `http-server/src/http_response.py`, `http-server/src/security.py`, `http-server/src/static_cache.py`, `http-server/src/mime_types.py` (all moved to server/)
- Remove: `browser/gui/` auth dialog references (AuthDialog class)
- Remove: `browser/core/storage.py` users table SQL (moved to server)

- [ ] **Step 1: Remove old HTTP server files**

```bash
git rm -r http-server/src/
```

- [ ] **Step 2: Clean up browser-side auth**

Remove `AuthDialog` class from `browser_gui.py`, remove local user management from `storage.py` (keep settings/bookmarks/shortcuts only).

- [ ] **Step 3: Run full test suite**

```bash
python3 -m pytest dns/tests/ -v
python3 -m pytest server/tests/ -v
python3 -m pytest vpn/test_vpn.py -v
python3 -m pytest browser/tests/ -v
```

Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git rm -r http-server/src/ && git add -A && git commit -m "refactor: remove obsolete code, final cleanup"
```

---

### Task 17: Update Environment Files

**Files:**
- Modify: `.env`
- Modify: `.env.example`

- [ ] **Step 1: Add all new env vars**

```bash
# .env additions
HTTP_ROLE=app
HTTP_NODE_ID=app-a
DATABASE_URL=postgresql://watercat:watercat@localhost:5432/watercat
HTTP_MAX_WORKERS=16
HTTP_BACKENDS=localhost:8081,localhost:8082
TLS_CERT_PATH=
TLS_KEY_PATH=
HTTP_DEV_INSECURE_TLS=false
SESSION_COOKIE_NAME=wc_session
SESSION_TTL_SECONDS=86400
DNS_MAX_WORKERS=8
VPN_MAX_WORKERS=8
BROWSER_DEV_INSECURE_TLS=false
BROWSER_DNS_PORT=53
```

- [ ] **Step 2: Commit**

```bash
git add .env .env.example && git commit -m "chore: update environment variables for new architecture"
```

---

### Task 18: Update Tests for Old Files and Run Final Verification

**Files:**
- Remove: `dns/test_dns.py` (old JSON protocol tests)
- Remove: `http-server/src/test_http_server.py` (old HTTP server tests)
- Create: `dns/tests/__init__.py`, `server/tests/__init__.py`

- [ ] **Step 1: Remove old test files**

```bash
git rm dns/test_dns.py http-server/src/test_http_server.py
```

- [ ] **Step 2: Create __init__.py files for test packages**

```bash
touch dns/tests/__init__.py server/tests/__init__.py
```

- [ ] **Step 3: Run full test suite one final time**

```bash
python3 -m pytest dns/tests/ server/tests/ vpn/ browser/tests/ -v
```

Expected: ALL PASS, no failures

- [ ] **Step 4: Final commit**

```bash
git add -A && git commit -m "test: final test suite update and verification"
```

---

## Verification Checklist

After all tasks complete:

- [ ] DNS server responds to `dig @localhost myweb.local` with A record
- [ ] DNS server returns NXDOMAIN for unknown domains
- [ ] App backend /health responds 200
- [ ] POST /auth/register creates user, returns session cookie
- [ ] POST /auth/login authenticates, returns session cookie
- [ ] GET /auth/me returns user with valid cookie
- [ ] POST /api/history stores entry
- [ ] GET /status shows backend pool state
- [ ] Gateway proxies requests to app backends with round-robin
- [ ] Gateway returns 502 when no backends healthy
- [ ] X-Upstream-Node header present on proxied responses
- [ ] Browser resolves DNS via wire format on port 53
- [ ] Browser submits form GET/POST through custom loader
- [ ] Browser session persists across pages
- [ ] AES-GCM encrypt/decrypt roundtrip works
- [ ] All tests pass: `python3 -m pytest dns/tests/ server/tests/ vpn/ browser/tests/ -v`

