"""RFC 1035 DNS server with bounded ThreadPoolExecutor."""

import socket
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from dns.config import (
    BIND_HOST,
    PORT,
    RECORDS_PATH,
    DEFAULT_TTL,
    RATE_LIMIT_MAX_QUERIES,
    RATE_LIMIT_WINDOW_SECONDS,
    MAX_WORKERS,
)
from dns.wire import QueryInfo, decode_query, encode_response, encode_error
from dns.resolver import StaticResolver
from dns.rate_limiter import RateLimiter
from dnslib import QTYPE, CLASS, RCODE


class DNSServer:

    def __init__(self, port: int | None = None):
        self._port = port if port is not None else PORT
        self._resolver = StaticResolver(RECORDS_PATH)
        self._rate_limiter = RateLimiter(RATE_LIMIT_MAX_QUERIES, RATE_LIMIT_WINDOW_SECONDS)
        self._executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self._shutdown = threading.Event()
        self._sock: socket.socket | None = None
        self._cache: dict[str, tuple[bytes, float]] = {}

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((BIND_HOST, self._port))
        print(f"[DNS] listening on {BIND_HOST}:{self._port}")
        if threading.current_thread() is threading.main_thread():
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
        if not self._rate_limiter.is_allowed(client_ip):
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
        if cached and time.time() < cached[1]:
            return encode_response(info, [(info.domain.encode(), QTYPE.A, CLASS.IN, DEFAULT_TTL, cached[0])])
        result = self._resolver.resolve(info.domain)
        if result is None:
            return encode_error(info, RCODE.NXDOMAIN)
        ip, ttl = result
        packed_ip = socket.inet_aton(ip)
        self._cache[info.domain] = (packed_ip, time.time() + ttl)
        return encode_response(info, [(info.domain.encode(), QTYPE.A, CLASS.IN, ttl, packed_ip)])
