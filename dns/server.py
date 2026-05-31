"""RFC 1035 DNS server built on asyncio UDP sockets."""

import asyncio
import signal
import socket
import time

from dns.config import (
    BIND_HOST,
    PORT,
    RECORDS_PATH,
    RATE_LIMIT_MAX_QUERIES,
    RATE_LIMIT_WINDOW_SECONDS,
)
from dns.cache import DNSCache
from dns.wire import QueryInfo, decode_query, encode_response, encode_error
from dns.resolver import StaticResolver
from dns.rate_limiter import RateLimiter
from dnslib import QTYPE, CLASS, RCODE
from server.shared.access_log import log_event, peer_label


class DNSServer:

    def __init__(self, port: int | None = None):
        self._port = port if port is not None else PORT
        self._resolver = StaticResolver(RECORDS_PATH)
        self._rate_limiter = RateLimiter(RATE_LIMIT_MAX_QUERIES, RATE_LIMIT_WINDOW_SECONDS)
        self._cache = DNSCache()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown: asyncio.Event | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: asyncio.DatagramProtocol | None = None

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    @property
    def port(self) -> int:
        return self._port

    async def start(self):
        if self._transport is not None:
            return
        self._loop = asyncio.get_running_loop()
        self._shutdown = asyncio.Event()
        transport, protocol = await self._loop.create_datagram_endpoint(
            lambda: _DNSDatagramProtocol(self),
            local_addr=(BIND_HOST, self._port),
        )
        self._transport = transport
        self._protocol = protocol
        sockname = transport.get_extra_info("sockname")
        if sockname:
            self._port = sockname[1]
        log_event("dns", f"listening on {BIND_HOST}:{self._port}")

    async def serve_forever(self):
        await self.start()
        if self._shutdown is None:
            return
        try:
            await self._shutdown.wait()
        finally:
            await self.stop()

    async def stop(self):
        if self._shutdown is not None:
            self._shutdown.set()
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._protocol = None

    def _handle_query(self, data: bytes, addr: tuple[str, int]):
        started_at = time.perf_counter()
        client = peer_label(addr)
        client_ip = addr[0]
        if not self._rate_limiter.is_allowed(client_ip):
            duration_ms = int((time.perf_counter() - started_at) * 1000)
            log_event("dns", f'{client} "?" -> RATE_LIMITED {duration_ms}ms bytes={len(data)}')
            return
        info = decode_query(data)
        if info is None:
            duration_ms = int((time.perf_counter() - started_at) * 1000)
            log_event("dns", f'{client} "invalid" -> BAD_REQUEST {duration_ms}ms bytes={len(data)}')
            return
        response, status, extra = self._resolve(info)
        if response and self._transport is not None:
            self._transport.sendto(response, addr)
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        suffix = f" {extra}" if extra else ""
        log_event(
            "dns",
            f'{client} "{info.domain}" qtype={info.qtype} -> {status} {duration_ms}ms{suffix}',
        )

    def _resolve(self, info: QueryInfo) -> tuple[bytes | None, str, str]:
        if info.qtype != QTYPE.A or info.qclass != CLASS.IN:
            return encode_error(info, RCODE.NOTIMP), "NOTIMP", f"qclass={info.qclass}"

        domain = info.domain.lower()
        cached = self._cache.get(domain)
        if cached is not None:
            remaining_ttl = max(1, int(cached.ttl - (time.time() - cached.created_at)))
            ip = socket.inet_ntoa(cached.ip)
            return (
                encode_response(info, [(domain.encode(), QTYPE.A, CLASS.IN, remaining_ttl, cached.ip)]),
                "OK",
                f"ip={ip} ttl={remaining_ttl} cache=hit",
            )

        result = self._resolver.resolve(domain)
        if result is None:
            return encode_error(info, RCODE.NXDOMAIN), "NXDOMAIN", "cache=miss"

        ip, ttl = result
        packed_ip = socket.inet_aton(ip)
        self._cache.put(domain, packed_ip, ttl)
        return (
            encode_response(info, [(domain.encode(), QTYPE.A, CLASS.IN, ttl, packed_ip)]),
            "OK",
            f"ip={ip} ttl={ttl} cache=miss",
        )


class _DNSDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: DNSServer) -> None:
        self._server = server

    def datagram_received(self, data: bytes, addr) -> None:
        self._server._handle_query(data, addr)


async def _main() -> None:
    server = DNSServer()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(server.stop()))
        except (NotImplementedError, RuntimeError):
            pass
    await server.serve_forever()


def main() -> None:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
