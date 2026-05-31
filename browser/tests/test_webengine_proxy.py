"""Integration tests for the local Qt WebEngine proxy."""

import asyncio
import unittest

from browser.core.dns_client import DNSError, DNSResult
from browser.core.webengine_proxy import LocalWebEngineProxy


class StaticDNSClient:
    def __init__(self, records: dict[str, str] | None = None, error: str = ""):
        self.records = records or {}
        self.error = error
        self.queries: list[str] = []

    async def resolve(self, domain: str) -> DNSResult:
        self.queries.append(domain)
        if self.error:
            raise DNSError(self.error)
        return DNSResult(domain=domain, ip=self.records[domain])


class FakeVPNClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.calls: list[tuple[str, int]] = []

    async def open_stream(self, target_host: str, target_port: int):
        self.calls.append((target_host, target_port))
        return await asyncio.open_connection(self.host, self.port)


class AsyncHTTPServer:
    def __init__(self, response: bytes):
        self.response = response
        self.received = b""
        self.server: asyncio.AbstractServer | None = None
        self.host = "127.0.0.1"
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, self.host, 0)
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()
        self.server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while b"\r\n\r\n" not in self.received:
            chunk = await reader.read(4096)
            if not chunk:
                break
            self.received += chunk
        writer.write(self.response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()


class AsyncEchoServer:
    def __init__(self):
        self.received = b""
        self.server: asyncio.AbstractServer | None = None
        self.host = "127.0.0.1"
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, self.host, 0)
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()
        self.server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.received = await reader.read(4096)
        writer.write(self.received.upper())
        await writer.drain()
        writer.close()
        await writer.wait_closed()


class TestLocalWebEngineProxy(unittest.TestCase):
    def test_http_requests_resolve_with_custom_dns(self):
        async def scenario():
            upstream = AsyncHTTPServer(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )
            await upstream.start()
            dns_client = StaticDNSClient({"example.com": "127.0.0.1"})
            proxy = LocalWebEngineProxy(
                bind_host="127.0.0.1",
                bind_port=0,
                dns_client_factory=lambda: dns_client,
                vpn_client_factory=lambda: FakeVPNClient("127.0.0.1", upstream.port),
                should_use_vpn=lambda _host: False,
                log_sink=lambda _line: None,
            )
            await proxy.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bind_port)
                writer.write(
                    (
                        f"GET http://example.com:{upstream.port}/demo?q=1 HTTP/1.1\r\n"
                        f"Host: example.com:{upstream.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("utf-8")
                )
                await writer.drain()
                response = await reader.read()
                writer.close()
                await writer.wait_closed()
            finally:
                await proxy.stop()
                await upstream.stop()

            self.assertIn(b"HTTP/1.1 200 OK", response)
            self.assertEqual(dns_client.queries, ["example.com"])
            self.assertIn(b"GET /demo?q=1 HTTP/1.1", upstream.received)
            self.assertIn(f"Host: example.com:{upstream.port}".encode("utf-8"), upstream.received)

        asyncio.run(scenario())

    def test_dns_failure_returns_bad_gateway(self):
        async def scenario():
            dns_client = StaticDNSClient(error="DNS server returned error for domain 'missing.test' (rcode=3)")
            proxy = LocalWebEngineProxy(
                bind_host="127.0.0.1",
                bind_port=0,
                dns_client_factory=lambda: dns_client,
                vpn_client_factory=lambda: FakeVPNClient("127.0.0.1", 1),
                should_use_vpn=lambda _host: False,
                log_sink=lambda _line: None,
            )
            await proxy.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bind_port)
                writer.write(
                    b"GET http://missing.test/ HTTP/1.1\r\n"
                    b"Host: missing.test\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                )
                await writer.drain()
                response = await reader.read()
                writer.close()
                await writer.wait_closed()
            finally:
                await proxy.stop()

            self.assertIn(b"502 Bad Gateway", response)
            self.assertIn(b"missing.test", response)

        asyncio.run(scenario())

    def test_connect_tunnels_bytes_after_dns_resolution(self):
        async def scenario():
            upstream = AsyncEchoServer()
            await upstream.start()
            dns_client = StaticDNSClient({"secure.example": "127.0.0.1"})
            proxy = LocalWebEngineProxy(
                bind_host="127.0.0.1",
                bind_port=0,
                dns_client_factory=lambda: dns_client,
                vpn_client_factory=lambda: FakeVPNClient("127.0.0.1", upstream.port),
                should_use_vpn=lambda _host: False,
                log_sink=lambda _line: None,
            )
            await proxy.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bind_port)
                writer.write(
                    (
                        f"CONNECT secure.example:{upstream.port} HTTP/1.1\r\n"
                        f"Host: secure.example:{upstream.port}\r\n"
                        "\r\n"
                    ).encode("utf-8")
                )
                await writer.drain()
                handshake = await reader.readuntil(b"\r\n\r\n")
                writer.write(b"hello")
                await writer.drain()
                echoed = await reader.read(5)
                writer.close()
                await writer.wait_closed()
            finally:
                await proxy.stop()
                await upstream.stop()

            self.assertIn(b"200 Connection Established", handshake)
            self.assertEqual(echoed, b"HELLO")
            self.assertEqual(upstream.received, b"hello")

        asyncio.run(scenario())

    def test_vpn_route_uses_stream_transport(self):
        async def scenario():
            upstream = AsyncHTTPServer(
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nthrough!"
            )
            await upstream.start()
            dns_client = StaticDNSClient({"vpn.example": "127.0.0.1"})
            vpn_client = FakeVPNClient("127.0.0.1", upstream.port)
            proxy = LocalWebEngineProxy(
                bind_host="127.0.0.1",
                bind_port=0,
                dns_client_factory=lambda: dns_client,
                vpn_client_factory=lambda: vpn_client,
                should_use_vpn=lambda host: host == "vpn.example",
                log_sink=lambda _line: None,
            )
            await proxy.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", proxy.bind_port)
                writer.write(
                    (
                        f"GET http://vpn.example:{upstream.port}/ HTTP/1.1\r\n"
                        f"Host: vpn.example:{upstream.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("utf-8")
                )
                await writer.drain()
                response = await reader.read()
                writer.close()
                await writer.wait_closed()
            finally:
                await proxy.stop()
                await upstream.stop()

            self.assertIn(b"through!", response)
            self.assertEqual(vpn_client.calls, [("127.0.0.1", upstream.port)])

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
