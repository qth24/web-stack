"""Local forward proxy for routing Qt WebEngine traffic through custom DNS."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlsplit

from .config import HTTP_BUFFER, HTTP_TIMEOUT
from .dns_client import DNSError, DNSClient
from .host_routing import is_ipv4_address
from .vpn_client import VPNClient, VPNError


class ProxyRequestError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = int(status_code)
        self.message = message


@dataclass
class ProxyRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str, default: str = "") -> str:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return default


class LocalWebEngineProxy:
    def __init__(
        self,
        bind_host: str,
        bind_port: int,
        dns_client_factory: Callable[[], DNSClient],
        vpn_client_factory: Callable[[], VPNClient],
        should_use_vpn: Callable[[str], bool],
        log_sink: Optional[Callable[[str], None]] = None,
        connect_timeout: float = HTTP_TIMEOUT,
        buffer_size: int = HTTP_BUFFER,
    ) -> None:
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self._dns_client_factory = dns_client_factory
        self._vpn_client_factory = vpn_client_factory
        self._should_use_vpn = should_use_vpn
        self._log_sink = log_sink or print
        self._connect_timeout = max(0.5, float(connect_timeout))
        self._buffer_size = max(512, int(buffer_size))
        self._server: asyncio.AbstractServer | None = None

    @property
    def endpoint(self) -> str:
        return f"{self.bind_host}:{self.bind_port}"

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_host,
            self.bind_port,
            backlog=128,
        )
        sockets = self._server.sockets or []
        if sockets:
            self.bind_port = int(sockets[0].getsockname()[1])
        self._log(f"listening on {self.endpoint}")

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("-", 0)
        try:
            request = await self._read_request(reader)
            if request is None:
                return
            if request.method.upper() == "CONNECT":
                await self._handle_connect(request, reader, writer, peer)
            else:
                await self._handle_http(request, writer, peer)
        except ProxyRequestError as exc:
            await self._send_error(writer, exc.status_code, exc.message)
            self._log_access(peer, "-", exc.status_code, exc.message)
        except Exception as exc:
            await self._send_error(writer, 500, str(exc))
            self._log_access(peer, "-", 500, str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _handle_http(
        self,
        request: ProxyRequest,
        client_writer: asyncio.StreamWriter,
        peer: tuple[str, int],
    ) -> None:
        scheme, host, port, path = self._parse_http_target(request)
        if scheme == "https":
            raise ProxyRequestError(400, "HTTPS requests must use CONNECT through the proxy")
        resolved_ip = await self._resolve_host(host)
        use_vpn = self._should_use_vpn(host)
        upstream_reader, upstream_writer = await self._open_upstream(resolved_ip, port, use_vpn)
        route = "vpn" if use_vpn else "direct"
        try:
            upstream_writer.write(self._build_origin_request(request, path, host))
            await upstream_writer.drain()
            status = await self._pipe_response(upstream_reader, client_writer)
        finally:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except OSError:
                pass
        self._log_access(peer, f'{request.method} {host}:{port}{path}', status, f"route={route} ip={resolved_ip}")

    async def _handle_connect(
        self,
        request: ProxyRequest,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        peer: tuple[str, int],
    ) -> None:
        host, port = self._parse_connect_target(request.target)
        resolved_ip = await self._resolve_host(host)
        use_vpn = self._should_use_vpn(host)
        upstream_reader, upstream_writer = await self._open_upstream(resolved_ip, port, use_vpn)
        route = "vpn" if use_vpn else "direct"
        try:
            client_writer.write(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: WaterCatProxy/1.0\r\n"
                b"\r\n"
            )
            await client_writer.drain()
            self._log_access(peer, f"CONNECT {host}:{port}", 200, f"route={route} ip={resolved_ip}")
            await self._relay_bidirectional(client_reader, client_writer, upstream_reader, upstream_writer)
        finally:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except OSError:
                pass

    async def _open_upstream(
        self,
        target_host: str,
        target_port: int,
        use_vpn: bool,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            if use_vpn:
                return await self._vpn_client_factory().open_stream(target_host, target_port)
            return await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=self._connect_timeout,
            )
        except VPNError as exc:
            raise ProxyRequestError(502, str(exc)) from exc
        except (ConnectionRefusedError, OSError, TimeoutError) as exc:
            raise ProxyRequestError(502, f"Could not connect to upstream {target_host}:{target_port}: {exc}") from exc

    async def _resolve_host(self, host: str) -> str:
        if is_ipv4_address(host):
            return host
        try:
            result = await self._dns_client_factory().resolve(host)
        except DNSError as exc:
            raise ProxyRequestError(502, str(exc)) from exc
        return result.ip

    async def _read_request(self, reader: asyncio.StreamReader) -> ProxyRequest | None:
        raw_head, remainder = await self._read_headers(reader)
        if raw_head is None:
            return None
        lines = raw_head.decode("iso-8859-1", errors="replace").replace("\r\n", "\n").split("\n")
        if not lines or not lines[0].strip():
            raise ProxyRequestError(400, "Missing request line")
        parts = lines[0].strip().split(" ", 2)
        if len(parts) != 3:
            raise ProxyRequestError(400, "Invalid request line")
        method, target, version = parts
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            headers.append((key.strip(), value.strip()))
        body = await self._read_request_body(reader, headers, remainder)
        return ProxyRequest(method=method, target=target, version=version, headers=headers, body=body)

    async def _read_headers(
        self,
        reader: asyncio.StreamReader,
    ) -> tuple[bytes | None, bytes]:
        data = bytearray()
        while b"\r\n\r\n" not in data and b"\n\n" not in data:
            chunk = await asyncio.wait_for(reader.read(self._buffer_size), timeout=self._connect_timeout)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 65536:
                raise ProxyRequestError(431, "Proxy request headers too large")
        if not data:
            return None, b""
        if b"\r\n\r\n" in data:
            head, tail = data.split(b"\r\n\r\n", 1)
        elif b"\n\n" in data:
            head, tail = data.split(b"\n\n", 1)
        else:
            raise ProxyRequestError(400, "Invalid proxy request")
        return head, tail

    async def _read_request_body(
        self,
        reader: asyncio.StreamReader,
        headers: list[tuple[str, str]],
        remainder: bytes,
    ) -> bytes:
        transfer_encoding = self._header_value(headers, "Transfer-Encoding").lower()
        content_length = self._header_value(headers, "Content-Length")
        if transfer_encoding == "chunked":
            return await self._read_chunked_body(reader, bytearray(remainder))
        if content_length:
            try:
                expected = max(0, int(content_length))
            except ValueError as exc:
                raise ProxyRequestError(400, "Invalid Content-Length header") from exc
            body = bytearray(remainder[:expected])
            while len(body) < expected:
                chunk = await asyncio.wait_for(
                    reader.read(expected - len(body)),
                    timeout=self._connect_timeout,
                )
                if not chunk:
                    raise ProxyRequestError(400, "Client closed before request body was complete")
                body.extend(chunk)
            return bytes(body)
        return bytes(remainder)

    async def _read_chunked_body(self, reader: asyncio.StreamReader, data: bytearray) -> bytes:
        consumed = 0
        while True:
            line_end = await self._ensure_line(data, reader, consumed)
            size_line = bytes(data[consumed:line_end]).decode("ascii", errors="replace")
            try:
                chunk_size = int(size_line.split(";", 1)[0].strip(), 16)
            except ValueError as exc:
                raise ProxyRequestError(400, "Invalid chunked request body") from exc
            consumed = line_end + 2
            await self._ensure_bytes(data, reader, consumed + chunk_size + 2)
            consumed += chunk_size + 2
            if chunk_size == 0:
                while True:
                    trailer_end = await self._ensure_line(data, reader, consumed)
                    if trailer_end == consumed:
                        consumed = trailer_end + 2
                        return bytes(data[:consumed])
                    consumed = trailer_end + 2

    async def _ensure_line(
        self,
        data: bytearray,
        reader: asyncio.StreamReader,
        start: int,
    ) -> int:
        while True:
            marker = data.find(b"\r\n", start)
            if marker != -1:
                return marker
            chunk = await asyncio.wait_for(reader.read(self._buffer_size), timeout=self._connect_timeout)
            if not chunk:
                raise ProxyRequestError(400, "Client closed during chunked request body")
            data.extend(chunk)

    async def _ensure_bytes(
        self,
        data: bytearray,
        reader: asyncio.StreamReader,
        expected: int,
    ) -> None:
        while len(data) < expected:
            chunk = await asyncio.wait_for(reader.read(self._buffer_size), timeout=self._connect_timeout)
            if not chunk:
                raise ProxyRequestError(400, "Client closed during chunked request body")
            data.extend(chunk)

    def _parse_http_target(self, request: ProxyRequest) -> tuple[str, str, int, str]:
        if request.target.startswith("/"):
            host = self._header_value(request.headers, "Host")
            if not host:
                raise ProxyRequestError(400, "Proxy request missing Host header")
            parsed = urlsplit(f"http://{host}{request.target}")
        else:
            parsed = urlsplit(request.target)
        if parsed.scheme not in {"http", "https"}:
            raise ProxyRequestError(400, f"Unsupported proxy scheme '{parsed.scheme or '-'}'")
        host = parsed.hostname or ""
        if not host:
            raise ProxyRequestError(400, "Proxy request missing target host")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return parsed.scheme, host, port, path

    def _parse_connect_target(self, target: str) -> tuple[str, int]:
        host, sep, raw_port = target.rpartition(":")
        if not sep or not host or not raw_port:
            raise ProxyRequestError(400, "CONNECT request must specify host:port")
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise ProxyRequestError(400, "CONNECT request has invalid port") from exc
        return host.strip(), port

    def _build_origin_request(self, request: ProxyRequest, path: str, host: str) -> bytes:
        lines = [f"{request.method} {path} {request.version}"]
        saw_host = False
        for key, value in request.headers:
            lower = key.lower()
            if lower in {"proxy-connection", "connection"}:
                continue
            if lower == "host":
                saw_host = True
                lines.append(f"Host: {value}")
                continue
            lines.append(f"{key}: {value}")
        if not saw_host:
            lines.append(f"Host: {host}")
        lines.append("Connection: close")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + request.body

    async def _pipe_response(
        self,
        upstream_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> str:
        status = "-"
        head = bytearray()
        while True:
            chunk = await upstream_reader.read(self._buffer_size)
            if not chunk:
                break
            if status == "-":
                head.extend(chunk)
                status = self._extract_status(head) or status
            client_writer.write(chunk)
            await client_writer.drain()
        return status

    async def _relay_bidirectional(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        tasks = {
            asyncio.create_task(self._pipe_raw(client_reader, upstream_writer)),
            asyncio.create_task(self._pipe_raw(upstream_reader, client_writer)),
        }
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.gather(*done, return_exceptions=True)

    async def _pipe_raw(
        self,
        source: asyncio.StreamReader,
        destination: asyncio.StreamWriter,
    ) -> None:
        while True:
            chunk = await source.read(self._buffer_size)
            if not chunk:
                break
            destination.write(chunk)
            await destination.drain()
        try:
            destination.write_eof()
        except (AttributeError, OSError):
            pass

    async def _send_error(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        message: str,
    ) -> None:
        status_text = self._status_text(status_code)
        body = message.encode("utf-8", errors="replace")
        response = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8") + body
        writer.write(response)
        await writer.drain()

    @staticmethod
    def _header_value(headers: list[tuple[str, str]], name: str, default: str = "") -> str:
        for key, value in headers:
            if key.lower() == name.lower():
                return value
        return default

    @staticmethod
    def _extract_status(data: bytes) -> str:
        if b"\r\n" not in data:
            return ""
        line = data.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
        parts = line.split(" ", 2)
        if len(parts) < 2:
            return ""
        if len(parts) == 2:
            return parts[1]
        return f"{parts[1]} {parts[2]}".strip()

    @staticmethod
    def _status_text(status_code: int) -> str:
        return {
            400: "Bad Request",
            431: "Request Header Fields Too Large",
            500: "Internal Server Error",
            502: "Bad Gateway",
        }.get(int(status_code), "Error")

    def _log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self._log_sink(f"{timestamp} [webengine-proxy] {message}")

    def _log_access(
        self,
        peer: tuple[str, int],
        target: str,
        status: int | str,
        detail: str,
    ) -> None:
        self._log(f'{peer[0]}:{peer[1]} "{target}" -> {status} {detail}'.strip())
