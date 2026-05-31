"""
http_client.py — Sends HTTP requests via raw TCP sockets and parses responses.
Supports: GET, POST
"""

import asyncio
import os
import ssl
from dataclasses import dataclass, field
from typing import Optional

try:
    from .config import HTTP_BUFFER, HTTP_TIMEOUT
except ImportError:
    from config import HTTP_BUFFER, HTTP_TIMEOUT


@dataclass
class HTTPResponse:
    """Parsed HTTP response result"""
    status_code: int        # 200, 404, ...
    status_text: str        # "OK", "Not Found", ...
    headers: dict           # {"Content-Type": "text/html", ...}
    body: str               # HTML/text content
    raw: str = field(repr=False)  # Original response (hidden in repr)
    raw_bytes: bytes = field(default=b"", repr=False)
    body_bytes: bytes = field(default=b"", repr=False)
    set_cookie_headers: list[str] = field(default_factory=list)

    @property
    def is_ok(self) -> bool:
        return 200 <= self.status_code < 300

    def header(self, name: str, default: str = "") -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def __str__(self):
        return (
            f"HTTPResponse(\n"
            f"  status  = {self.status_code} {self.status_text}\n"
            f"  headers = {self.headers}\n"
            f"  body    = {self.body[:100]}{'...' if len(self.body) > 100 else ''}\n"
            f")"
        )


class HTTPError(Exception):
    pass


class HTTPClient:
    """
    Sends HTTP requests via raw TCP socket.
    Does not use urllib/requests - builds request strings per HTTP/1.1 spec.
    """

    def __init__(self, timeout: float = HTTP_TIMEOUT):
        self.timeout = timeout

    async def get(
        self,
        ip: str,
        port: int,
        path: str,
        host: str,
        extra_headers: Optional[dict] = None,
        use_tls: bool = False,
    ) -> HTTPResponse:
        """Sends GET request"""
        request = self._build_request("GET", path, host, extra_headers=extra_headers)
        return await self._send(ip, port, request, use_tls=use_tls, host=host)

    async def post(
        self,
        ip: str,
        port: int,
        path: str,
        host: str,
        body: str,
        content_type: str = "application/x-www-form-urlencoded",
        use_tls: bool = False,
        extra_headers: Optional[dict] = None,
    ) -> HTTPResponse:
        """Sends POST request with body"""
        extra_headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body.encode("utf-8"))),
            **(extra_headers or {}),
        }
        request = self._build_request("POST", path, host, extra_headers, body)
        return await self._send(ip, port, request, use_tls=use_tls, host=host)

    def _build_request(
        self,
        method: str,
        path: str,
        host: str,
        extra_headers: Optional[dict] = None,
        body: str = "",
    ) -> str:
        """
        Creates raw HTTP request string:
          METHOD /path HTTP/1.1\r\n
          Host: ...\r\n
          ...\r\n
          \r\n
          [body]
        """
        lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: MiniWebBrowser/1.0",
            "Accept: text/html,*/*",
            "Connection: close",  # Simplify: no keep-alive
        ]

        if extra_headers:
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")

        # Headers end with a blank line, followed by the body
        request = "\r\n".join(lines) + "\r\n\r\n" + body
        return request

    async def _send(self, ip: str, port: int, request: str, use_tls: bool = False, host: str = "") -> HTTPResponse:
        """Sends request via TCP and receives entire response"""
        writer = None
        try:
            if use_tls:
                if os.getenv("BROWSER_DEV_INSECURE_TLS", "false").lower() == "true":
                    context = ssl._create_unverified_context()
                else:
                    context = ssl.create_default_context()
            else:
                context = None

            connect_coro = asyncio.open_connection(
                ip,
                port,
                ssl=context,
                server_hostname=host if use_tls else None,
            )
            reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)

            writer.write(request.encode("utf-8"))
            await writer.drain()

            # Receive response - read chunks until connection closes
            chunks = []
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(HTTP_BUFFER), timeout=self.timeout)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except TimeoutError:
                    break  # Server silent - assume done

            raw_bytes = b"".join(chunks)
            return self._parse_response(raw_bytes)

        except ConnectionRefusedError:
            raise HTTPError(f"Could not connect to HTTP server at {ip}:{port}")
        except ssl.SSLError as e:
            raise HTTPError(f"TLS/SSL Handshake failed: {e}")
        except TimeoutError:
            raise HTTPError(f"HTTP server did not respond after {self.timeout}s")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    def _parse_response(self, raw_bytes: bytes) -> HTTPResponse:
        """
        Splits raw HTTP response into status, headers, and body.
        Format:
          HTTP/1.1 200 OK\r\n
          Header: Value\r\n
          \r\n
          body...
        """
        if not raw_bytes:
            raise HTTPError("Server returned empty response")

        # Split headers and body at first blank line
        if b"\r\n\r\n" in raw_bytes:
            header_bytes, body_bytes = raw_bytes.split(b"\r\n\r\n", 1)
        elif b"\n\n" in raw_bytes:
            header_bytes, body_bytes = raw_bytes.split(b"\n\n", 1)
        else:
            raw = raw_bytes.decode("utf-8", errors="replace")
            raise HTTPError(f"Invalid HTTP response format:\n{raw[:200]}")

        header_block = header_bytes.decode("iso-8859-1", errors="replace")
        header_lines = header_block.replace("\r\n", "\n").split("\n")

        # Parse status line: "HTTP/1.1 200 OK"
        status_line = header_lines[0].strip()
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            raise HTTPError(f"Invalid status line: '{status_line}'")

        try:
            status_code = int(parts[1])
        except ValueError:
            raise HTTPError(f"Status code is not a number: '{parts[1]}'")

        status_text = parts[2] if len(parts) > 2 else ""

        # Parse headers
        headers = {}
        set_cookie_headers = []
        for line in header_lines[1:]:
            line = line.strip()
            if ":" in line:
                key, _, val = line.partition(":")
                clean_key = key.strip()
                clean_val = val.strip()
                if clean_key.lower() == "set-cookie":
                    set_cookie_headers.append(clean_val)
                if clean_key in headers:
                    headers[clean_key] = f"{headers[clean_key]}, {clean_val}"
                else:
                    headers[clean_key] = clean_val

        # Decode chunked transfer encoding
        if self._header_value(headers, "Transfer-Encoding").lower() == "chunked":
            body_bytes = self._decode_chunked_body(body_bytes)

        body = body_bytes.decode("utf-8", errors="replace")
        raw = raw_bytes.decode("utf-8", errors="replace")

        return HTTPResponse(
            status_code=status_code,
            status_text=status_text,
            headers=headers,
            body=body,
            raw=raw,
            raw_bytes=raw_bytes,
            body_bytes=body_bytes,
            set_cookie_headers=set_cookie_headers,
        )

    @staticmethod
    def _header_value(headers: dict[str, str], name: str, default: str = "") -> str:
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return default

    @staticmethod
    def _decode_chunked_body(raw_body: bytes) -> bytes:
        """Decodes HTTP chunked transfer encoding."""
        result = bytearray()
        pos = 0
        while pos < len(raw_body):
            crlf = raw_body.find(b"\r\n", pos)
            if crlf == -1:
                break
            chunk_size_hex = raw_body[pos:crlf].decode("ascii", errors="ignore")
            try:
                chunk_size = int(chunk_size_hex.split(";")[0].strip(), 16)
            except ValueError:
                break
            if chunk_size <= 0:
                break
            chunk_start = crlf + 2
            if chunk_size < 0 or chunk_start + chunk_size > len(raw_body):
                break
            chunk_end = chunk_start + chunk_size
            result.extend(raw_body[chunk_start:chunk_end])
            pos = chunk_end + 2  # skip trailing \r\n
        return bytes(result)
