"""
http_client.py — Sends HTTP requests via raw TCP sockets and parses responses.
Supports: GET, POST
"""

import socket
from dataclasses import dataclass, field
from typing import Optional


HTTP_TIMEOUT = 5.0
HTTP_BUFFER = 4096


@dataclass
class HTTPResponse:
    """Parsed HTTP response result"""
    status_code: int        # 200, 404, ...
    status_text: str        # "OK", "Not Found", ...
    headers: dict           # {"Content-Type": "text/html", ...}
    body: str               # HTML/text content
    raw: str = field(repr=False)  # Original response (hidden in repr)

    @property
    def is_ok(self) -> bool:
        return 200 <= self.status_code < 300

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

    def get(self, ip: str, port: int, path: str, host: str) -> HTTPResponse:
        """Sends GET request"""
        request = self._build_request("GET", path, host)
        return self._send(ip, port, request)

    def post(self, ip: str, port: int, path: str, host: str, body: str, content_type: str = "application/x-www-form-urlencoded") -> HTTPResponse:
        """Sends POST request with body"""
        extra_headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body.encode("utf-8"))),
        }
        request = self._build_request("POST", path, host, extra_headers, body)
        return self._send(ip, port, request)

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

    def _send(self, ip: str, port: int, request: str) -> HTTPResponse:
        """Sends request via TCP and receives entire response"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((ip, port))
            sock.sendall(request.encode("utf-8"))

            # Receive response - read chunks until connection closes
            chunks = []
            while True:
                try:
                    chunk = sock.recv(HTTP_BUFFER)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except socket.timeout:
                    break  # Server silent - assume done

            raw = b"".join(chunks).decode("utf-8", errors="replace")
            return self._parse_response(raw)

        except ConnectionRefusedError:
            raise HTTPError(f"Could not connect to HTTP server at {ip}:{port}")
        except socket.timeout:
            raise HTTPError(f"HTTP server did not respond after {self.timeout}s")
        finally:
            sock.close()

    def _parse_response(self, raw: str) -> HTTPResponse:
        """
        Splits raw HTTP response into status, headers, and body.
        Format:
          HTTP/1.1 200 OK\r\n
          Header: Value\r\n
          \r\n
          body...
        """
        if not raw:
            raise HTTPError("Server returned empty response")

        # Split headers and body at first blank line
        if "\r\n\r\n" in raw:
            header_block, body = raw.split("\r\n\r\n", 1)
        elif "\n\n" in raw:
            header_block, body = raw.split("\n\n", 1)
        else:
            raise HTTPError(f"Invalid HTTP response format:\n{raw[:200]}")

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
        for line in header_lines[1:]:
            line = line.strip()
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip()] = val.strip()

        return HTTPResponse(
            status_code=status_code,
            status_text=status_text,
            headers=headers,
            body=body,
            raw=raw,
        )


if __name__ == "__main__":
    # Test with real HTTP server
    client = HTTPClient()
    try:
        resp = client.get("127.0.0.1", 8000, "/", "example.local")
        print(resp)
    except HTTPError as e:
        print(f"[ERR] {e}")
