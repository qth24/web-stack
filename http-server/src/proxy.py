"""Reverse proxy module: route matching, round-robin selection, request forwarding."""

import json
import socket
import ssl
import threading
from pathlib import Path
from typing import Any, Optional

from config import PROXY_BUFFER_SIZE, PROXY_CONNECT_TIMEOUT, PROXY_READ_TIMEOUT
from http_response import build_response
from security import waf_inspect

HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})


def load_proxy_routes(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    routes = data.get("routes", [])
    if not isinstance(routes, list):
        return []
    return routes


def _host_matches(route_hosts: Optional[list[str]], request_host: str) -> bool:
    if not route_hosts:
        return True
    normalized = request_host.lower().split(":")[0]
    return any(h.lower() == normalized for h in route_hosts)


def _path_matches(route_prefixes: Optional[list[str]], request_target: str) -> bool:
    if not route_prefixes:
        return True
    path_only = request_target.split("?")[0]
    return any(path_only == pfx or path_only.startswith(pfx.rstrip("/") + "/") for pfx in route_prefixes)


def match_proxy_route(request: dict, routes: list[dict[str, Any]]) -> int | None:
    request_host = request.get("headers", {}).get("host", "")
    request_target = request.get("target", "")
    for idx, route in enumerate(routes):
        if not _host_matches(route.get("hosts"), request_host):
            continue
        if not _path_matches(route.get("path_prefixes"), request_target):
            continue
        return idx
    return None


class ProxyRoundRobin:
    def __init__(self):
        self._cursors: dict[int, int] = {}
        self._lock = threading.Lock()

    def next_index(self, route_index: int, upstream_count: int) -> int:
        with self._lock:
            cursor = self._cursors.get(route_index, 0)
            idx = cursor % upstream_count
            self._cursors[route_index] = cursor + 1
            return idx


def _strip_hop_by_hop(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}


def _build_upstream_request(request: dict, upstream: dict, client_ip: str) -> bytes:
    method = request["method"]
    target = request["target"]
    http_version = "HTTP/1.1"

    headers = _strip_hop_by_hop(request.get("headers", {}))

    headers["host"] = f"{upstream['host']}:{upstream['port']}"

    xff = f"{client_ip}, {headers.get('x-forwarded-for', '')}".rstrip(", ")
    headers["x-forwarded-for"] = xff if xff else client_ip
    headers["x-forwarded-proto"] = request.get("scheme", "http")
    headers["x-forwarded-host"] = request.get("headers", {}).get("host", upstream["host"])

    headers.setdefault("user-agent", "UIT-Reverse-Proxy/1.0")
    headers.setdefault("connection", "close")

    request_line = f"{method} {target} {http_version}\r\n"
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())

    body_bytes = request.get("body_bytes", b"")
    if not body_bytes:
        try:
            body_bytes = request.get("body", "").encode("utf-8")
        except Exception:
            body_bytes = b""

    head = (request_line + header_lines + "\r\n").encode("iso-8859-1")
    return head + body_bytes


def forward_request(
    request: dict,
    routes: list[dict[str, Any]],
    route_index: int,
    client_ip: str,
    round_robin: ProxyRoundRobin,
) -> bytes:
    route = routes[route_index]
    upstreams = route.get("upstreams", [])
    if not upstreams:
        return _proxy_error(502, "No upstreams configured", scheme=request.get("scheme", "http"))

    start_idx = round_robin.next_index(route_index, len(upstreams))
    last_error = ""

    for offset in range(len(upstreams)):
        upstream = upstreams[(start_idx + offset) % len(upstreams)]
        result = _try_upstream(request, upstream, client_ip, last_error)
        if isinstance(result, bytes):
            raw_bytes = result
            if b"\r\n\r\n" in raw_bytes:
                return raw_bytes
            return _proxy_error(502, "Empty or invalid upstream response", scheme=request.get("scheme", "http"))
        last_error = result if isinstance(result, str) else str(result)

    if "timeout" in last_error.lower() or "timed out" in last_error.lower():
        return _proxy_error(504, "Gateway Timeout", scheme=request.get("scheme", "http"))
    return _proxy_error(502, "Bad Gateway", scheme=request.get("scheme", "http"))


def _try_upstream(request: dict, upstream: dict, client_ip: str, _last_error: str) -> bytes | str:
    scheme = upstream.get("scheme", "http")
    host = upstream["host"]
    port = upstream.get("port", 443 if scheme == "https" else 80)
    verify_tls = upstream.get("verify_tls", True)

    upstream_request = _build_upstream_request(request, upstream, client_ip)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PROXY_CONNECT_TIMEOUT)
        sock.connect((host, port))

        if scheme == "https":
            sock.settimeout(PROXY_CONNECT_TIMEOUT)
            if verify_tls:
                context = ssl.create_default_context()
            else:
                context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.settimeout(PROXY_READ_TIMEOUT)
        sock.sendall(upstream_request)

        response_chunks = []
        first_byte = True
        while True:
            try:
                chunk = sock.recv(PROXY_BUFFER_SIZE)
                if not chunk:
                    break
                response_chunks.append(chunk)
                first_byte = False
            except socket.timeout:
                if first_byte:
                    return "upstream timeout before first response byte"
                break
            except (ConnectionResetError, OSError):
                if first_byte:
                    return "upstream connection reset before first response byte"
                break

        if not response_chunks:
            return "upstream returned empty response"

        return b"".join(response_chunks)

    except (socket.timeout, TimeoutError):
        return "upstream connection timed out"
    except ssl.SSLError as e:
        return f"upstream TLS error: {e}"
    except ConnectionRefusedError:
        return "upstream connection refused"
    except OSError as e:
        return f"upstream connection error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def _proxy_error(status_code: int, message: str, scheme: str = "http") -> bytes:
    from security import build_security_headers
    return build_response(
        status_code=status_code,
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            **build_security_headers(scheme),
        },
        body=f"{status_code} {message}",
    )
