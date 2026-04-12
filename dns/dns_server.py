"""Network/handler layer for mini DNS module."""

import argparse
import json
import socket
import sys
import time
from typing import Any, Dict, Optional, Tuple

try:
    from .dns_cache import DNSCache
    from .dns_resolver import (
        DEFAULT_RECORDS,
        StaticResolver,
        is_valid_domain,
        load_records_from_file,
        normalize_domain,
    )
except ImportError:
    from dns_cache import DNSCache
    from dns_resolver import (
        DEFAULT_RECORDS,
        StaticResolver,
        is_valid_domain,
        load_records_from_file,
        normalize_domain,
    )


MAX_UDP_REQUEST_BYTES = 1024
MAX_UDP_RESPONSE_BYTES = 2048


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _colorize(text: str, code: Optional[str]) -> str:
    if not code or not _supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def log_event(tag: str, message: str, color_code: Optional[str] = None) -> None:
    timestamp = time.strftime("%H:%M:%S")
    label = _colorize(f"[{tag}]", color_code)
    print(f"{timestamp} {label} {message}")


class DNSRequestHandler:
    """Parse request, consult cache/resolver, build JSON response."""

    def __init__(
        self,
        cache: DNSCache,
        resolver: StaticResolver,
        max_request_bytes: int = MAX_UDP_REQUEST_BYTES,
    ) -> None:
        self.cache = cache
        self.resolver = resolver
        self.max_request_bytes = max(64, int(max_request_bytes))

    def handle_packet(self, payload: bytes, client_addr: Tuple[str, int]) -> Dict[str, Any]:
        if len(payload) > self.max_request_bytes:
            message = f"UDP packet too large (max {self.max_request_bytes} bytes)"
            log_event("ERROR", f"{client_addr} {message}", "31")
            return {
                "status": "BAD_REQUEST",
                "domain": None,
                "ip": None,
                "message": message,
            }

        request, error_message = self._parse_request(payload)
        if error_message:
            log_event("ERROR", f"{client_addr} {error_message}", "31")
            return {
                "status": "BAD_REQUEST",
                "domain": None,
                "ip": None,
                "message": error_message,
            }

        raw_domain = request["domain"]
        domain = normalize_domain(raw_domain)

        if not is_valid_domain(domain):
            message = "Invalid domain format"
            log_event("ERROR", f"{client_addr} {message}: {raw_domain!r}", "31")
            return {
                "status": "BAD_REQUEST",
                "domain": raw_domain,
                "ip": None,
                "message": message,
            }

        now = time.time()
        entry, cache_state = self.cache.get(domain, now)

        if cache_state == "HIT":
            remaining = max(0.0, entry.expire_at - now) if entry else 0.0
            log_event("CACHE HIT", f"{domain} -> {entry.ip} (remaining={remaining:.2f}s)", "32")
            return self._ok_response(domain, entry.ip, entry.expire_at)

        if cache_state == "EXPIRED":
            log_event("CACHE EXPIRED", f"{domain} stale entry removed", "38;5;214")

        log_event("CACHE MISS", f"{domain} not in cache", "33")
        resolved = self.resolver.resolve(domain)

        if resolved is None:
            log_event("NXDOMAIN", f"{domain} not found", "31")
            return {
                "status": "NXDOMAIN",
                "domain": domain,
                "ip": None,
                "message": "Domain not found",
            }

        ip, ttl = resolved
        new_entry = self.cache.set(domain, ip, ttl, now)
        log_event("CACHE UPDATED", f"{domain} -> {ip} (ttl={ttl}s)", "34")
        return self._ok_response(domain, ip, new_entry.expire_at)

    @staticmethod
    def _parse_request(payload: bytes) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not payload:
            return None, "Empty UDP packet"

        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None, "Request must be UTF-8 encoded JSON"

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, RecursionError, ValueError):
            return None, "Invalid JSON payload"

        if not isinstance(data, dict):
            return None, "JSON root must be an object"

        domain = data.get("domain")
        if not isinstance(domain, str):
            return None, "Missing or invalid 'domain' field"

        if not domain.strip():
            return None, "Domain cannot be empty"

        return {"domain": domain}, None

    @staticmethod
    def _ok_response(domain: str, ip: str, expire_at: float) -> Dict[str, Any]:
        return {
            "status": "OK",
            "domain": domain,
            "ip": ip,
            "expire_at": round(expire_at, 3),
        }


class MiniDNSServer:
    """Single-thread UDP server loop using recvfrom."""

    def __init__(
        self,
        host: str,
        port: int,
        handler: DNSRequestHandler,
        max_request_bytes: int = MAX_UDP_REQUEST_BYTES,
        max_response_bytes: int = MAX_UDP_RESPONSE_BYTES,
    ) -> None:
        self.host = host
        self.port = port
        self.handler = handler
        self.max_request_bytes = max(64, int(max_request_bytes))
        self.max_response_bytes = max(128, int(max_response_bytes))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))

    def serve_forever(self) -> None:
        log_event("INFO", f"DNS server listening on {self.host}:{self.port}")
        while True:
            try:
                payload, client_addr = self.socket.recvfrom(self.max_request_bytes + 1)
            except KeyboardInterrupt:
                log_event("INFO", "Shutdown requested by user")
                break
            except OSError as exc:
                log_event("ERROR", f"Socket receive error: {exc}", "31")
                continue

            try:
                response = self.handler.handle_packet(payload, client_addr)
            except Exception as exc:
                log_event("ERROR", f"Unexpected handler error for {client_addr}: {exc}", "31")
                response = {
                    "status": "ERROR",
                    "domain": None,
                    "ip": None,
                    "message": "Internal server error",
                }

            try:
                data = json.dumps(response, ensure_ascii=True).encode("utf-8")
                if len(data) > self.max_response_bytes:
                    log_event(
                        "ERROR",
                        f"Response too large for {client_addr}; sending fallback error",
                        "31",
                    )
                    fallback = {
                        "status": "ERROR",
                        "domain": None,
                        "ip": None,
                        "message": "Internal response too large",
                    }
                    data = json.dumps(fallback, ensure_ascii=True).encode("utf-8")
                self.socket.sendto(data, client_addr)
            except (OSError, TypeError, ValueError) as exc:
                log_event("ERROR", f"Failed to send response to {client_addr}: {exc}", "31")


def build_server(args: argparse.Namespace) -> MiniDNSServer:
    records = load_records_from_file(args.records, logger=log_event)
    cache = DNSCache()
    resolver = StaticResolver(records=records, default_ttl=args.default_ttl)

    if not resolver.records:
        log_event("ERROR", "No valid records loaded. Falling back to built-in defaults.", "31")
        resolver = StaticResolver(records=DEFAULT_RECORDS, default_ttl=args.default_ttl)

    handler = DNSRequestHandler(
        cache=cache,
        resolver=resolver,
        max_request_bytes=args.max_request_bytes,
    )
    return MiniDNSServer(
        host=args.host,
        port=args.port,
        handler=handler,
        max_request_bytes=args.max_request_bytes,
        max_response_bytes=args.max_response_bytes,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mini UDP DNS server with TTL cache")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5200, help="UDP port (default: 5200)")
    parser.add_argument(
        "--records",
        default="dns/dns_records.json",
        help="Path to static DNS record file (default: dns/dns_records.json)",
    )
    parser.add_argument("--default-ttl", type=int, default=5, help="Default TTL in seconds")
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=MAX_UDP_REQUEST_BYTES,
        help="Maximum UDP request size in bytes",
    )
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=MAX_UDP_RESPONSE_BYTES,
        help="Maximum UDP response size in bytes",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = build_server(args)
    server.serve_forever()


if __name__ == "__main__":
    main()
