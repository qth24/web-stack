"""Network/handler layer for the mini DNS UDP+JSON module."""

import argparse
import socket
import sys
import time
from typing import Any, Dict, Optional, Tuple

try:
    from . import config
    from .dns_cache import DNSCache
    from .dns_resolver import StaticResolver, load_records_from_file
    from .protocol import (
        STATUS_BAD_REQUEST,
        STATUS_ERROR,
        STATUS_NXDOMAIN,
        STATUS_RATE_LIMITED,
        ProtocolError,
        build_error_response,
        build_success_response,
        decode_request,
        encode_response,
    )
    from .rate_limiter import RateLimiter
except ImportError:
    import config
    from dns_cache import DNSCache
    from dns_resolver import StaticResolver, load_records_from_file
    from protocol import (
        STATUS_BAD_REQUEST,
        STATUS_ERROR,
        STATUS_NXDOMAIN,
        STATUS_RATE_LIMITED,
        ProtocolError,
        build_error_response,
        build_success_response,
        decode_request,
        encode_response,
    )
    from rate_limiter import RateLimiter


MAX_UDP_REQUEST_BYTES = config.MAX_REQUEST_BYTES
MAX_UDP_RESPONSE_BYTES = config.MAX_RESPONSE_BYTES


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
    """Parse a UDP JSON request, then consult cache/resolver and build a response."""

    def __init__(
        self,
        cache: DNSCache,
        resolver: StaticResolver,
        max_request_bytes: int = MAX_UDP_REQUEST_BYTES,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self.cache = cache
        self.resolver = resolver
        self.max_request_bytes = max(64, int(max_request_bytes))
        self.rate_limiter = rate_limiter

    def handle_packet(self, payload: bytes, client_addr: Tuple[str, int]) -> Dict[str, Any]:
        if len(payload) > self.max_request_bytes:
            message = f"UDP packet too large (max {self.max_request_bytes} bytes)"
            log_event("ERROR", f"{client_addr} {message}", "31")
            return build_error_response(STATUS_BAD_REQUEST, message)

        try:
            request = decode_request(payload)
        except ProtocolError as exc:
            log_event("ERROR", f"{client_addr} {exc}", "31")
            return build_error_response(
                exc.status,
                str(exc),
                request_id=exc.request_id,
                domain=exc.domain,
                qtype=exc.qtype,
            )

        if self.rate_limiter is not None:
            client_ip = client_addr[0]
            if not self.rate_limiter.is_allowed(client_ip):
                retry_after = self.rate_limiter.get_retry_after(client_ip)
                log_event("RATE LIMIT", f"{client_ip} exceeded limit", "31")
                return build_error_response(
                    STATUS_RATE_LIMITED,
                    "Rate limit exceeded. Try again later.",
                    request_id=request.request_id,
                    domain=request.domain,
                    qtype=request.qtype,
                    retry_after=retry_after,
                )

        now = time.time()
        entry, cache_state = self.cache.get(request.domain, now)

        if cache_state == "HIT":
            remaining = max(0.0, entry.expire_at - now) if entry else 0.0
            log_event(
                "CACHE HIT",
                f"{request.domain} -> {entry.ip} (remaining={remaining:.2f}s)",
                "32",
            )
            return build_success_response(request, entry.ip, int(remaining))

        if cache_state == "EXPIRED":
            log_event("CACHE EXPIRED", f"{request.domain} stale entry removed", "38;5;214")

        log_event("CACHE MISS", f"{request.domain} not in cache", "33")
        resolved = self.resolver.resolve(request.domain)

        if resolved is None:
            log_event("NXDOMAIN", f"{request.domain} not found", "31")
            return build_error_response(
                STATUS_NXDOMAIN,
                "Domain not found",
                request_id=request.request_id,
                domain=request.domain,
                qtype=request.qtype,
            )

        ip, ttl = resolved
        self.cache.set(request.domain, ip, ttl, now)
        log_event("CACHE UPDATED", f"{request.domain} -> {ip} (ttl={ttl}s)", "34")
        return build_success_response(request, ip, ttl)


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
        try:
            self.socket.bind((self.host, self.port))
        except PermissionError as exc:
            self.socket.close()
            raise RuntimeError(
                f"Cannot bind UDP {self.host}:{self.port}: permission denied. "
                "Use a high local dev port such as 5336, or run with privileges for port 53."
            ) from exc
        except OSError as exc:
            self.socket.close()
            if exc.errno == 98:
                raise RuntimeError(
                    f"Cannot bind UDP {self.host}:{self.port}: address already in use. "
                    "Stop the other DNS server or choose another DNS_PORT."
                ) from exc
            raise

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
                response = build_error_response(STATUS_ERROR, "Internal server error")

            try:
                data = encode_response(response)
                if len(data) > self.max_response_bytes:
                    log_event(
                        "ERROR",
                        f"Response too large for {client_addr}; sending fallback error",
                        "31",
                    )
                    fallback = build_error_response(STATUS_ERROR, "Internal response too large")
                    data = encode_response(fallback)
                self.socket.sendto(data, client_addr)
            except (OSError, TypeError, ValueError) as exc:
                log_event("ERROR", f"Failed to send response to {client_addr}: {exc}", "31")


def build_server(args: argparse.Namespace) -> MiniDNSServer:
    records = load_records_from_file(args.records, logger=log_event)
    cache = DNSCache()

    resolver = StaticResolver(
        records=records,
        default_ttl=args.default_ttl,
    )

    if not resolver.records:
        log_event("ERROR", "No valid static records loaded. All lookups will return NXDOMAIN.", "31")
    log_event("INFO", f"Loaded {len(resolver.records)} static DNS records")

    rate_limiter = RateLimiter(
        max_queries=config.RATE_LIMIT_MAX_QUERIES,
        window_seconds=config.RATE_LIMIT_WINDOW_SECONDS,
    )

    handler = DNSRequestHandler(
        cache=cache,
        resolver=resolver,
        max_request_bytes=args.max_request_bytes,
        rate_limiter=rate_limiter,
    )
    return MiniDNSServer(
        host=args.host,
        port=args.port,
        handler=handler,
        max_request_bytes=args.max_request_bytes,
        max_response_bytes=args.max_response_bytes,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Static UDP JSON DNS server")
    parser.add_argument(
        "--host",
        default=config.BIND_HOST,
        help=f"Bind host (default: {config.BIND_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=config.PORT,
        help=f"UDP port (default: {config.PORT})",
    )
    parser.add_argument(
        "--records",
        default=config.RECORDS_PATH,
        help=f"Path to static DNS record file (default: {config.RECORDS_PATH})",
    )
    parser.add_argument(
        "--default-ttl",
        type=int,
        default=config.DEFAULT_TTL,
        help=f"Default TTL in seconds (default: {config.DEFAULT_TTL})",
    )
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
    try:
        server = build_server(args)
    except RuntimeError as exc:
        log_event("ERROR", str(exc), "31")
        raise SystemExit(1) from exc
    server.serve_forever()


if __name__ == "__main__":
    main()
