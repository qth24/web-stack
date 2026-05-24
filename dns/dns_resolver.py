"""Resolver layer for the mini DNS module."""

import json
import socket
from typing import Any, Callable, Dict, Optional, Protocol, Tuple


def normalize_domain(raw_domain: str) -> str:
    domain = raw_domain.strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]
    return domain


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False

    labels = domain.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False

    return True


def is_valid_ipv4(ip_address: str) -> bool:
    try:
        socket.inet_aton(ip_address)
    except OSError:
        return False
    return True


class Resolver(Protocol):
    """A domain resolver that returns (ip, ttl) or None for NXDOMAIN."""

    def resolve(self, domain: str) -> Optional[Tuple[str, int]]:
        ...


class StaticResolver:
    """Resolve domain names only from a configured static records table."""

    def __init__(
        self,
        records: Dict[str, Any],
        default_ttl: int = 10,
    ) -> None:
        self.default_ttl = max(1, int(default_ttl))
        self.records: Dict[str, Tuple[str, int]] = {}

        for raw_domain, value in records.items():
            domain = normalize_domain(str(raw_domain))
            if not is_valid_domain(domain):
                continue

            ip: Optional[str] = None
            ttl = self.default_ttl

            if isinstance(value, str):
                ip = value
            elif isinstance(value, dict):
                ip = value.get("ip")
                ttl = value.get("ttl", self.default_ttl)
            else:
                continue

            if not isinstance(ip, str) or not is_valid_ipv4(ip):
                continue

            try:
                ttl = max(1, int(ttl))
            except (TypeError, ValueError):
                ttl = self.default_ttl

            self.records[domain] = (ip, ttl)

    def resolve(self, domain: str) -> Optional[Tuple[str, int]]:
        return self.records.get(domain)


class SystemForwardingResolver:
    """Resolve domains through the host operating system's resolver."""

    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl_seconds = max(1, int(ttl_seconds))

    def resolve(self, domain: str) -> Optional[Tuple[str, int]]:
        try:
            address_infos = socket.getaddrinfo(
                domain,
                None,
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
        except socket.gaierror:
            return None

        for _family, _socktype, _proto, _canonname, sockaddr in address_infos:
            ip_address = sockaddr[0]
            if is_valid_ipv4(ip_address):
                return ip_address, self.ttl_seconds

        return None


class HybridResolver:
    """Resolve from local records first, then fall back to the system resolver."""

    def __init__(self, static_resolver: Resolver, forwarding_resolver: Resolver) -> None:
        self.static_resolver = static_resolver
        self.forwarding_resolver = forwarding_resolver

    def resolve(self, domain: str) -> Optional[Tuple[str, int]]:
        result = self.static_resolver.resolve(domain)
        if result is not None:
            return result
        return self.forwarding_resolver.resolve(domain)


def create_resolver(
    mode: str,
    records: Dict[str, Any],
    default_ttl: int = 10,
    forward_ttl_seconds: int = 60,
) -> Resolver:
    """Build a resolver for the configured mode."""
    normalized_mode = (mode or "").strip().lower()
    static_resolver = StaticResolver(records, default_ttl)

    if normalized_mode == "static":
        return static_resolver

    forwarding_resolver = SystemForwardingResolver(ttl_seconds=forward_ttl_seconds)

    if normalized_mode == "forward":
        return forwarding_resolver

    if normalized_mode == "hybrid":
        return HybridResolver(static_resolver, forwarding_resolver)

    raise ValueError(f"Unsupported DNS resolver mode: {mode!r}")


def load_records_from_file(path: str, logger: Optional[Callable[[str, str, Optional[str]], None]] = None) -> Dict[str, Any]:
    def _log(tag: str, message: str, color: Optional[str] = None) -> None:
        if logger:
            logger(tag, message, color)

    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            data = json.load(file_obj)
    except FileNotFoundError:
        _log("ERROR", f"Records file not found: {path}. No records loaded.", "31")
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        _log("ERROR", f"Cannot read records file: {exc}. No records loaded.", "31")
        return {}

    if not isinstance(data, dict):
        _log("ERROR", "Records file root must be an object. No records loaded.", "31")
        return {}

    return data
