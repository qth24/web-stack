"""Static resolver layer for mini DNS module."""

import json
import socket
from typing import Any, Callable, Dict, Optional, Tuple


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
