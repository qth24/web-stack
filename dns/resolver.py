"""Static authoritative DNS resolver."""

import json
import re

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class StaticResolver:

    def __init__(self, records_path: str):
        with open(records_path) as f:
            raw = json.load(f)
        self._zone: dict[str, tuple[str, int]] = {}
        for domain, value in raw.items():
            if isinstance(value, str):
                ip = value
                ttl = 300
            elif isinstance(value, dict):
                ip = value.get("ip", "")
                ttl = value.get("ttl", 300)
            else:
                continue
            if not ip or not _IPV4_RE.match(ip):
                continue
            self._zone[domain] = (ip, ttl)

    def resolve(self, domain: str) -> tuple[str, int] | None:
        return self._zone.get(domain.lower(), None)

    def has_domain(self, domain: str) -> bool:
        return domain.lower() in self._zone
