"""Static authoritative DNS resolver."""

import json


class StaticResolver:

    def __init__(self, records_path: str):
        with open(records_path) as f:
            raw = json.load(f)
        self._zone: dict[str, tuple[str, int]] = {}
        for domain, value in raw.items():
            if isinstance(value, str):
                self._zone[domain] = (value, 300)
            elif isinstance(value, dict):
                self._zone[domain] = (value.get("ip", ""), value.get("ttl", 300))

    def resolve(self, domain: str) -> tuple[str, int] | None:
        return self._zone.get(domain.lower(), None)

    def has_domain(self, domain: str) -> bool:
        return domain.lower() in self._zone
