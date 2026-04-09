"""Cache layer for mini DNS module."""

import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class CacheEntry:
    ip: str
    expire_at: float
    ttl: int


class DNSCache:
    """In-memory TTL cache with lazy deletion."""

    def __init__(self) -> None:
        self._entries: Dict[str, CacheEntry] = {}

    def get(self, domain: str, now: Optional[float] = None) -> Tuple[Optional[CacheEntry], str]:
        now_ts = time.time() if now is None else now
        entry = self._entries.get(domain)

        if entry is None:
            return None, "MISS"

        if entry.expire_at <= now_ts:
            del self._entries[domain]
            return None, "EXPIRED"

        return entry, "HIT"

    def set(self, domain: str, ip: str, ttl: int, now: Optional[float] = None) -> CacheEntry:
        now_ts = time.time() if now is None else now
        ttl_value = max(1, int(ttl))
        entry = CacheEntry(ip=ip, expire_at=now_ts + ttl_value, ttl=ttl_value)
        self._entries[domain] = entry
        return entry
