"""TTL-based in-memory DNS response cache with thread safety."""

import time
import threading
from typing import Optional
from dataclasses import dataclass


@dataclass
class CacheEntry:
    ip: bytes
    ttl: int
    created_at: float


class DNSCache:

    def __init__(self, max_size: int = 10000):
        self._store: dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self._max_size = max_size

    def get(self, domain: str) -> Optional[CacheEntry]:
        domain = domain.lower()
        with self._lock:
            entry = self._store.get(domain)
            if entry is None:
                return None
            if time.time() - entry.created_at > entry.ttl:
                del self._store[domain]
                return None
            return entry

    def put(self, domain: str, ip: bytes, ttl: int):
        domain = domain.lower()
        with self._lock:
            if len(self._store) >= self._max_size:
                oldest = min(self._store, key=lambda k: self._store[k].created_at)
                del self._store[oldest]
            self._store[domain] = CacheEntry(ip=ip, ttl=ttl, created_at=time.time())
