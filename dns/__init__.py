"""Mini DNS module package."""

from .cache import CacheEntry, DNSCache
from .resolver import StaticResolver

__all__ = [
    "CacheEntry",
    "DNSCache",
    "StaticResolver",
]
