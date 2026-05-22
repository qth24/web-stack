"""Mini DNS module package."""

from .dns_cache import CacheEntry, DNSCache
from .dns_resolver import StaticResolver, load_records_from_file

__all__ = [
    "CacheEntry",
    "DNSCache",
    "StaticResolver",
    "load_records_from_file",
]
