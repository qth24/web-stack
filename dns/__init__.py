"""Mini DNS module package."""

from .dns_cache import CacheEntry, DNSCache
from .dns_resolver import DEFAULT_RECORDS, StaticResolver, load_records_from_file

__all__ = [
    "CacheEntry",
    "DNSCache",
    "DEFAULT_RECORDS",
    "StaticResolver",
    "load_records_from_file",
]
