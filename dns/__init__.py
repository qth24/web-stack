"""Mini DNS module package."""

from .dns_cache import CacheEntry, DNSCache
from .dns_resolver import (
    HybridResolver,
    StaticResolver,
    SystemForwardingResolver,
    create_resolver,
    load_records_from_file,
)

__all__ = [
    "CacheEntry",
    "DNSCache",
    "HybridResolver",
    "StaticResolver",
    "SystemForwardingResolver",
    "create_resolver",
    "load_records_from_file",
]
