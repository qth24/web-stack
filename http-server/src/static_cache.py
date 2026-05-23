"""In-memory cache for static files with TTL expiry and max-size eviction."""

import hashlib
import time
from collections import OrderedDict


class StaticCache:
    """Dict-based cache mapping file_path -> (content_bytes, etag, last_modified, content_type).

    Evicts oldest entries when max_size is reached.
    Entries expire after ttl_seconds.
    """

    def __init__(self, max_size=100, ttl_seconds=60):
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._store = OrderedDict()

    def get(self, file_path):
        """Return cached entry if valid, or None."""
        if file_path not in self._store:
            return None

        content_bytes, etag, last_modified, content_type = self._store[file_path]

        if time.time() - last_modified > self._ttl_seconds:
            del self._store[file_path]
            return None

        # Move to end (most recently used)
        self._store.move_to_end(file_path)
        return content_bytes, etag, last_modified, content_type

    def put(self, file_path, content_bytes, etag, content_type):
        """Store an entry, evicting oldest if at capacity."""
        if file_path in self._store:
            del self._store[file_path]

        while len(self._store) >= self._max_size:
            self._store.popitem(last=False)

        self._store[file_path] = (content_bytes, etag, time.time(), content_type)

    @staticmethod
    def compute_etag(content_bytes):
        """Compute MD5 ETag from file content, formatted as \"<hex>\"."""
        return '"' + hashlib.md5(content_bytes).hexdigest() + '"'


# Module-level singleton
static_cache = StaticCache()
