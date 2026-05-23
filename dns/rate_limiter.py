"""Sliding window rate limiter for per-client-IP query throttling."""

import time
from collections import defaultdict
from typing import Dict, List


class RateLimiter:
    """Sliding window rate limiter that tracks query timestamps per client IP.

    Uses a list of timestamps per IP. On each check, entries older than the
    window are pruned, then the remaining count is compared against the limit.
    """

    def __init__(self, max_queries: int, window_seconds: float) -> None:
        """Initialize the rate limiter.

        Args:
            max_queries: Maximum number of queries allowed within the window.
            window_seconds: Size of the sliding window in seconds.
        """
        self.max_queries = max(1, int(max_queries))
        self.window_seconds = max(0.1, float(window_seconds))
        self._timestamps: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        """Check whether a query from *client_ip* is allowed.

        Records the current timestamp if allowed. Prunes expired entries
        before checking.

        Args:
            client_ip: The client IP address string.

        Returns:
            True if the query is within the rate limit, False otherwise.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune entries older than the window.
        timestamps = self._timestamps[client_ip]
        self._timestamps[client_ip] = [ts for ts in timestamps if ts > cutoff]
        timestamps = self._timestamps[client_ip]

        if len(timestamps) >= self.max_queries:
            return False

        timestamps.append(now)
        return True

    def get_retry_after(self, client_ip: str) -> float:
        """Return seconds until the client IP can make another query.

        Based on the oldest timestamp still within the window. If no
        timestamps exist, returns 0.0.

        Args:
            client_ip: The client IP address string.

        Returns:
            Seconds to wait before the next query is allowed.
        """
        now = time.time()
        cutoff = now - self.window_seconds
        timestamps = self._timestamps.get(client_ip, [])

        # Keep only timestamps within the window.
        valid = [ts for ts in timestamps if ts > cutoff]
        if not valid:
            return 0.0

        # The oldest valid timestamp determines when a slot opens.
        oldest = min(valid)
        retry_after = (oldest + self.window_seconds) - now
        return max(0.0, round(retry_after, 2))
