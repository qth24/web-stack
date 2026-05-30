import threading


class BackendPool:
    def __init__(self, backends: list[str], health_path: str = "/health"):
        self._backends = [(url.strip(), True) for url in backends]
        self._cursor = 0
        self._lock = threading.Lock()
        self._health_path = health_path

    def next_backend(self) -> str | None:
        with self._lock:
            healthy = [(url, is_h) for url, is_h in self._backends if is_h]
            if not healthy:
                return None
            idx = self._cursor % len(healthy)
            self._cursor += 1
            return healthy[idx][0]

    def mark_down(self, url: str):
        with self._lock:
            for i, (b_url, _) in enumerate(self._backends):
                if b_url == url:
                    self._backends[i] = (url, False)
                    return

    def mark_up(self, url: str):
        with self._lock:
            for i, (b_url, _) in enumerate(self._backends):
                if b_url == url:
                    self._backends[i] = (url, True)
                    return

    def status(self) -> dict:
        with self._lock:
            return {
                "backends": [{"url": url, "healthy": h} for url, h in self._backends],
                "healthy_count": sum(1 for _, h in self._backends if h),
            }
