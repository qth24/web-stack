import threading
import time


class Metrics:
    def __init__(self):
        self._active_connections = 0
        self._total_requests = 0
        self._lock = threading.Lock()
        self._start_time = time.time()

    def inc_connections(self):
        with self._lock:
            self._active_connections += 1

    def dec_connections(self):
        with self._lock:
            self._active_connections -= 1

    def inc_requests(self):
        with self._lock:
            self._total_requests += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "active_connections": self._active_connections,
                "total_requests": self._total_requests,
                "uptime_seconds": int(time.time() - self._start_time),
            }
