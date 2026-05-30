"""ThreadPoolExecutor factory with graceful shutdown."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event


def create_pool(max_workers: int = 16) -> tuple[ThreadPoolExecutor, Event]:
    return ThreadPoolExecutor(max_workers=max_workers), Event()
