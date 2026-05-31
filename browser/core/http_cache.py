"""Disk-backed HTTP cache for GET responses from the custom loader.

Cache entries stored under STATE_DIR/http_cache/:
  manifest.json  — LRU metadata and entry index
  entries/<key>.bin — serialized response bodies

Only caches 200 OK GET responses. Skips requests/responses with
Cookie/Set-Cookie headers or Cache-Control: no-store.
"""

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class CacheEntry:
    scheme: str
    host: str
    port: int
    path: str
    status_code: int
    status_text: str
    headers: dict[str, str]
    body_bytes: bytes
    created_at: float = field(default_factory=time.time)
    fresh_until: Optional[float] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    body_size: int = 0

    def __post_init__(self):
        self.body_size = len(self.body_bytes)

    @property
    def is_fresh(self) -> bool:
        if self.fresh_until is not None and self.fresh_until > time.time():
            return True
        return False

    def is_stale(self) -> bool:
        return not self.is_fresh

    def can_revalidate(self) -> bool:
        return self.etag is not None or self.last_modified is not None


def _derive_key(scheme: str, host: str, port: int, path: str) -> str:
    raw = f"{scheme}://{host}:{port}{path}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _compute_fresh_until(headers: dict[str, str]) -> Optional[float]:
    cc = headers.get("Cache-Control", "").lower()
    if "no-cache" in cc:
        return None
    if "max-age=" in cc:
        for part in cc.split(","):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    return time.time() + int(part.split("=", 1)[1])
                except ValueError:
                    pass
    expires = headers.get("Expires", "")
    if expires:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(expires)
            return dt.timestamp()
        except Exception:
            pass
    return None


def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.strip().title(): v.strip() for k, v in headers.items()}


class HTTPCache:
    def __init__(self, cache_dir: Path, max_mb: int = 64, max_entry_mb: int = 4):
        self._cache_dir = Path(cache_dir)
        self._entries_dir = self._cache_dir / "entries"
        self._manifest_path = self._cache_dir / "manifest.json"
        self._max_bytes = max_mb * 1024 * 1024
        self._max_entry_bytes = max_entry_mb * 1024 * 1024
        self._manifest: dict[str, Any] = {"entries": {}, "total_size": 0}
        self._loaded = False
        self._async_lock: asyncio.Lock | None = None

    def _get_async_lock(self) -> asyncio.Lock:
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._entries_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(self._manifest_path, "r", encoding="utf-8") as f:
                self._manifest = json.load(f)
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            self._manifest = {"entries": {}, "total_size": 0}
        if not isinstance(self._manifest, dict):
            self._manifest = {"entries": {}, "total_size": 0}
        self._manifest.setdefault("entries", {})
        self._manifest.setdefault("total_size", 0)
        self._loaded = True

    def _save_manifest(self) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        with open(self._manifest_path, "w", encoding="utf-8") as f:
            json.dump(self._manifest, f, indent=2)

    def _entry_path(self, key: str) -> Path:
        return self._entries_dir / f"{key}.bin"

    def lookup(self, scheme: str, host: str, port: int, path: str) -> Optional[CacheEntry]:
        self._ensure_loaded()
        key = _derive_key(scheme, host, port, path)
        meta = self._manifest["entries"].get(key)
        if meta is None:
            return None
        entry_path = self._entry_path(key)
        if not entry_path.exists():
            self._remove_manifest_entry(key)
            return None
        try:
            data = json.loads(entry_path.read_bytes().decode("utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            self._remove_manifest_entry(key)
            return None
        entry = CacheEntry(
            scheme=data.get("scheme", scheme),
            host=data.get("host", host),
            port=data.get("port", port),
            path=data.get("path", path),
            status_code=data.get("status_code", 200),
            status_text=data.get("status_text", ""),
            headers=data.get("headers", {}),
            body_bytes=bytes(data.get("body_base64", "")),
            created_at=data.get("created_at", time.time()),
            fresh_until=data.get("fresh_until"),
            etag=data.get("etag"),
            last_modified=data.get("last_modified"),
            body_size=data.get("body_size", 0),
        )
        meta["last_access"] = time.time()
        return entry

    def store(
        self,
        scheme: str,
        host: str,
        port: int,
        path: str,
        status_code: int,
        status_text: str,
        headers: dict[str, str],
        body_bytes: bytes,
    ) -> Optional[CacheEntry]:
        self._ensure_loaded()
        norms = _normalize_headers(headers)

        cc = norms.get("Cache-Control", "").lower()
        if "no-store" in cc:
            return None

        if status_code != 200:
            return None

        fresh_until = _compute_fresh_until(norms)
        etag = norms.get("Etag")
        last_modified = norms.get("Last-Modified")

        if fresh_until is None and etag is None and last_modified is None:
            return None

        entry = CacheEntry(
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            status_code=status_code,
            status_text=status_text,
            headers=headers,
            body_bytes=body_bytes,
            created_at=time.time(),
            fresh_until=fresh_until,
            etag=etag,
            last_modified=last_modified,
        )

        if entry.body_size > self._max_entry_bytes:
            return None

        key = _derive_key(scheme, host, port, path)

        self._evict_lru_if_needed(entry.body_size)

        entry_data = {
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "status_code": status_code,
            "status_text": status_text,
            "headers": headers,
            "body_base64": list(body_bytes),
            "created_at": entry.created_at,
            "fresh_until": entry.fresh_until,
            "etag": entry.etag,
            "last_modified": entry.last_modified,
            "body_size": entry.body_size,
        }
        entry_path = self._entry_path(key)
        entry_path.write_bytes(json.dumps(entry_data).encode("utf-8"))

        old_meta = self._manifest["entries"].get(key)
        old_size = old_meta.get("size", 0) if old_meta else 0

        self._manifest["entries"][key] = {
            "size": entry.body_size,
            "last_access": time.time(),
            "created_at": entry.created_at,
        }
        self._manifest["total_size"] = max(0, self._manifest["total_size"] - old_size + entry.body_size)
        self._save_manifest()
        return entry

    def _evict_lru_if_needed(self, incoming_size: int) -> None:
        while self._manifest["total_size"] + incoming_size > self._max_bytes and self._manifest["entries"]:
            lru_key = min(
                self._manifest["entries"].keys(),
                key=lambda k: self._manifest["entries"][k].get("last_access", 0),
            )
            self._remove_entry(lru_key)

    def _remove_entry(self, key: str) -> None:
        meta = self._manifest["entries"].pop(key, None)
        if meta:
            self._manifest["total_size"] = max(0, self._manifest["total_size"] - meta.get("size", 0))
        entry_path = self._entry_path(key)
        try:
            entry_path.unlink(missing_ok=True)
        except OSError:
            pass
        self._save_manifest()

    def _remove_manifest_entry(self, key: str) -> None:
        meta = self._manifest["entries"].pop(key, None)
        if meta:
            self._manifest["total_size"] = max(0, self._manifest["total_size"] - meta.get("size", 0))
        self._save_manifest()

    def clear(self) -> None:
        self._ensure_loaded()
        for key in list(self._manifest["entries"].keys()):
            entry_path = self._entry_path(key)
            try:
                entry_path.unlink(missing_ok=True)
            except OSError:
                pass
        self._manifest = {"entries": {}, "total_size": 0}
        self._save_manifest()

    def entry_count(self) -> int:
        self._ensure_loaded()
        return len(self._manifest["entries"])

    def total_size_bytes(self) -> int:
        self._ensure_loaded()
        return self._manifest["total_size"]

    async def lookup_async(self, scheme: str, host: str, port: int, path: str) -> Optional[CacheEntry]:
        async with self._get_async_lock():
            return await asyncio.to_thread(self.lookup, scheme, host, port, path)

    async def store_async(
        self,
        scheme: str,
        host: str,
        port: int,
        path: str,
        status_code: int,
        status_text: str,
        headers: dict[str, str],
        body_bytes: bytes,
    ) -> Optional[CacheEntry]:
        async with self._get_async_lock():
            return await asyncio.to_thread(
                self.store,
                scheme,
                host,
                port,
                path,
                status_code,
                status_text,
                headers,
                body_bytes,
            )
