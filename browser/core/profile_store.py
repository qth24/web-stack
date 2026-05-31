"""Server-backed encrypted profile store and ephemeral guest profile model."""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any

from browser.core.profile_crypto import (
    ProfileCryptoError,
    decrypt_json,
    deterministic_entry_id,
    encrypt_json,
    unwrap_local_profile_key,
    unwrap_profile_key,
    wrap_local_profile_key,
    wrap_profile_key,
)


PROFILE_COLLECTIONS = ("settings", "bookmarks", "shortcuts", "history")


class ProfileStoreError(RuntimeError):
    """Raised when the browser profile store cannot load or persist data."""


def now_string() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


class EphemeralGuestProfileStore:
    def __init__(self, default_bookmarks: list[str]):
        self._data = {
            "settings": {},
            "bookmarks": [str(url) for url in default_bookmarks],
            "shortcuts": [
                {"name": _short_label(str(url)), "url": str(url)}
                for url in default_bookmarks
                if str(url).strip()
            ][:12],
            "history": [],
        }
        self.current_user = {
            "id": "guest",
            "username": "guest",
            "display_name": "Guest",
            "is_local": True,
            "encrypted": False,
        }

    def load_profile_data(self) -> dict[str, Any]:
        return _deep_copy(self._data)

    async def sync_state(
        self,
        settings: dict[str, Any],
        bookmarks: list[str],
        shortcuts: list[dict[str, str]],
        history: list[dict[str, str]],
    ) -> dict[str, Any]:
        self._data = {
            "settings": _deep_copy(settings),
            "bookmarks": [str(url) for url in bookmarks if str(url).strip()],
            "shortcuts": [
                {"name": str(item.get("name", "")).strip() or _short_label(str(item.get("url", "")).strip()),
                 "url": str(item.get("url", "")).strip()}
                for item in shortcuts
                if str(item.get("url", "")).strip()
            ][:12],
            "history": [
                {
                    "url": str(item.get("url", "")).strip(),
                    "title": str(item.get("title", "")).strip(),
                    "visited_at": str(item.get("visited_at", "")).strip() or now_string(),
                }
                for item in history
                if str(item.get("url", "")).strip()
            ][:300],
        }
        return self.load_profile_data()

    def clear_local_key(self) -> None:
        return


class RemoteEncryptedProfileStore:
    def __init__(self, api_client: Any, state_dir: Path, user: dict[str, Any]):
        self.api_client = api_client
        self.state_dir = Path(state_dir)
        self.user = {
            "id": int(user["id"]),
            "username": str(user["username"]),
            "display_name": str(user.get("display_name") or user["username"]),
            "is_local": False,
            "encrypted": True,
        }
        self._master_key: bytes | None = None
        self._shadow: dict[str, dict[str, dict[str, Any]]] = {name: {} for name in PROFILE_COLLECTIONS}
        self._profile_data = {
            "settings": {},
            "bookmarks": [],
            "shortcuts": [],
            "history": [],
        }

    @property
    def device_key_path(self) -> Path:
        return self.state_dir / "device_profile.key"

    @property
    def remember_path(self) -> Path:
        return self.state_dir / "remembered_profiles.json"

    def load_profile_data(self) -> dict[str, Any]:
        return _deep_copy(self._profile_data)

    async def bootstrap_with_password(self, password: str) -> dict[str, Any]:
        bootstrap = await self.api_client.get_profile_bootstrap()
        record = bootstrap.get("profile_key")
        if record:
            try:
                self._master_key = unwrap_profile_key(record, password)
            except ProfileCryptoError as exc:
                raise ProfileStoreError(str(exc)) from exc
        else:
            self._master_key = secrets.token_bytes(32)
            await self.api_client.set_profile_key(wrap_profile_key(self._master_key, password))
            bootstrap = await self.api_client.get_profile_bootstrap()
        self._persist_local_key()
        self._apply_bootstrap(bootstrap)
        return self.load_profile_data()

    async def restore_from_saved_key(self) -> bool:
        local_key = self._read_local_key()
        if local_key is None:
            return False
        self._master_key = local_key
        bootstrap = await self.api_client.get_profile_bootstrap()
        if bootstrap.get("profile_key") is None:
            return False
        self._apply_bootstrap(bootstrap)
        return True

    def clear_local_key(self) -> None:
        try:
            if not self.remember_path.exists():
                return
            data = json.loads(self.remember_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        key = str(self.user["id"])
        if key in data:
            data.pop(key, None)
            try:
                self.remember_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except OSError:
                pass

    async def sync_state(
        self,
        settings: dict[str, Any],
        bookmarks: list[str],
        shortcuts: list[dict[str, str]],
        history: list[dict[str, str]],
    ) -> dict[str, Any]:
        if self._master_key is None:
            raise ProfileStoreError("Encrypted profile is locked.")
        latest_bootstrap = await self.api_client.get_profile_bootstrap()
        latest_remote = self._decode_entries(latest_bootstrap.get("entries", []))
        local_desired = self._state_to_maps(settings, bookmarks, shortcuts, history)
        final_maps: dict[str, dict[str, dict[str, Any]]] = {}
        changes: list[dict[str, Any]] = []

        for collection in PROFILE_COLLECTIONS:
            previous = self._shadow.get(collection, {})
            remote = latest_remote.get(collection, {})
            desired = local_desired.get(collection, {})
            final = self._merge_collection(previous, remote, desired)
            final_maps[collection] = final
            changes.extend(self._collection_changes(collection, remote, final))

        if changes:
            await self.api_client.apply_profile_entries(changes)
            latest_bootstrap = await self.api_client.get_profile_bootstrap()
            final_maps = self._decode_entries(latest_bootstrap.get("entries", []))

        self._shadow = final_maps
        self._profile_data = self._maps_to_profile_data(final_maps)
        return self.load_profile_data()

    def _persist_local_key(self) -> None:
        if self._master_key is None:
            return
        self.state_dir.mkdir(parents=True, exist_ok=True)
        device_key = self._ensure_device_key()
        payload = wrap_local_profile_key(self._master_key, device_key)
        try:
            data = {}
            if self.remember_path.exists():
                data = json.loads(self.remember_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except (OSError, json.JSONDecodeError):
            data = {}
        data[str(self.user["id"])] = {
            "username": self.user["username"],
            "wrapped_master_key": payload,
            "saved_at": now_string(),
        }
        self.remember_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _ensure_device_key(self) -> bytes:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if self.device_key_path.exists():
            return self.device_key_path.read_bytes()
        key = secrets.token_bytes(32)
        self.device_key_path.write_bytes(key)
        try:
            self.device_key_path.chmod(0o600)
        except OSError:
            pass
        return key

    def _read_local_key(self) -> bytes | None:
        try:
            data = json.loads(self.remember_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return None
        record = data.get(str(self.user["id"]))
        if not isinstance(record, dict):
            return None
        wrapped = str(record.get("wrapped_master_key", "")).strip()
        if not wrapped:
            return None
        try:
            return unwrap_local_profile_key(wrapped, self._ensure_device_key())
        except (OSError, ProfileCryptoError):
            return None

    def _apply_bootstrap(self, bootstrap: dict[str, Any]) -> None:
        if self._master_key is None:
            raise ProfileStoreError("Encrypted profile is locked.")
        self._shadow = self._decode_entries(bootstrap.get("entries", []))
        self._profile_data = self._maps_to_profile_data(self._shadow)

    def _decode_entries(self, entries: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
        if self._master_key is None:
            raise ProfileStoreError("Encrypted profile is locked.")
        result: dict[str, dict[str, dict[str, Any]]] = {name: {} for name in PROFILE_COLLECTIONS}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            collection = str(entry.get("collection", "")).strip()
            entry_id = str(entry.get("entry_id", "")).strip()
            if collection not in result or not entry_id or entry.get("deleted"):
                continue
            ciphertext = str(entry.get("ciphertext", "")).strip()
            if not ciphertext:
                continue
            try:
                payload = decrypt_json(ciphertext, self._master_key)
            except ProfileCryptoError:
                continue
            if not isinstance(payload, dict):
                continue
            result[collection][entry_id] = payload
        return result

    def _maps_to_profile_data(self, maps: dict[str, dict[str, dict[str, Any]]]) -> dict[str, Any]:
        settings = {
            payload["key"]: payload["value"]
            for payload in maps.get("settings", {}).values()
            if isinstance(payload, dict) and "key" in payload
        }
        bookmarks = sorted(
            (
                payload
                for payload in maps.get("bookmarks", {}).values()
                if isinstance(payload, dict) and payload.get("url")
            ),
            key=lambda item: (str(item.get("updated_at", "")), str(item.get("url", ""))),
            reverse=True,
        )
        shortcuts = sorted(
            (
                payload
                for payload in maps.get("shortcuts", {}).values()
                if isinstance(payload, dict) and payload.get("url")
            ),
            key=lambda item: (str(item.get("updated_at", "")), str(item.get("url", ""))),
            reverse=True,
        )
        history = sorted(
            (
                payload
                for payload in maps.get("history", {}).values()
                if isinstance(payload, dict) and payload.get("url")
            ),
            key=lambda item: (str(item.get("visited_at", "")), str(item.get("url", ""))),
            reverse=True,
        )
        return {
            "settings": settings,
            "bookmarks": [str(item.get("url", "")).strip() for item in bookmarks if str(item.get("url", "")).strip()],
            "shortcuts": [
                {
                    "name": str(item.get("name", "")).strip() or _short_label(str(item.get("url", "")).strip()),
                    "url": str(item.get("url", "")).strip(),
                }
                for item in shortcuts[:12]
                if str(item.get("url", "")).strip()
            ],
            "history": [
                {
                    "url": str(item.get("url", "")).strip(),
                    "title": str(item.get("title", "")).strip(),
                    "visited_at": str(item.get("visited_at", "")).strip() or now_string(),
                }
                for item in history[:300]
                if str(item.get("url", "")).strip()
            ],
        }

    def _state_to_maps(
        self,
        settings: dict[str, Any],
        bookmarks: list[str],
        shortcuts: list[dict[str, str]],
        history: list[dict[str, str]],
    ) -> dict[str, dict[str, dict[str, Any]]]:
        if self._master_key is None:
            raise ProfileStoreError("Encrypted profile is locked.")
        previous = self._shadow
        now = now_string()
        result: dict[str, dict[str, dict[str, Any]]] = {name: {} for name in PROFILE_COLLECTIONS}

        for key, value in settings.items():
            entry_id = deterministic_entry_id(self._master_key, "settings", str(key))
            prev = previous.get("settings", {}).get(entry_id)
            payload = {"key": str(key), "value": value}
            if prev is not None and prev.get("value") == value:
                payload = prev
            result["settings"][entry_id] = payload

        for url in bookmarks:
            url = str(url).strip()
            if not url:
                continue
            entry_id = deterministic_entry_id(self._master_key, "bookmarks", url)
            prev = previous.get("bookmarks", {}).get(entry_id, {})
            result["bookmarks"][entry_id] = {
                "url": url,
                "updated_at": str(prev.get("updated_at", now)),
            }
            if prev.get("url") != url:
                result["bookmarks"][entry_id]["updated_at"] = now

        for item in shortcuts[:12]:
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            name = str(item.get("name", "")).strip() or _short_label(url)
            entry_id = deterministic_entry_id(self._master_key, "shortcuts", url)
            prev = previous.get("shortcuts", {}).get(entry_id, {})
            payload = {
                "name": name,
                "url": url,
                "updated_at": str(prev.get("updated_at", now)),
            }
            if prev.get("name") != name or prev.get("url") != url:
                payload["updated_at"] = now
            result["shortcuts"][entry_id] = payload

        for item in history[:300]:
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            entry_id = deterministic_entry_id(self._master_key, "history", url)
            prev = previous.get("history", {}).get(entry_id, {})
            visited_at = str(item.get("visited_at", "")).strip() or now
            payload = {
                "url": url,
                "title": str(item.get("title", "")).strip(),
                "visited_at": visited_at,
            }
            if prev.get("url") == url and prev.get("title") == payload["title"] and prev.get("visited_at") == visited_at:
                payload = prev
            result["history"][entry_id] = payload

        return result

    @staticmethod
    def _merge_collection(
        previous: dict[str, dict[str, Any]],
        remote: dict[str, dict[str, Any]],
        desired: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        missing = object()
        final: dict[str, dict[str, Any]] = {}
        keys = set(previous) | set(remote) | set(desired)
        for entry_id in keys:
            prev = previous.get(entry_id, missing)
            remote_val = remote.get(entry_id, missing)
            local = desired.get(entry_id, missing)

            if local is missing and prev is not missing:
                continue
            if local is missing and prev is missing:
                if remote_val is not missing:
                    final[entry_id] = remote_val
                continue
            if local is missing:
                continue
            if prev is missing:
                final[entry_id] = local
                continue
            if local == prev:
                if remote_val is not missing:
                    final[entry_id] = remote_val
                continue
            final[entry_id] = local
        return final

    def _collection_changes(
        self,
        collection: str,
        remote: dict[str, dict[str, Any]],
        final: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if self._master_key is None:
            raise ProfileStoreError("Encrypted profile is locked.")
        changes: list[dict[str, Any]] = []
        for entry_id in sorted(set(remote) | set(final)):
            remote_val = remote.get(entry_id)
            final_val = final.get(entry_id)
            if final_val is None and remote_val is not None:
                changes.append({"collection": collection, "entry_id": entry_id, "deleted": True})
            elif final_val is not None and final_val != remote_val:
                changes.append(
                    {
                        "collection": collection,
                        "entry_id": entry_id,
                        "ciphertext": encrypt_json(final_val, self._master_key),
                        "deleted": False,
                    }
                )
        return changes


def _short_label(url: str) -> str:
    stripped = url.replace("http://", "").replace("https://", "").rstrip("/")
    return stripped[:18] or url
