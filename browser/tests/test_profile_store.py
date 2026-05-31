"""Tests for the server-backed encrypted profile store."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from browser.core.profile_crypto import unwrap_profile_key
from browser.core.profile_store import RemoteEncryptedProfileStore


class FakeAPIClient:
    def __init__(self) -> None:
        self.profile_key: dict | None = None
        self.entries: dict[tuple[str, str], dict] = {}

    async def get_profile_bootstrap(self) -> dict:
        return {
            "user": {"id": 7, "username": "demo", "display_name": "Demo"},
            "profile_key": self.profile_key,
            "entries": [
                {
                    "collection": collection,
                    "entry_id": entry_id,
                    "ciphertext": payload.get("ciphertext"),
                    "deleted": payload.get("deleted", False),
                }
                for (collection, entry_id), payload in sorted(self.entries.items())
            ],
        }

    async def set_profile_key(self, record: dict) -> dict:
        self.profile_key = dict(record)
        return dict(record)

    async def apply_profile_entries(self, entries: list[dict]) -> dict:
        for item in entries:
            key = (item["collection"], item["entry_id"])
            if item.get("deleted"):
                self.entries[key] = {
                    "deleted": True,
                    "ciphertext": None,
                }
            else:
                self.entries[key] = {
                    "deleted": False,
                    "ciphertext": item["ciphertext"],
                }
        return {"entries": entries}


class TestRemoteEncryptedProfileStore(unittest.TestCase):
    def _run(self, coro):
        return asyncio.run(coro)

    def test_bootstrap_creates_profile_key_and_local_remember_file(self):
        api = FakeAPIClient()
        user = {"id": 7, "username": "demo", "display_name": "Demo"}
        with tempfile.TemporaryDirectory() as tmp:
            store = RemoteEncryptedProfileStore(api, Path(tmp), user)

            profile = self._run(store.bootstrap_with_password("secret123"))

            self.assertEqual(profile["bookmarks"], [])
            self.assertIsNotNone(api.profile_key)
            unwrapped = unwrap_profile_key(api.profile_key, "secret123")
            self.assertEqual(len(unwrapped), 32)
            self.assertTrue((Path(tmp) / "remembered_profiles.json").exists())

    def test_sync_preserves_remote_additions_when_local_copy_is_unchanged(self):
        api = FakeAPIClient()
        user = {"id": 7, "username": "demo", "display_name": "Demo"}
        with tempfile.TemporaryDirectory() as tmp:
            first = RemoteEncryptedProfileStore(api, Path(tmp), user)
            second = RemoteEncryptedProfileStore(api, Path(tmp), user)

            self._run(first.bootstrap_with_password("secret123"))
            merged = self._run(
                first.sync_state(
                    settings={},
                    bookmarks=["http://local.example"],
                    shortcuts=[],
                    history=[],
                )
            )
            self.assertEqual(merged["bookmarks"], ["http://local.example"])

            self._run(second.bootstrap_with_password("secret123"))
            merged_second = self._run(
                second.sync_state(
                    settings={},
                    bookmarks=["http://local.example", "http://remote.example"],
                    shortcuts=[],
                    history=[],
                )
            )
            self.assertIn("http://remote.example", merged_second["bookmarks"])

            merged_first = self._run(
                first.sync_state(
                    settings={},
                    bookmarks=["http://local.example"],
                    shortcuts=[],
                    history=[],
                )
            )

            self.assertIn("http://local.example", merged_first["bookmarks"])
            self.assertIn("http://remote.example", merged_first["bookmarks"])


if __name__ == "__main__":
    unittest.main()
