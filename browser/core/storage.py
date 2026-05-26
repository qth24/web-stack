"""SQLite storage for WaterCat browser profile data."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any


PASSWORD_ITERATIONS = 210_000
SCHEMA_VERSION = "2"
LOCAL_USERNAME = "__local__"
ENC_PREFIX = "enc:v1:"


class StorageError(RuntimeError):
    """Raised when browser storage cannot complete an operation."""


class AuthError(StorageError):
    """Raised when login or sign-up validation fails."""


class BrowserStorage:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._profile_keys: dict[int, bytes] = {}
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT,
                is_local INTEGER NOT NULL DEFAULT 0,
                is_encrypted INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (user_id, key),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS shortcuts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                created_at TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                visited_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_history_user_time
                ON history(user_id, visited_at DESC);

            CREATE TABLE IF NOT EXISTS user_meta (
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (user_id, key),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS browser_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self._ensure_user_column("is_local", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_user_column("is_encrypted", "INTEGER NOT NULL DEFAULT 1")
        self.set_browser_meta("schema_version", SCHEMA_VERSION)
        self.conn.commit()

    def _ensure_user_column(self, column: str, definition: str) -> None:
        columns = {
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if column not in columns:
            self.conn.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")

    @staticmethod
    def now() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _derive_key(password: str, salt_hex: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            PASSWORD_ITERATIONS,
            dklen=32,
        )

    @staticmethod
    def _hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
        salt_hex = salt_hex or secrets.token_hex(16)
        key = BrowserStorage._derive_key(password, salt_hex)
        return key.hex(), salt_hex

    @staticmethod
    def _normalize_username(username: str) -> str:
        return username.strip()

    def _row_to_user(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "username": row["username"],
            "display_name": row["display_name"],
            "created_at": row["created_at"],
            "last_login_at": row["last_login_at"],
            "is_local": bool(row["is_local"]),
            "encrypted": bool(row["is_encrypted"]),
        }

    def user_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"]) if row else 0

    def account_count(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS count FROM users WHERE is_local = 0"
        ).fetchone()
        return int(row["count"]) if row else 0

    def get_or_create_local_user(self) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (LOCAL_USERNAME,),
        ).fetchone()
        if row is not None:
            return self._row_to_user(row)

        created_at = self.now()
        cur = self.conn.execute(
            """
            INSERT INTO users(
                username, display_name, password_hash, password_salt,
                created_at, last_login_at, is_local, is_encrypted
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, 0)
            """,
            (LOCAL_USERNAME, "Local profile", "", "", created_at, created_at),
        )
        self.conn.commit()
        row = self.conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        return self._row_to_user(row)

    def create_user(self, username: str, password: str, display_name: str = "") -> dict[str, Any]:
        username = self._normalize_username(username)
        display_name = display_name.strip() or username
        if username.lower() == LOCAL_USERNAME:
            raise AuthError("This username is reserved.")
        if len(username) < 3:
            raise AuthError("Username must contain at least 3 characters.")
        if len(password) < 6:
            raise AuthError("Password must contain at least 6 characters.")

        password_hash, salt = self._hash_password(password)
        created_at = self.now()
        try:
            cur = self.conn.execute(
                """
                INSERT INTO users(
                    username, display_name, password_hash, password_salt,
                    created_at, last_login_at, is_local, is_encrypted
                )
                VALUES (?, ?, ?, ?, ?, ?, 0, 1)
                """,
                (username, display_name, password_hash, salt, created_at, created_at),
            )
            self.conn.commit()
        except sqlite3.IntegrityError as exc:
            raise AuthError("Username already exists.") from exc

        key = self._derive_key(password, salt)
        self._profile_keys[int(cur.lastrowid)] = key
        row = self.conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        return self._row_to_user(row)

    def authenticate_user(self, username: str, password: str) -> dict[str, Any]:
        username = self._normalize_username(username)
        row = self.conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE AND is_local = 0",
            (username,),
        ).fetchone()
        if row is None:
            raise AuthError("Invalid username or password.")
        password_hash, _ = self._hash_password(password, row["password_salt"])
        if not hmac.compare_digest(password_hash, row["password_hash"]):
            raise AuthError("Invalid username or password.")
        now = self.now()
        self.conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (now, row["id"]),
        )
        self.conn.commit()
        self._profile_keys[int(row["id"])] = self._derive_key(password, row["password_salt"])
        user = self._row_to_user(row)
        user["last_login_at"] = now
        return user

    def forget_profile_key(self, user_id: int) -> None:
        self._profile_keys.pop(user_id, None)

    def is_encrypted_user(self, user_id: int) -> bool:
        row = self.conn.execute(
            "SELECT is_encrypted FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return bool(row and row["is_encrypted"])

    def _key_for_user(self, user_id: int) -> bytes | None:
        if not self.is_encrypted_user(user_id):
            return None
        key = self._profile_keys.get(user_id)
        if key is None:
            raise StorageError("Encrypted profile is locked.")
        return key

    @staticmethod
    def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < len(data):
            block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
            output.extend(block)
            counter += 1
        return bytes(byte ^ stream for byte, stream in zip(data, output))

    def _encrypt_json(self, value: Any, key: bytes) -> str:
        nonce = secrets.token_bytes(16)
        plaintext = json.dumps(value, separators=(",", ":")).encode("utf-8")
        ciphertext = self._xor_stream(plaintext, key, nonce)
        tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
        packed = base64.urlsafe_b64encode(nonce + ciphertext + tag).decode("ascii")
        return f"{ENC_PREFIX}{packed}"

    def _decrypt_json(self, packed: str, key: bytes) -> Any:
        if not packed.startswith(ENC_PREFIX):
            return json.loads(packed)
        raw = base64.urlsafe_b64decode(packed[len(ENC_PREFIX):].encode("ascii"))
        if len(raw) < 48:
            raise StorageError("Encrypted value is corrupt.")
        nonce, payload = raw[:16], raw[16:]
        ciphertext, tag = payload[:-32], payload[-32:]
        expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise StorageError("Encrypted value failed integrity check.")
        plaintext = self._xor_stream(ciphertext, key, nonce)
        return json.loads(plaintext.decode("utf-8"))

    def _encode_value(self, user_id: int, value: Any) -> str:
        key = self._key_for_user(user_id)
        if key is None:
            return json.dumps(value)
        return self._encrypt_json(value, key)

    def _decode_value(self, user_id: int, value: str, default: Any = None) -> Any:
        try:
            if value.startswith(ENC_PREFIX):
                key = self._key_for_user(user_id)
                if key is None:
                    raise StorageError("Encrypted value has no profile key.")
                return self._decrypt_json(value, key)
            return json.loads(value)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return value if not value.startswith(ENC_PREFIX) else default

    def set_browser_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            """
            INSERT INTO browser_meta(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, json.dumps(value), self.now()),
        )

    def get_user_meta(self, user_id: int, key: str, default: Any = None) -> Any:
        row = self.conn.execute(
            "SELECT value FROM user_meta WHERE user_id = ? AND key = ?",
            (user_id, key),
        ).fetchone()
        if row is None:
            return default
        return self._decode_value(user_id, row["value"], default)

    def set_user_meta(self, user_id: int, key: str, value: Any) -> None:
        self.conn.execute(
            """
            INSERT INTO user_meta(user_id, key, value, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (user_id, key, self._encode_value(user_id, value), self.now()),
        )
        self.conn.commit()

    def load_settings(self, user_id: int) -> dict[str, Any]:
        rows = self.conn.execute(
            "SELECT key, value FROM user_settings WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        result: dict[str, Any] = {}
        for row in rows:
            result[row["key"]] = self._decode_value(user_id, row["value"], row["value"])
        return result

    def save_settings(self, user_id: int, settings: dict[str, Any]) -> None:
        now = self.now()
        with self.conn:
            for key, value in settings.items():
                self.conn.execute(
                    """
                    INSERT INTO user_settings(user_id, key, value, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                    """,
                    (user_id, key, self._encode_value(user_id, value), now),
                )

    def load_bookmarks(self, user_id: int) -> list[str]:
        rows = self.conn.execute(
            "SELECT url FROM bookmarks WHERE user_id = ? ORDER BY position ASC, created_at DESC",
            (user_id,),
        ).fetchall()
        return [str(self._decode_value(user_id, row["url"], "")) for row in rows]

    def save_bookmarks(self, user_id: int, bookmarks: list[str]) -> None:
        now = self.now()
        with self.conn:
            self.conn.execute("DELETE FROM bookmarks WHERE user_id = ?", (user_id,))
            for index, url in enumerate(bookmarks):
                url = str(url).strip()
                if not url:
                    continue
                self.conn.execute(
                    """
                    INSERT INTO bookmarks(user_id, url, title, created_at, position)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        self._encode_value(user_id, url),
                        self._encode_value(user_id, url),
                        now,
                        index,
                    ),
                )

    def load_shortcuts(self, user_id: int) -> list[dict[str, str]]:
        rows = self.conn.execute(
            "SELECT name, url FROM shortcuts WHERE user_id = ? ORDER BY position ASC, created_at DESC",
            (user_id,),
        ).fetchall()
        return [
            {
                "name": str(self._decode_value(user_id, row["name"], "")),
                "url": str(self._decode_value(user_id, row["url"], "")),
            }
            for row in rows
        ]

    def save_shortcuts(self, user_id: int, shortcuts: list[Any]) -> None:
        now = self.now()
        with self.conn:
            self.conn.execute("DELETE FROM shortcuts WHERE user_id = ?", (user_id,))
            for index, item in enumerate(shortcuts):
                if isinstance(item, dict):
                    url = str(item.get("url", "")).strip()
                    name = str(item.get("name", "")).strip() or url
                else:
                    url = str(item).strip()
                    name = url
                if not url:
                    continue
                self.conn.execute(
                    """
                    INSERT INTO shortcuts(user_id, name, url, created_at, position)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        self._encode_value(user_id, name),
                        self._encode_value(user_id, url),
                        now,
                        index,
                    ),
                )

    def load_history(self, user_id: int, limit: int = 300) -> list[dict[str, str]]:
        rows = self.conn.execute(
            """
            SELECT url, title, visited_at FROM history
            WHERE user_id = ?
            ORDER BY datetime(visited_at) DESC, id ASC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        return [
            {
                "url": str(self._decode_value(user_id, row["url"], "")),
                "title": str(self._decode_value(user_id, row["title"], "")),
                "visited_at": row["visited_at"],
            }
            for row in rows
        ]

    def save_history(self, user_id: int, history: list[dict[str, str]]) -> None:
        now = self.now()
        with self.conn:
            self.conn.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
            for item in history[:300]:
                url = str(item.get("url", "")).strip()
                if not url:
                    continue
                self.conn.execute(
                    """
                    INSERT INTO history(user_id, url, title, visited_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        self._encode_value(user_id, url),
                        self._encode_value(user_id, str(item.get("title", "")).strip()),
                        str(item.get("visited_at", "")).strip() or now,
                    ),
                )

    def migrate_from_state(self, user_id: int, state: dict[str, Any]) -> None:
        if self.get_user_meta(user_id, "legacy_state_migrated", False):
            return
        if not state:
            self.set_user_meta(user_id, "legacy_state_migrated", True)
            return

        settings = state.get("settings")
        if isinstance(settings, dict) and not self.load_settings(user_id):
            self.save_settings(user_id, settings)

        bookmarks = state.get("bookmarks")
        if isinstance(bookmarks, list) and not self.load_bookmarks(user_id):
            self.save_bookmarks(user_id, [str(item) for item in bookmarks])

        shortcuts = state.get("shortcuts")
        if isinstance(shortcuts, list) and not self.load_shortcuts(user_id):
            self.save_shortcuts(user_id, shortcuts)

        history = state.get("history")
        if isinstance(history, list) and not self.load_history(user_id):
            normalized = []
            for item in history:
                if isinstance(item, dict):
                    normalized.append(item)
                else:
                    normalized.append({"url": str(item), "visited_at": ""})
            self.save_history(user_id, normalized)

        self.set_user_meta(user_id, "legacy_state_migrated", True)
