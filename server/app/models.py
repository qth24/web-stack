import datetime
import hashlib
import secrets

from server.app.db import get_pool

# Direct SQL access for users, sessions, history, and profiles.

async def create_user(username: str, password_hash: str, password_salt: str, display_name: str = None) -> int:
    pool = await get_pool()
    async with pool.connection() as conn:
        result = await conn.execute(
            "INSERT INTO users (username, password_hash, password_salt, display_name) VALUES (%s, %s, %s, %s) RETURNING id",
            (username, password_hash, password_salt, display_name if display_name is not None else username),
        )
        row = await result.fetchone()
        await conn.commit()
        return row[0]


async def get_user_by_username(username: str) -> dict | None:
    pool = await get_pool()
    async with pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT id, username, display_name, password_hash, password_salt, created_at FROM users WHERE username = %s",
            (username,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return {
            "id": row[0], "username": row[1], "display_name": row[2],
            "password_hash": row[3], "password_salt": row[4], "created_at": row[5],
        }


async def get_user_by_id(user_id: int) -> dict | None:
    pool = await get_pool()
    async with pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT id, username, display_name, password_hash, password_salt, created_at FROM users WHERE id = %s",
            (user_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return {
            "id": row[0], "username": row[1], "display_name": row[2],
            "password_hash": row[3], "password_salt": row[4], "created_at": row[5],
        }


async def create_session(user_id: int, expires_hours: int = 24) -> str:
    # Stores only the token hash; the raw token lives in the cookie.
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=expires_hours)
    pool = await get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
            (user_id, token_hash, expires_at),
        )
        await conn.commit()
    return token


async def validate_session_token(token: str) -> dict | None:
    # Auth gate: maps a valid cookie token back to a user.
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    pool = await get_pool()
    async with pool.connection() as conn:
        cursor = await conn.execute(
            """SELECT u.id, u.username, u.display_name FROM users u
               JOIN sessions s ON u.id = s.user_id
               WHERE s.token_hash = %s AND s.expires_at > NOW()""",
            (token_hash,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return {"id": row[0], "username": row[1], "display_name": row[2]}


async def delete_session(token: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    pool = await get_pool()
    async with pool.connection() as conn:
        await conn.execute("DELETE FROM sessions WHERE token_hash = %s", (token_hash,))
        await conn.commit()


async def add_history(user_id: int, url: str, title: str = None):
    pool = await get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO history (user_id, url, title) VALUES (%s, %s, %s)",
            (user_id, url, title),
        )
        await conn.commit()


async def get_history(user_id: int, limit: int = 50) -> list[dict]:
    pool = await get_pool()
    async with pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT url, title, visited_at FROM history WHERE user_id = %s ORDER BY visited_at DESC LIMIT %s",
            (user_id, limit),
        )
        rows = await cursor.fetchall()
        return [{"url": r[0], "title": r[1], "visited_at": r[2].isoformat()} for r in rows]


async def add_message(user_id: int, content: str):
    pool = await get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO messages (user_id, content) VALUES (%s, %s)",
            (user_id, content),
        )
        await conn.commit()


async def get_messages(user_id: int, limit: int = 50) -> list[dict]:
    pool = await get_pool()
    async with pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT content, created_at FROM messages WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
            (user_id, limit),
        )
        rows = await cursor.fetchall()
        return [{"content": r[0], "created_at": r[1].isoformat()} for r in rows]


async def get_browser_profile_key(user_id: int) -> dict | None:
    pool = await get_pool()
    async with pool.connection() as conn:
        cursor = await conn.execute(
            """
            SELECT wrapped_profile_key, wrap_salt, wrap_kdf_version, profile_schema_version, updated_at
            FROM browser_profile_keys
            WHERE user_id = %s
            """,
            (user_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return {
            "wrapped_profile_key": row[0],
            "wrap_salt": row[1],
            "wrap_kdf_version": row[2],
            "profile_schema_version": row[3],
            "updated_at": row[4].isoformat() if row[4] else None,
        }


async def upsert_browser_profile_key(
    user_id: int,
    wrapped_profile_key: str,
    wrap_salt: str,
    wrap_kdf_version: str,
    profile_schema_version: str,
) -> dict:
    # Saves the client-wrapped profile master key.
    pool = await get_pool()
    async with pool.connection() as conn:
        cursor = await conn.execute(
            """
            INSERT INTO browser_profile_keys (
                user_id, wrapped_profile_key, wrap_salt, wrap_kdf_version, profile_schema_version, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                wrapped_profile_key = EXCLUDED.wrapped_profile_key,
                wrap_salt = EXCLUDED.wrap_salt,
                wrap_kdf_version = EXCLUDED.wrap_kdf_version,
                profile_schema_version = EXCLUDED.profile_schema_version,
                updated_at = NOW()
            RETURNING wrapped_profile_key, wrap_salt, wrap_kdf_version, profile_schema_version, updated_at
            """,
            (user_id, wrapped_profile_key, wrap_salt, wrap_kdf_version, profile_schema_version),
        )
        row = await cursor.fetchone()
        await conn.commit()
        return {
            "wrapped_profile_key": row[0],
            "wrap_salt": row[1],
            "wrap_kdf_version": row[2],
            "profile_schema_version": row[3],
            "updated_at": row[4].isoformat() if row[4] else None,
        }


async def list_browser_profile_entries(user_id: int) -> list[dict]:
    pool = await get_pool()
    async with pool.connection() as conn:
        cursor = await conn.execute(
            """
            SELECT collection, entry_id, ciphertext, deleted_at, updated_at
            FROM browser_profile_entries
            WHERE user_id = %s
            ORDER BY collection ASC, updated_at ASC, entry_id ASC
            """,
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "collection": row[0],
                "entry_id": row[1],
                "ciphertext": row[2],
                "deleted": row[3] is not None,
                "deleted_at": row[3].isoformat() if row[3] else None,
                "updated_at": row[4].isoformat() if row[4] else None,
            }
            for row in rows
        ]


async def apply_browser_profile_entry_changes(user_id: int, entries: list[dict]) -> list[dict]:
    # Applies encrypted profile upserts and delete tombstones.
    if not entries:
        return []
    pool = await get_pool()
    async with pool.connection() as conn:
        results: list[dict] = []
        for entry in entries:
            deleted = bool(entry.get("deleted"))
            cursor = await conn.execute(
                """
                INSERT INTO browser_profile_entries (
                    user_id, collection, entry_id, ciphertext, deleted_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (user_id, collection, entry_id) DO UPDATE SET
                    ciphertext = EXCLUDED.ciphertext,
                    deleted_at = EXCLUDED.deleted_at,
                    updated_at = NOW()
                RETURNING collection, entry_id, ciphertext, deleted_at, updated_at
                """,
                (
                    user_id,
                    entry["collection"],
                    entry["entry_id"],
                    None if deleted else entry.get("ciphertext"),
                    datetime.datetime.now(datetime.timezone.utc) if deleted else None,
                ),
            )
            row = await cursor.fetchone()
            results.append(
                {
                    "collection": row[0],
                    "entry_id": row[1],
                    "ciphertext": row[2],
                    "deleted": row[3] is not None,
                    "deleted_at": row[3].isoformat() if row[3] else None,
                    "updated_at": row[4].isoformat() if row[4] else None,
                }
            )
        await conn.commit()
        return results
