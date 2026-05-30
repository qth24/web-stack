"""Database CRUD operations for users, sessions, history, and messages."""
import hashlib
import secrets
import datetime
from server.app.db import get_pool


def create_user(username: str, password_hash: str, password_salt: str, display_name: str = None) -> int:
    pool = get_pool()
    with pool.connection() as conn:
        result = conn.execute(
            "INSERT INTO users (username, password_hash, password_salt, display_name) VALUES (%s, %s, %s, %s) RETURNING id",
            (username, password_hash, password_salt, display_name or username),
        )
        return result.fetchone()[0]


def get_user_by_username(username: str) -> dict | None:
    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id, username, display_name, password_hash, password_salt, created_at FROM users WHERE username = %s",
            (username,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0], "username": row[1], "display_name": row[2],
            "password_hash": row[3], "password_salt": row[4], "created_at": row[5],
        }


def get_user_by_id(user_id: int) -> dict | None:
    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id, username, display_name, password_hash, password_salt, created_at FROM users WHERE id = %s",
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0], "username": row[1], "display_name": row[2],
            "password_hash": row[3], "password_salt": row[4], "created_at": row[5],
        }


def create_session(user_id: int, expires_hours: int = 24) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=expires_hours)
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
            (user_id, token_hash, expires_at),
        )
    return token


def validate_session_token(token: str) -> dict | None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """SELECT u.id, u.username, u.display_name FROM users u
               JOIN sessions s ON u.id = s.user_id
               WHERE s.token_hash = %s AND s.expires_at > NOW()""",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        return {"id": row[0], "username": row[1], "display_name": row[2]}


def delete_session(token: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = %s", (token_hash,))


def add_history(user_id: int, url: str, title: str = None):
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO history (user_id, url, title) VALUES (%s, %s, %s)",
            (user_id, url, title),
        )


def get_history(user_id: int, limit: int = 50) -> list[dict]:
    pool = get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT url, title, visited_at FROM history WHERE user_id = %s ORDER BY visited_at DESC LIMIT %s",
            (user_id, limit),
        ).fetchall()
        return [{"url": r[0], "title": r[1], "visited_at": r[2].isoformat()} for r in rows]


def add_message(user_id: int, content: str):
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO messages (user_id, content) VALUES (%s, %s)",
            (user_id, content),
        )


def get_messages(user_id: int, limit: int = 50) -> list[dict]:
    pool = get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT content, created_at FROM messages WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
            (user_id, limit),
        ).fetchall()
        return [{"content": r[0], "created_at": r[1].isoformat()} for r in rows]
