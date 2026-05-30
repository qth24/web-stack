"""PostgreSQL connection pool and schema initialization."""
import os
import threading
from psycopg_pool import ConnectionPool

_pool = None
_pool_lock = threading.Lock()


def get_pool(min_size: int = 2, max_size: int = 8):
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                url = os.getenv("DATABASE_URL", "postgresql://watercat:watercat@localhost:5432/watercat")
                _pool = ConnectionPool(url, min_size=min_size, max_size=max_size, open=True)
    return _pool


def close_pool():
    global _pool
    if _pool:
        _pool.close()
        _pool = None


def init_schema():
    pool = get_pool()
    with pool.connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(64) UNIQUE NOT NULL,
                display_name VARCHAR(128),
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(64) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                title TEXT,
                visited_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()
