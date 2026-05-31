"""PostgreSQL connection pool and schema initialization."""
import asyncio
import os
from psycopg_pool import AsyncConnectionPool

_pool = None
_pool_lock = None


def _get_pool_lock() -> asyncio.Lock:
    global _pool_lock
    if _pool_lock is None:
        _pool_lock = asyncio.Lock()
    return _pool_lock


async def get_pool(min_size: int = 2, max_size: int = 8):
    global _pool
    if _pool is None:
        async with _get_pool_lock():
            if _pool is None:
                url = os.getenv("DATABASE_URL", "postgresql://watercat:watercat@localhost:5432/watercat")
                _pool = AsyncConnectionPool(url, min_size=min_size, max_size=max_size, open=False)
                await _pool.open(wait=True)
    return _pool


async def close_pool():
    global _pool, _pool_lock
    if _pool:
        await _pool.close()
        _pool = None
    _pool_lock = None


async def init_schema():
    pool = await get_pool()
    async with pool.connection() as conn:
        await conn.execute("""
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
            CREATE TABLE IF NOT EXISTS browser_profile_keys (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                wrapped_profile_key TEXT NOT NULL,
                wrap_salt TEXT NOT NULL,
                wrap_kdf_version VARCHAR(64) NOT NULL,
                profile_schema_version VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS browser_profile_entries (
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                collection VARCHAR(32) NOT NULL,
                entry_id VARCHAR(64) NOT NULL,
                ciphertext TEXT,
                deleted_at TIMESTAMP,
                updated_at TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY (user_id, collection, entry_id)
            );
        """)
        await conn.commit()
