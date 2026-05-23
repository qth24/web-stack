"""HTTP server configuration loaded from environment and http-server/.env."""

import os
from pathlib import Path


HTTP_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = HTTP_DIR / ".env"


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _get_str(name: str, default: str) -> str:
    return os.getenv(name, default).strip() or default


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


_load_env_file(ENV_PATH)


HOST = _get_str("HTTP_HOST", "0.0.0.0")
PORT = _get_int("HTTP_PORT", 8000)
BUFFER_SIZE = _get_int("HTTP_BUFFER_SIZE", 4096)
SERVER_NAME = _get_str("HTTP_SERVER_NAME", "UIT-HTTP-Server/1.0")

_PUBLIC_DIR_VALUE = _get_str("HTTP_PUBLIC_DIR", "public")
_public_path = Path(_PUBLIC_DIR_VALUE).expanduser()
if _public_path.is_absolute():
    PUBLIC_DIR = _public_path
else:
    PUBLIC_DIR = HTTP_DIR / _PUBLIC_DIR_VALUE

CACHE_MAX_SIZE = _get_int("HTTP_CACHE_MAX_SIZE", 100)
CACHE_TTL = _get_int("HTTP_CACHE_TTL", 60)
