"""HTTP server configuration loaded from environment and http-server/.env."""

import os
from pathlib import Path


HTTP_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = HTTP_DIR.parent / ".env"


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


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _get_bool(name: str, default: bool) -> bool:
    return _get_str(name, str(default)).lower() in {"1", "true", "yes", "on"}


_load_env_file(ENV_PATH)


HOST = _get_str("HTTP_HOST", "0.0.0.0")
PORT = _get_int("HTTP_PORT", 8000)
HTTPS_PORT = _get_int("HTTP_HTTPS_PORT", 8443)
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

ENABLE_HSTS = _get_str("HTTP_ENABLE_HSTS", "false").strip().lower() in {"1", "true", "yes", "on"}
HSTS_MAX_AGE = _get_int("HTTP_HSTS_MAX_AGE", 31536000)
HSTS_INCLUDE_SUBDOMAINS = _get_str("HTTP_HSTS_INCLUDE_SUBDOMAINS", "false").strip().lower() in {"1", "true", "yes", "on"}
ENABLE_CSP = _get_str("HTTP_ENABLE_CSP", "true").strip().lower() in {"1", "true", "yes", "on"}
CSP_POLICY = _get_str(
    "HTTP_CSP_POLICY",
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'; object-src 'none'; script-src 'none'; "
    "style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; manifest-src 'self'",
)
ENABLE_WAF = _get_bool("HTTP_ENABLE_WAF", True)

PROXY_ROUTES_PATH = _get_str("HTTP_PROXY_ROUTES_PATH", "proxy_routes.json")
_proxy_path = Path(PROXY_ROUTES_PATH).expanduser()
if _proxy_path.is_absolute():
    PROXY_ROUTES_FILE = _proxy_path
else:
    PROXY_ROUTES_FILE = HTTP_DIR / PROXY_ROUTES_PATH
PROXY_CONNECT_TIMEOUT = _get_float("HTTP_PROXY_CONNECT_TIMEOUT", 3.0)
PROXY_READ_TIMEOUT = _get_float("HTTP_PROXY_READ_TIMEOUT", 10.0)
PROXY_BUFFER_SIZE = _get_int("HTTP_PROXY_BUFFER_SIZE", 4096)
