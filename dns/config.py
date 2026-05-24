"""DNS server configuration loaded from environment and dns/.env."""

import os
from pathlib import Path


DNS_DIR = Path(__file__).resolve().parent
ENV_PATH = DNS_DIR.parent / ".env"


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


def _resolve_path(value: str) -> str:
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)

    project_path = DNS_DIR.parent / path
    if project_path.exists():
        return str(project_path)

    dns_path = DNS_DIR / path
    if dns_path.exists():
        return str(dns_path)

    return str(project_path)


BIND_HOST = _get_str("DNS_BIND_HOST", "0.0.0.0")
PORT = _get_int("DNS_PORT", 53)
RECORDS_PATH = _resolve_path(_get_str("DNS_RECORDS_PATH", str(DNS_DIR / "dns_records.json")))
DEFAULT_TTL = _get_int("DNS_DEFAULT_TTL", 5)
RESOLVER_MODE = _get_str("DNS_RESOLVER_MODE", "hybrid").lower()
FORWARD_TTL_SECONDS = _get_int("DNS_FORWARD_TTL_SECONDS", 60)
MAX_REQUEST_BYTES = _get_int("DNS_MAX_REQUEST_BYTES", 1024)
MAX_RESPONSE_BYTES = _get_int("DNS_MAX_RESPONSE_BYTES", 2048)
RATE_LIMIT_MAX_QUERIES = _get_int("DNS_RATE_LIMIT_MAX_QUERIES", 10)
RATE_LIMIT_WINDOW_SECONDS = _get_int("DNS_RATE_LIMIT_WINDOW_SECONDS", 10)
