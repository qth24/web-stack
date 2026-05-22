"""DNS server configuration loaded from environment and dns/.env."""

import os
from pathlib import Path


DNS_DIR = Path(__file__).resolve().parent
ENV_PATH = DNS_DIR / ".env"


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

BIND_HOST = _get_str("DNS_BIND_HOST", "0.0.0.0")
PORT = _get_int("DNS_PORT", 5200)
RECORDS_PATH = _get_str("DNS_RECORDS_PATH", str(DNS_DIR / "dns_records.json"))
DEFAULT_TTL = _get_int("DNS_DEFAULT_TTL", 5)
MAX_REQUEST_BYTES = _get_int("DNS_MAX_REQUEST_BYTES", 1024)
MAX_RESPONSE_BYTES = _get_int("DNS_MAX_RESPONSE_BYTES", 2048)
