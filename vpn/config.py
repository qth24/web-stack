"""VPN server configuration loaded from the root .env file."""

import os
from pathlib import Path


VPN_DIR = Path(__file__).resolve().parent
ENV_PATH = VPN_DIR.parent / ".env"


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
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


_load_env_file(ENV_PATH)

BIND_HOST = _get_str("VPN_BIND_HOST", "0.0.0.0")
PORT = _get_int("VPN_PORT", 9443)
TOKEN = _get_str("VPN_TOKEN", "demo-token")
CONNECT_TIMEOUT = _get_float("VPN_CONNECT_TIMEOUT", 5.0)
READ_TIMEOUT = _get_float("VPN_READ_TIMEOUT", 10.0)
BUFFER_SIZE = _get_int("VPN_BUFFER_SIZE", 4096)
MAX_FRAME_BYTES = _get_int("VPN_MAX_FRAME_BYTES", 2 * 1024 * 1024)
ALLOW_PRIVATE_TARGETS = _get_bool("VPN_ALLOW_PRIVATE_TARGETS", True)
