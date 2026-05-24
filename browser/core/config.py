"""Browser configuration loaded from environment and browser/.env."""

import os
from pathlib import Path


BROWSER_DIR = Path(__file__).resolve().parents[1]
ENV_PATH = BROWSER_DIR.parent / ".env"
CONFIGURED_KEYS = set(os.environ)


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
        if key:
            CONFIGURED_KEYS.add(key)


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


def _get_list(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


_load_env_file(ENV_PATH)

DNS_HOST = _get_str("BROWSER_DNS_HOST", "127.0.0.1")
DNS_PORT = _get_int("BROWSER_DNS_PORT", 53)
DNS_TIMEOUT = _get_float("BROWSER_DNS_TIMEOUT", 3.0)
DNS_BUFFER = _get_int("BROWSER_DNS_BUFFER", 4096)
ENABLE_DNS_CACHE = _get_bool("BROWSER_ENABLE_DNS_CACHE", True)
FORCE_CUSTOM_DNS_ALL_HOSTS = _get_bool("BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS", False)

HTTP_TIMEOUT = _get_float("BROWSER_HTTP_TIMEOUT", 5.0)
HTTP_BUFFER = _get_int("BROWSER_HTTP_BUFFER", 4096)
HTTP_DEFAULT_PORT = _get_int("BROWSER_HTTP_DEFAULT_PORT", 80)
HTTPS_DEFAULT_PORT = _get_int("BROWSER_HTTPS_DEFAULT_PORT", 443)

HOME_URL = _get_str("BROWSER_HOME_URL", "internal:home")
SEARCH_URL = _get_str("BROWSER_SEARCH_URL", "internal:search?q={query}")
BROWSER_THEME = _get_str("BROWSER_THEME", "light").lower()
SEARCH_ENGINE = _get_str("BROWSER_SEARCH_ENGINE", "google").lower()
BROWSER_FONT_SIZE = _get_int("BROWSER_FONT_SIZE", 16)
DEFAULT_BOOKMARKS = _get_list(
    "BROWSER_DEFAULT_BOOKMARKS",
    [
        "http://example.local/",
        "http://example.local/about",
        "http://test.local/",
    ],
)

STATE_DIR = Path(_get_str("BROWSER_STATE_DIR", str(Path.home() / ".mini_web_browser"))).expanduser()
STATE_PATH = Path(_get_str("BROWSER_STATE_PATH", str(STATE_DIR / "browser_state.json"))).expanduser()
