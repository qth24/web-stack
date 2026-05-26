"""Browser configuration loaded from environment and browser/.env."""

import os
from pathlib import Path


BROWSER_DIR = Path(__file__).resolve().parents[1]
ENV_PATHS = (BROWSER_DIR / ".env", BROWSER_DIR.parent / ".env")
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


for env_path in ENV_PATHS:
    _load_env_file(env_path)


def _browser_path(name: str, default: str) -> Path:
    raw = _get_str(name, default)
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path
    if raw.startswith("browser/"):
        return (BROWSER_DIR.parent / path).resolve()
    return (BROWSER_DIR / path).resolve()

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

ENABLE_VPN = _get_bool("BROWSER_ENABLE_VPN", False)
VPN_HOST = _get_str("BROWSER_VPN_HOST", "127.0.0.1")
VPN_PORT = _get_int("BROWSER_VPN_PORT", 9443)
VPN_TOKEN = _get_str("BROWSER_VPN_TOKEN", "demo-token")
VPN_TIMEOUT = _get_float("BROWSER_VPN_TIMEOUT", 8.0)
VPN_BUFFER = _get_int("BROWSER_VPN_BUFFER", 4096)
VPN_MAX_FRAME_BYTES = _get_int("BROWSER_VPN_MAX_FRAME_BYTES", 2 * 1024 * 1024)
VPN_MODE = _get_str("BROWSER_VPN_MODE", "all").lower()
VPN_DOMAINS = _get_list("BROWSER_VPN_DOMAINS", [".local", "localhost"])

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

ENABLE_HTTP_CACHE = _get_bool("BROWSER_ENABLE_HTTP_CACHE", True)
HTTP_CACHE_MAX_MB = _get_int("BROWSER_HTTP_CACHE_MAX_MB", 64)
HTTP_CACHE_MAX_ENTRY_MB = _get_int("BROWSER_HTTP_CACHE_MAX_ENTRY_MB", 4)

STATE_DIR = Path(_get_str("BROWSER_STATE_DIR", str(Path.home() / ".mini_web_browser"))).expanduser()
STATE_PATH = Path(_get_str("BROWSER_STATE_PATH", str(STATE_DIR / "browser_state.json"))).expanduser()
COOKIE_STATE_PATH = STATE_DIR / "cookies.json"
BROWSER_DB_PATH = _browser_path("BROWSER_DB_PATH", "data/watercat_browser.db")

ENABLE_PHISHING_DETECTION = _get_bool("BROWSER_ENABLE_PHISHING_DETECTION", True)
PHISHING_SUSPICIOUS_THRESHOLD = _get_int("BROWSER_PHISHING_SUSPICIOUS_THRESHOLD", 31)
PHISHING_BLOCK_THRESHOLD = _get_int("BROWSER_PHISHING_BLOCK_THRESHOLD", 61)
PHISHING_RULES_PATH = Path(
    _get_str("BROWSER_PHISHING_RULES_PATH", str(STATE_DIR / "phishing_rules.json"))
).expanduser()
GOOGLE_SAFE_BROWSING_API_KEY = _get_str("BROWSER_GOOGLE_SAFE_BROWSING_API_KEY", "")

ENABLE_AI_ASSISTANT = _get_bool("BROWSER_ENABLE_AI_ASSISTANT", True)
AI_MODEL = _get_str("BROWSER_AI_MODEL", "gemini-2.5-flash")
AI_STREAM = _get_bool("BROWSER_AI_STREAM", True)
AI_TEMPERATURE = _get_float("BROWSER_AI_TEMPERATURE", 0.3)
AI_MAX_OUTPUT_TOKENS = _get_int("BROWSER_AI_MAX_OUTPUT_TOKENS", 1200)
AI_SELECTION_MAX_CHARS = _get_int("BROWSER_AI_SELECTION_MAX_CHARS", 8000)
AI_PAGE_TEXT_MAX_CHARS = _get_int("BROWSER_AI_PAGE_TEXT_MAX_CHARS", 24000)
