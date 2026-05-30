"""Shared HTTP security helper: security headers and basic WAF."""
from urllib.parse import unquote


BASELINE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), "
        "gyroscope=(), magnetometer=(), microphone=(), "
        "payment=(), usb=()"
    ),
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Server": "MiniWebStack/2.0",
}


def apply_security_headers(response_headers: dict[str, str], scheme: str = "http"):
    """Add security headers to the response headers dict."""
    for k, v in BASELINE_HEADERS.items():
        response_headers.setdefault(k, v)

    if scheme == "https":
        response_headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )


def _inspect_value(value: str) -> str | None:
    if not value:
        return None
    try:
        decoded = unquote(value)
    except Exception:
        decoded = value
    lower = decoded.lower()

    if "\0" in lower:
        return "null-byte in request target"
    if "../" in lower or "..\\" in lower:
        return "path traversal attempt"
    if any(
        probe in lower
        for probe in ("/.git", "/.env", "/.ssh", "/etc/passwd")
    ):
        return "sensitive path probe"
    if "<script" in lower:
        return "script injection in request target"

    return None


def waf_inspect(request: dict) -> str | None:
    """Inspect the request for obvious malicious probes.

    Returns a block reason string if the request should be blocked,
    or None if the request is safe.
    """
    target = request.get("target", "")
    reason = _inspect_value(target)
    if reason:
        return reason

    headers = request.get("headers", {})
    for extra_header in ("x-original-url", "x-rewrite-url"):
        value = headers.get(extra_header, "")
        reason = _inspect_value(value)
        if reason:
            return reason

    return None
