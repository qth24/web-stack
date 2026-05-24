"""Shared HTTP security helper: security headers, HSTS, CSP, and basic WAF."""

from urllib.parse import unquote

from config import (
    CSP_POLICY,
    ENABLE_CSP,
    ENABLE_HSTS,
    ENABLE_WAF,
    HSTS_INCLUDE_SUBDOMAINS,
    HSTS_MAX_AGE,
)


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
}


def build_security_headers(scheme: str = "http") -> dict[str, str]:
    """Return a dict of all security headers for the given scheme."""
    headers = dict(BASELINE_HEADERS)

    if ENABLE_CSP:
        headers["Content-Security-Policy"] = CSP_POLICY

    if scheme == "https" and ENABLE_HSTS:
        sts = f"max-age={HSTS_MAX_AGE}"
        if HSTS_INCLUDE_SUBDOMAINS:
            sts += "; includeSubDomains"
        headers["Strict-Transport-Security"] = sts

    return headers


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
    if not ENABLE_WAF:
        return None

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
