"""Google Safe Browsing API v4 lookup client.

https://developers.google.com/safe-browsing/v4/lookup-api
"""

import json
import os
import urllib.request
from typing import Optional

from browser.core.phishing import ReputationHit

_REQUEST_BODY = {
    "client": {"clientId": "watercat-browser", "clientVersion": "1.0.0"},
    "threatInfo": {
        "threatTypes": [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
        ],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [],
    },
}

_TIMEOUT = 3


def _get_api_key() -> str:
    return os.environ.get("BROWSER_GOOGLE_SAFE_BROWSING_API_KEY", "")


def google_safe_browsing_lookup(url: str, _host: str = "") -> Optional[ReputationHit]:
    api_key = _get_api_key()
    if not api_key:
        return None

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        "?key=" + api_key
    )

    body = dict(_REQUEST_BODY)
    body["threatInfo"] = dict(_REQUEST_BODY["threatInfo"])
    body["threatInfo"]["threatEntries"] = [{"url": url}]

    data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    matches = result.get("matches", []) if isinstance(result, dict) else []
    if matches:
        return ReputationHit(
            source="google_safebrowsing",
            verdict="malicious",
            ttl_seconds=3600,
        )

    return ReputationHit(
        source="google_safebrowsing",
        verdict="safe",
        ttl_seconds=3600,
    )
