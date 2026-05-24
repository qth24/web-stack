"""Cookie dataclass and CookieJar with persistence, matching, and Set-Cookie parsing."""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    host_only: bool = True
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    expires_at: Optional[float] = None
    same_site: str = "Lax"
    created_at: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        if self.expires_at is not None and self.expires_at <= time.time():
            return True
        return False

    def matches(self, host: str, scheme: str, request_path: str) -> bool:
        if self.is_expired():
            return False
        if self.secure and scheme != "https":
            return False
        if not self._domain_matches(host):
            return False
        if not self._path_matches(request_path):
            return False
        return True

    def _domain_matches(self, host: str) -> bool:
        host = host.lower()
        cookie_domain = self.domain.lower()
        if self.host_only:
            return host == cookie_domain
        return host == cookie_domain or host.endswith("." + cookie_domain)

    def _path_matches(self, request_path: str) -> bool:
        cookie_path = self.path.rstrip("/") or "/"
        rp = request_path or "/"
        if cookie_path == "/":
            return True
        return rp == cookie_path or rp.startswith(cookie_path + "/")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "host_only": self.host_only,
            "path": self.path,
            "secure": self.secure,
            "http_only": self.http_only,
            "expires_at": self.expires_at,
            "same_site": self.same_site,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Cookie":
        return cls(
            name=str(data.get("name", "")),
            value=str(data.get("value", "")),
            domain=str(data.get("domain", "")),
            host_only=bool(data.get("host_only", True)),
            path=str(data.get("path", "/")),
            secure=bool(data.get("secure", False)),
            http_only=bool(data.get("http_only", False)),
            expires_at=data.get("expires_at"),
            same_site=str(data.get("same_site", "Lax")),
            created_at=float(data.get("created_at", time.time())),
        )


class CookieJar:
    """Structured cookie store with load/save, expiration pruning, matching."""

    def __init__(self, state_path: Optional[Path] = None):
        self._cookies: list[Cookie] = []
        self._state_path = state_path

    @property
    def cookie_list(self) -> list[Cookie]:
        return list(self._cookies)

    def load(self) -> None:
        if self._state_path is None or not self._state_path.exists():
            return
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return
        raw_cookies = data.get("cookies", data) if isinstance(data, dict) else data
        if isinstance(raw_cookies, list):
            self._cookies = self._parse_structured(raw_cookies)
        elif isinstance(raw_cookies, dict):
            self._cookies = self._migrate_legacy(raw_cookies)

    def save(self) -> None:
        if self._state_path is None:
            return
        self.prune_expired()
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"cookies": [c.to_dict() for c in self._cookies]}
        with open(self._state_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _state_data(self) -> dict[str, Any]:
        self.prune_expired()
        return {"cookies": [c.to_dict() for c in self._cookies]}

    def load_from_state(self, state_data: dict[str, Any]) -> None:
        raw_cookies = state_data.get("cookies", state_data) if isinstance(state_data, dict) else state_data
        if isinstance(raw_cookies, list):
            self._cookies = self._parse_structured(raw_cookies)
        elif isinstance(raw_cookies, dict):
            self._cookies = self._migrate_legacy(raw_cookies)
        self.prune_expired()

    def _parse_structured(self, items: list[dict[str, Any]]) -> list[Cookie]:
        result = []
        for item in items:
            if isinstance(item, dict) and "name" in item:
                cookie = Cookie.from_dict(item)
                if not cookie.is_expired():
                    result.append(cookie)
        return result

    def _migrate_legacy(self, legacy: dict[str, dict[str, str]]) -> list[Cookie]:
        result = []
        for domain, cookies in legacy.items():
            if not isinstance(cookies, dict):
                continue
            for name, value in cookies.items():
                result.append(Cookie(
                    name=str(name),
                    value=str(value),
                    domain=str(domain),
                    host_only=True,
                    path="/",
                ))
        return result

    def matching_cookies(self, host: str, scheme: str, path: str) -> list[Cookie]:
        self.prune_expired()
        return [c for c in self._cookies if c.matches(host, scheme, path)]

    def request_cookie_header(self, host: str, scheme: str, path: str) -> Optional[str]:
        matched = self.matching_cookies(host, scheme, path)
        if not matched:
            return None
        return "; ".join(f"{c.name}={c.value}" for c in matched)

    def prune_expired(self) -> None:
        self._cookies = [c for c in self._cookies if not c.is_expired()]

    def store_cookie(self, cookie: Cookie) -> None:
        self._cookies = [c for c in self._cookies if not (c.name == cookie.name and c.domain == cookie.domain and c.path == cookie.path)]
        self._cookies.append(cookie)

    def delete_cookie(self, name: str, domain: str, path: str = "/") -> None:
        self._cookies = [c for c in self._cookies if not (c.name == name and c.domain == domain and c.path == path)]

    def clear(self) -> None:
        self._cookies.clear()

    def store_from_set_cookie(
        self,
        set_cookie_header: str,
        request_domain: str,
        request_scheme: str = "http",
        request_path: str = "/",
    ) -> Optional[Cookie]:
        parts = set_cookie_header.split(";")
        if not parts:
            return None

        pair = parts[0].strip()
        if "=" not in pair:
            return None
        name, value = pair.split("=", 1)
        name = name.strip()
        value = value.strip()

        domain = request_domain
        host_only = True
        path = request_path
        secure = False
        http_only = False
        expires_at = None
        same_site = "Lax"
        delete = False

        for attr in parts[1:]:
            attr = attr.strip()
            if "=" in attr:
                akey, _, aval = attr.partition("=")
                akey = akey.strip().lower()
                aval = aval.strip()
                if akey == "expires":
                    try:
                        from email.utils import parsedate_to_datetime
                        dt = parsedate_to_datetime(aval)
                        expires_at = dt.timestamp()
                    except Exception:
                        pass
                elif akey == "max-age":
                    try:
                        max_age = int(aval)
                        if max_age <= 0:
                            delete = True
                        else:
                            expires_at = time.time() + max_age
                    except ValueError:
                        pass
                elif akey == "domain":
                    d = aval.lower()
                    if d.startswith("."):
                        host_only = False
                        domain = d[1:]
                    else:
                        host_only = False
                        domain = d
                elif akey == "path":
                    path = aval or "/"
                elif akey == "samesite":
                    val = aval.capitalize()
                    if val in {"Strict", "Lax", "None"}:
                        same_site = val
            else:
                alower = attr.lower()
                if alower == "secure":
                    secure = True
                elif alower == "httponly":
                    http_only = True

        if delete:
            self.delete_cookie(name, domain, path)
            return None

        if expires_at is not None and expires_at <= time.time():
            self.delete_cookie(name, domain, path)
            return None

        cookie = Cookie(
            name=name,
            value=value,
            domain=domain,
            host_only=host_only,
            path=path,
            secure=secure,
            http_only=http_only,
            expires_at=expires_at,
            same_site=same_site,
        )
        self.store_cookie(cookie)
        return cookie

    def store_from_response(
        self,
        set_cookie_headers: list[str],
        request_domain: str,
        request_scheme: str = "http",
        request_path: str = "/",
    ) -> list[Cookie]:
        results = []
        for header in set_cookie_headers:
            cookie = self.store_from_set_cookie(header, request_domain, request_scheme, request_path)
            if cookie is not None:
                results.append(cookie)
        return results

    def to_legacy_dict(self) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        for cookie in self._cookies:
            if cookie.is_expired():
                continue
            result.setdefault(cookie.domain, {})
            result[cookie.domain][cookie.name] = cookie.value
        return result

    def __len__(self) -> int:
        return len(self._cookies)

    def __iter__(self):
        return iter(self._cookies)
