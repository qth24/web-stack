"""Cookie-backed browser session and profile API client."""

from __future__ import annotations

import json
from typing import Any, Callable

from browser.core.host_routing import effective_port_for_host
from browser.core.http_client import HTTPClient, HTTPResponse
from browser.core.url_parser import parse_url


class SessionError(RuntimeError):
    """Raised when the backend session or profile API returns an error."""


class SessionManager:
    def __init__(
        self,
        *,
        base_url: str,
        dns_client: Any,
        http_client: HTTPClient,
        cookie_jar: Any,
        http_default_port: int,
        https_default_port: int,
        on_cookies_changed: Callable[[list[Any]], None] | None = None,
    ):
        self._base_url = base_url.rstrip("/")
        self._dns_client = dns_client
        self._http_client = http_client
        self._cookie_jar = cookie_jar
        self._http_default_port = http_default_port
        self._https_default_port = https_default_port
        self._on_cookies_changed = on_cookies_changed

    async def register(self, username: str, password: str, display_name: str = "") -> dict[str, Any]:
        payload = {
            "username": username,
            "password": password,
            "display_name": display_name,
        }
        response = await self._request("POST", "/auth/register", body=json.dumps(payload))
        return self._json_or_error(response)

    async def login(self, username: str, password: str) -> dict[str, Any]:
        response = await self._request(
            "POST",
            "/auth/login",
            body=json.dumps({"username": username, "password": password}),
        )
        return self._json_or_error(response)

    async def logout(self) -> None:
        await self._request("POST", "/auth/logout")

    async def me(self) -> dict[str, Any] | None:
        response = await self._request("GET", "/auth/me")
        if response.status_code == 401:
            return None
        return self._json_or_error(response)

    async def get_profile_bootstrap(self) -> dict[str, Any]:
        response = await self._request("GET", "/api/profile/bootstrap")
        return self._json_or_error(response)

    async def set_profile_key(self, record: dict[str, Any]) -> dict[str, Any]:
        response = await self._request("POST", "/api/profile/key", body=json.dumps(record))
        return self._json_or_error(response)

    async def apply_profile_entries(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        response = await self._request("POST", "/api/profile/entries", body=json.dumps({"entries": entries}))
        return self._json_or_error(response)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: str | None = None,
        content_type: str = "application/json",
    ) -> HTTPResponse:
        parsed = parse_url(self._base_url if "://" in self._base_url else f"http://{self._base_url}")
        scheme = parsed.protocol
        host = parsed.host
        base_path = parsed.path.rstrip("/")
        request_path = f"{base_path}{path}" or path
        port = effective_port_for_host(
            scheme,
            host,
            parsed.port,
            self._http_default_port,
            self._https_default_port,
        )
        record = await self._dns_client.resolve(host)
        headers: dict[str, str] = {}
        cookie_header = self._cookie_jar.request_cookie_header(host, scheme, request_path)
        if cookie_header:
            headers["Cookie"] = cookie_header

        if method == "GET":
            response = await self._http_client.get(
                ip=record.ip,
                port=port,
                path=request_path,
                host=host,
                extra_headers=headers or None,
                use_tls=(scheme == "https"),
            )
        else:
            response = await self._http_client.post(
                ip=record.ip,
                port=port,
                path=request_path,
                host=host,
                body=body or "",
                content_type=content_type,
                use_tls=(scheme == "https"),
                extra_headers=headers or None,
            )

        new_cookies = self._cookie_jar.store_from_response(response.set_cookie_headers, host, scheme, request_path)
        if new_cookies and self._on_cookies_changed is not None:
            self._on_cookies_changed(new_cookies)
        return response

    @staticmethod
    def _json_or_error(response: HTTPResponse) -> dict[str, Any]:
        try:
            data = json.loads(response.body or "{}")
        except json.JSONDecodeError as exc:
            raise SessionError(f"Backend returned invalid JSON: {response.status_code}") from exc
        if 200 <= response.status_code < 300:
            if isinstance(data, dict):
                return data
            raise SessionError("Backend returned an unexpected payload.")
        message = data.get("error") if isinstance(data, dict) else None
        raise SessionError(message or f"Request failed with status {response.status_code}")
