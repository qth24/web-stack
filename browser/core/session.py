"""WaterCat server session state management."""
import json
import http.client


class SessionManager:
    def __init__(self, base_url: str = "http://localhost:8081"):
        self._base_url = base_url.rstrip("/")
        self._token: str | None = None
        self._user: dict | None = None

    def register(self, username: str, password: str) -> dict:
        data = json.dumps({"username": username, "password": password})
        resp = self._request("POST", "/auth/register", data)
        self._extract_token(resp)
        return json.loads(resp.get("body", b"{}"))

    def login(self, username: str, password: str) -> dict:
        data = json.dumps({"username": username, "password": password})
        resp = self._request("POST", "/auth/login", data)
        self._extract_token(resp)
        return json.loads(resp.get("body", b"{}"))

    def logout(self):
        self._request("POST", "/auth/logout")
        self._token = None
        self._user = None

    def me(self) -> dict | None:
        resp = self._request("GET", "/auth/me")
        if resp.get("status_code") == 200:
            self._user = json.loads(resp.get("body", b"{}"))
            return self._user
        return None

    def post_history(self, url: str, title: str = None):
        self._request("POST", "/api/history", json.dumps({"url": url, "title": title}))

    def is_authenticated(self) -> bool:
        return self.me() is not None

    @property
    def token(self) -> str | None:
        return self._token

    @property
    def user(self) -> dict | None:
        return self._user

    def _request(self, method: str, path: str, body: str = None) -> dict:
        host, port = self._base_url.replace("http://", "").split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            headers = {"Content-Type": "application/json"}
            if self._token:
                headers["Cookie"] = f"wc_session={self._token}"
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_data = resp.read()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return {"status_code": resp.status, "headers": headers, "body": resp_data}
        finally:
            conn.close()

    def _extract_token(self, resp: dict):
        cookie = resp.get("headers", {}).get("set-cookie", "")
        if "wc_session=" in cookie:
            start = cookie.index("wc_session=") + 11
            end = cookie.index(";", start) if ";" in cookie[start:] else len(cookie)
            self._token = cookie[start:end]
