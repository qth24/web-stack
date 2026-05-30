import unittest
import threading
import time
import json
import http.client
from server.app.db import init_schema
from server.app.server import AppServer


class TestAppServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_schema()
        cls.server = AppServer("127.0.0.1", 8099, max_workers=4)
        cls._thread = threading.Thread(target=cls.server.start, daemon=True)
        cls._thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", 8099, timeout=5)
        hdrs = headers or {}
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, resp.getheaders(), data

    def _register(self, username, password="test1234"):
        body = json.dumps({"username": username, "password": password}).encode()
        status, headers, data = self._request(
            "POST", "/auth/register", body=body,
            headers={"Content-Type": "application/json"},
        )
        return status, headers, data

    def _extract_cookie(self, headers):
        for name, value in headers:
            if name.lower() == "set-cookie" and "wc_session=" in value:
                return value.split("wc_session=")[1].split(";")[0]
        return None

    def test_health_endpoint(self):
        status, _, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "ok")

    def test_register_and_login_flow(self):
        import uuid
        username = f"t_{uuid.uuid4().hex[:6]}"
        status, headers, body = self._register(username)
        self.assertEqual(status, 201)
        data = json.loads(body)
        self.assertEqual(data["username"], username)

        status, headers, _ = self._request(
            "POST", "/auth/login",
            body=json.dumps({"username": username, "password": "test1234"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)

    def test_not_found(self):
        status, _, body = self._request("GET", "/nonexistent")
        self.assertEqual(status, 404)
        self.assertIn(b"not found", body)

    def test_path_traversal_blocked(self):
        status, _, body = self._request("GET", "/../../../etc/passwd")
        self.assertEqual(status, 403)

    def test_me_with_cookie(self):
        import uuid
        username = f"t_{uuid.uuid4().hex[:6]}"
        _, headers, _ = self._register(username)
        token = self._extract_cookie(headers)
        self.assertIsNotNone(token, "Should receive a session cookie")

        status, _, body = self._request(
            "GET", "/auth/me",
            headers={"Cookie": f"wc_session={token}"},
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["username"], username)

    def test_history_post_and_get(self):
        import uuid
        username = f"t_{uuid.uuid4().hex[:6]}"
        _, headers, _ = self._register(username)
        token = self._extract_cookie(headers)
        self.assertIsNotNone(token)

        status, _, body = self._request(
            "POST", "/api/history",
            body=json.dumps({"url": "http://example.com", "title": "Example"}).encode(),
            headers={"Cookie": f"wc_session={token}", "Content-Type": "application/json"},
        )
        self.assertEqual(status, 201)

        status, _, body = self._request(
            "GET", "/api/history",
            headers={"Cookie": f"wc_session={token}"},
        )
        self.assertEqual(status, 200)
        entries = json.loads(body)
        self.assertIsInstance(entries, list)
        self.assertTrue(any(e["url"] == "http://example.com" for e in entries))

    def test_messages_post_and_get(self):
        import uuid
        username = f"t_{uuid.uuid4().hex[:6]}"
        _, headers, _ = self._register(username)
        token = self._extract_cookie(headers)
        self.assertIsNotNone(token)

        status, _, body = self._request(
            "POST", "/api/messages",
            body=json.dumps({"content": "Hello world"}).encode(),
            headers={"Cookie": f"wc_session={token}", "Content-Type": "application/json"},
        )
        self.assertEqual(status, 201)

        status, _, body = self._request(
            "GET", "/api/messages",
            headers={"Cookie": f"wc_session={token}"},
        )
        self.assertEqual(status, 200)
        entries = json.loads(body)
        self.assertIsInstance(entries, list)
        self.assertTrue(any(e["content"] == "Hello world" for e in entries))

    def test_api_routes_require_auth(self):
        status, _, _ = self._request("GET", "/api/history")
        self.assertEqual(status, 401)

        status, _, _ = self._request("POST", "/api/history",
                                     body=json.dumps({"url": "http://x.com"}).encode(),
                                     headers={"Content-Type": "application/json"})
        self.assertEqual(status, 401)

        status, _, _ = self._request("GET", "/api/messages")
        self.assertEqual(status, 401)

        status, _, _ = self._request("POST", "/api/messages",
                                     body=json.dumps({"content": "x"}).encode(),
                                     headers={"Content-Type": "application/json"})
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
