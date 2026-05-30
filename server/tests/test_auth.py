import unittest
import json
import uuid
from server.app.db import init_schema
from server.app.auth import hash_password, handle_register, handle_login, handle_me, handle_logout
from server.app.models import create_session, validate_session_token, delete_session


class TestHashPassword(unittest.TestCase):
    def test_consistent_with_same_salt(self):
        h1, s1 = hash_password("testpass")
        h2, _ = hash_password("testpass", s1)
        self.assertEqual(h1, h2)

    def test_different_with_no_salt(self):
        h1, _ = hash_password("testpass")
        h2, _ = hash_password("testpass")
        self.assertNotEqual(h1, h2)

    def test_output_is_hex(self):
        h, s = hash_password("testpass")
        self.assertEqual(len(h), 64)
        self.assertEqual(len(s), 32)


class TestRegister(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_schema()

    def test_creates_user_and_returns_cookie(self):
        username = f"tu_{uuid.uuid4().hex[:8]}"
        body = json.dumps({"username": username, "password": "secret123"}).encode()
        resp = handle_register(body)
        self.assertEqual(resp.status_code, 201)
        self.assertIn("set-cookie", resp.headers)
        self.assertIn("wc_session=", resp.headers["set-cookie"])

    def test_duplicate_username_rejected(self):
        username = f"tu_{uuid.uuid4().hex[:8]}"
        body = json.dumps({"username": username, "password": "secret123"}).encode()
        handle_register(body)
        resp = handle_register(body)
        self.assertEqual(resp.status_code, 409)

    def test_empty_username_rejected(self):
        resp = handle_register(json.dumps({"username": "", "password": "secret"}).encode())
        self.assertEqual(resp.status_code, 400)

    def test_short_password_rejected(self):
        resp = handle_register(json.dumps({"username": "testuser", "password": "ab"}).encode())
        self.assertEqual(resp.status_code, 422)

    def test_invalid_json(self):
        resp = handle_register(b"not json")
        self.assertEqual(resp.status_code, 400)


class TestLogin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_schema()

    def setUp(self):
        self.username = f"tu_{uuid.uuid4().hex[:8]}"
        handle_register(json.dumps({"username": self.username, "password": "secret123"}).encode())

    def test_valid_credentials(self):
        resp = handle_login(json.dumps({"username": self.username, "password": "secret123"}).encode())
        self.assertEqual(resp.status_code, 200)
        self.assertIn("set-cookie", resp.headers)

    def test_wrong_password(self):
        resp = handle_login(json.dumps({"username": self.username, "password": "wrongpass"}).encode())
        self.assertEqual(resp.status_code, 401)

    def test_nonexistent_user(self):
        resp = handle_login(json.dumps({"username": "nobody_long_random_name", "password": "secret"}).encode())
        self.assertEqual(resp.status_code, 401)


class TestMe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_schema()

    def test_me_with_valid_token(self):
        username = f"tu_{uuid.uuid4().hex[:8]}"
        resp = handle_register(json.dumps({"username": username, "password": "secret123"}).encode())
        cookie = resp.headers.get("set-cookie", "")
        token = cookie.split("wc_session=")[1].split(";")[0]

        resp = handle_me(token)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.body)
        self.assertEqual(data["username"], username)

    def test_me_with_invalid_token(self):
        resp = handle_me("invalid_token")
        self.assertEqual(resp.status_code, 401)

    def test_me_with_none_token(self):
        resp = handle_me(None)
        self.assertEqual(resp.status_code, 401)


class TestLogout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_schema()

    def test_logout_clears_cookie(self):
        username = f"tu_{uuid.uuid4().hex[:8]}"
        resp = handle_register(json.dumps({"username": username, "password": "secret123"}).encode())
        cookie = resp.headers.get("set-cookie", "")
        token = cookie.split("wc_session=")[1].split(";")[0]

        resp = handle_logout(token)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("set-cookie", resp.headers)
        self.assertIn("Max-Age=0", resp.headers["set-cookie"])

        resp = handle_me(token)
        self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
