import asyncio
import unittest
from pathlib import Path

from server.app.router import route
from server.shared.static import set_public_dir


def _request(path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: myweb.local\r\nConnection: close\r\n\r\n".encode()


class TestRouterStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        public_dir = Path(__file__).resolve().parents[2] / "http-server" / "public"
        set_public_dir(str(public_dir))

    def test_root_serves_index_html(self):
        response = asyncio.run(route(_request("/")))

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"HTTP Server is running", response.body)
        self.assertTrue(response.headers.get("Content-Type", "").startswith("text/html"))

    def test_direct_asset_serves_public_file(self):
        response = asyncio.run(route(_request("/styles.css")))

        self.assertEqual(response.status_code, 200)
        self.assertIn(b".container", response.body)
        self.assertTrue(response.headers.get("Content-Type", "").startswith("text/css"))


if __name__ == "__main__":
    unittest.main()
