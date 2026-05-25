"""Tests for the browser Mini VPN client."""

import socket
import threading
import unittest

from browser.core.vpn_client import VPNClient
from vpn.protocol import build_success_response, decode_frame, encode_frame


class FakeVPNServer:
    def __init__(self, response_payload: bytes):
        self.response_payload = response_payload
        self.frame = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.host, self.port = self.socket.getsockname()
        self.socket.listen()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def join(self):
        self.thread.join(timeout=2)

    def _serve(self):
        conn, _addr = self.socket.accept()
        with conn:
            data = b""
            while not data.endswith(b"\n"):
                data += conn.recv(4096)
            self.frame = decode_frame(data)
            conn.sendall(encode_frame(build_success_response(self.frame["id"], self.response_payload)))
        self.socket.close()


class TestVPNClient(unittest.TestCase):
    def test_get_wraps_http_request_and_parses_response(self):
        raw_http = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
        server = FakeVPNServer(raw_http)
        server.start()
        client = VPNClient(
            host="127.0.0.1",
            port=server.port,
            token="demo-token",
            timeout=2,
        )

        response = client.get(
            ip="127.0.0.1",
            port=8000,
            path="/",
            host="myweb.local",
            extra_headers={"X-Test": "1"},
        )
        server.join()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, "OK")
        self.assertEqual(server.frame["op"], "connect")
        self.assertEqual(server.frame["token"], "demo-token")
        self.assertEqual(server.frame["target_host"], "127.0.0.1")
        self.assertEqual(server.frame["target_port"], 8000)
        self.assertEqual(server.frame["server_name"], "myweb.local")


if __name__ == "__main__":
    unittest.main()
