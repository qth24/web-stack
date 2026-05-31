import asyncio
import unittest
import threading
import time
import socket
import http.server
import json
import http.client
from server.gateway.server import GatewayServer


def _wait_for_server(host: str, port: int, deadline: float):
    while time.time() < deadline:
        try:
            with socket.socket() as s:
                s.settimeout(0.5)
                s.connect((host, port))
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)
    raise RuntimeError(f"Server {host}:{port} did not start within deadline")


def _run_server(server):
    asyncio.run(server.serve_forever())


class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        elif self.path == "/test":
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"hello from backend")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else b""
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def _find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestGatewayServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._backend_port = _find_free_port()
        cls._gateway_port = _find_free_port()

        cls._backend = http.server.ThreadingHTTPServer(
            ("127.0.0.1", cls._backend_port), EchoHandler
        )
        cls._backend_thread = threading.Thread(
            target=cls._backend.serve_forever, daemon=True
        )
        cls._backend_thread.start()

        cls._gateway = GatewayServer(
            host="127.0.0.1",
            port=cls._gateway_port,
            backends=[f"127.0.0.1:{cls._backend_port}"],
            node_id="gw-test",
            max_workers=4,
        )
        cls._gateway_thread = threading.Thread(
            target=_run_server, args=(cls._gateway,), daemon=True
        )
        cls._gateway_thread.start()
        _wait_for_server("127.0.0.1", cls._gateway_port, time.time() + 5)

    @classmethod
    def tearDownClass(cls):
        asyncio.run_coroutine_threadsafe(cls._gateway.stop(), cls._gateway.loop).result(timeout=5)
        cls._backend.shutdown()
        cls._backend_thread.join(timeout=2)
        cls._gateway_thread.join(timeout=2)

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self._gateway_port, timeout=5
        )
        hdrs = headers or {}
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        resp_headers = dict(resp.getheaders())
        conn.close()
        return resp.status, resp_headers, data

    def test_health_returns_200(self):
        status, _, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload.get("status"), "ok")
        self.assertEqual(payload.get("node"), "gw-test")

    def test_status_returns_backend_pool_info(self):
        status, _, body = self._request("GET", "/status")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload.get("node"), "gw-test")
        self.assertIn("backend_pool", payload)
        self.assertIn("backends", payload["backend_pool"])
        self.assertEqual(payload["backend_pool"]["healthy_count"], 1)
        self.assertIn("total_requests", payload)
        self.assertIn("uptime_seconds", payload)

    def test_proxy_request_returns_200_with_upstream_header(self):
        status, headers, body = self._request("GET", "/test")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello from backend")
        self.assertEqual(headers.get("x-upstream-node"), "gw-test")

    def test_502_when_all_backends_unhealthy(self):
        self._gateway._pool.mark_down(f"127.0.0.1:{self._backend_port}")
        try:
            status, _, body = self._request("GET", "/test")
            self.assertEqual(status, 502)
        finally:
            self._gateway._pool.mark_up(f"127.0.0.1:{self._backend_port}")

    def test_missing_backend_returns_404(self):
        status, _, _ = self._request("GET", "/nonexistent")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
