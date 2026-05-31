"""Tests for the Mini VPN tunnel server and protocol."""

import asyncio
import json
import socket
import threading
import time
import unittest

from vpn.protocol import (
    STATUS_OK,
    STATUS_UNAUTHORIZED,
    build_connect_request,
    build_stream_connect_request,
    decode_frame,
    encode_frame,
    parse_connect_request,
    parse_stream_connect_request,
)
from vpn.vpn_server import MiniVPNServer, TunnelPolicy, VPNRequestHandler


class OneShotHTTPServer:
    def __init__(self, response: bytes):
        self.response = response
        self.received = b""
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
            while b"\r\n\r\n" not in self.received:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                self.received += chunk
            conn.sendall(self.response)
        self.socket.close()


class EchoServer:
    def __init__(self):
        self.received = b""
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
            self.received = conn.recv(4096)
            conn.sendall(self.received.upper())
        self.socket.close()


def _run_server(server):
    asyncio.run(server.serve_forever())


class TestVPNProtocol(unittest.TestCase):
    def test_parse_connect_request_decodes_payload(self):
        frame = build_connect_request(
            request_id="req-1",
            token="demo-token",
            target_host="127.0.0.1",
            target_port=8000,
            payload=b"GET / HTTP/1.1\r\n\r\n",
        )
        request = parse_connect_request(frame)
        self.assertEqual(request.request_id, "req-1")
        self.assertEqual(request.target_host, "127.0.0.1")
        self.assertEqual(request.target_port, 8000)
        self.assertEqual(request.payload, b"GET / HTTP/1.1\r\n\r\n")

    def test_parse_stream_connect_request_without_payload(self):
        frame = build_stream_connect_request(
            request_id="req-stream-1",
            token="demo-token",
            target_host="127.0.0.1",
            target_port=9443,
        )
        request = parse_stream_connect_request(frame)
        self.assertEqual(request.request_id, "req-stream-1")
        self.assertEqual(request.target_host, "127.0.0.1")
        self.assertEqual(request.target_port, 9443)


class TestVPNHandler(unittest.TestCase):
    def test_valid_frame_forwards_to_upstream(self):
        upstream = OneShotHTTPServer(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
        )
        upstream.start()
        handler = VPNRequestHandler(
            token="demo-token",
            policy=TunnelPolicy(allow_private_targets=True),
            connect_timeout=1,
            read_timeout=1,
        )
        raw_request = b"GET / HTTP/1.1\r\nHost: example.local\r\nConnection: close\r\n\r\n"
        frame = build_connect_request(
            request_id="req-2",
            token="demo-token",
            target_host="127.0.0.1",
            target_port=upstream.port,
            payload=raw_request,
        )
        response = asyncio.run(handler.handle_frame(encode_frame(frame)))
        upstream.join()

        self.assertEqual(response["status"], STATUS_OK)
        self.assertIn(b"GET / HTTP/1.1", upstream.received)

    def test_invalid_token_is_unauthorized(self):
        handler = VPNRequestHandler(token="demo-token")
        frame = build_connect_request(
            request_id="req-3",
            token="wrong",
            target_host="127.0.0.1",
            target_port=8000,
            payload=b"GET / HTTP/1.1\r\n\r\n",
        )
        response = asyncio.run(handler.handle_frame(encode_frame(frame)))
        self.assertEqual(response["status"], STATUS_UNAUTHORIZED)


class TestMiniVPNServer(unittest.TestCase):
    def test_live_tcp_roundtrip(self):
        upstream = OneShotHTTPServer(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        )
        upstream.start()
        handler = VPNRequestHandler(token="demo-token", connect_timeout=1, read_timeout=1)
        server = MiniVPNServer("127.0.0.1", 0, handler)
        thread = threading.Thread(target=_run_server, args=(server,), daemon=True)
        thread.start()
        deadline = time.time() + 5
        while time.time() < deadline and not server.sockets:
            time.sleep(0.05)
        _host, port = server.sockets[0].getsockname()
        try:
            frame = build_connect_request(
                request_id="req-4",
                token="demo-token",
                target_host="127.0.0.1",
                target_port=upstream.port,
                payload=b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n",
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            with sock:
                sock.connect(("127.0.0.1", port))
                sock.sendall(encode_frame(frame))
                data = b""
                while not data.endswith(b"\n"):
                    data += sock.recv(4096)
            response = decode_frame(data)
        finally:
            asyncio.run_coroutine_threadsafe(server.stop(), server.loop).result(timeout=5)
            thread.join(timeout=2)
            upstream.join()

        self.assertEqual(response["status"], STATUS_OK)
        self.assertEqual(response["id"], "req-4")

    def test_live_stream_roundtrip(self):
        upstream = EchoServer()
        upstream.start()
        handler = VPNRequestHandler(token="demo-token", connect_timeout=1, read_timeout=1)
        server = MiniVPNServer("127.0.0.1", 0, handler)
        thread = threading.Thread(target=_run_server, args=(server,), daemon=True)
        thread.start()
        deadline = time.time() + 5
        while time.time() < deadline and not server.sockets:
            time.sleep(0.05)
        _host, port = server.sockets[0].getsockname()
        try:
            frame = build_stream_connect_request(
                request_id="req-5",
                token="demo-token",
                target_host="127.0.0.1",
                target_port=upstream.port,
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            with sock:
                sock.connect(("127.0.0.1", port))
                sock.sendall(encode_frame(frame))
                data = b""
                while not data.endswith(b"\n"):
                    data += sock.recv(4096)
                response = decode_frame(data)
                sock.sendall(b"stream")
                echoed = sock.recv(4096)
        finally:
            asyncio.run_coroutine_threadsafe(server.stop(), server.loop).result(timeout=5)
            thread.join(timeout=2)
            upstream.join()

        self.assertEqual(response["status"], STATUS_OK)
        self.assertTrue(response["stream"])
        self.assertEqual(echoed, b"STREAM")
        self.assertEqual(upstream.received, b"stream")


if __name__ == "__main__":
    unittest.main()
