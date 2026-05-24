"""Unit tests for the browser DNS client."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from browser.core.dns_client import DNSClient, DNSError, DNSResult


class FakeSocket:
    def __init__(self, response_bytes: bytes):
        self.response_bytes = response_bytes
        self.sent_payload = None
        self.sent_address = None
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendto(self, data: bytes, address):
        self.sent_payload = data
        self.sent_address = address

    def recvfrom(self, _buffer_size):
        return self.response_bytes, ("127.0.0.1", 5336)

    def close(self):
        self.closed = True


def _response_payload(**overrides) -> bytes:
    response = {
        "version": "v1",
        "id": "req-123",
        "status": "OK",
        "domain": "example.local",
        "qtype": "A",
        "ip": "127.0.0.1",
        "ttl": 30,
    }
    response.update(overrides)
    return json.dumps(response).encode("utf-8")


class TestDNSClient(unittest.TestCase):
    def test_query_uses_v1_contract_and_converts_ttl_to_expiry(self):
        fake_socket = FakeSocket(_response_payload())
        client = DNSClient(server_host="127.0.0.1", server_port=5336, enable_cache=False)

        with patch("browser.core.dns_client.socket.socket", return_value=fake_socket):
            with patch("browser.core.dns_client.uuid.uuid4", return_value=SimpleNamespace(hex="req-123")):
                with patch("browser.core.dns_client.time.time", return_value=1000.0):
                    result = client.resolve("Example.Local.")

        self.assertEqual(result.domain, "example.local")
        self.assertEqual(result.ip, "127.0.0.1")
        self.assertEqual(result.expire_at, 1030.0)
        sent = json.loads(fake_socket.sent_payload.decode("utf-8"))
        self.assertEqual(sent["version"], "v1")
        self.assertEqual(sent["id"], "req-123")
        self.assertEqual(sent["op"], "resolve")
        self.assertEqual(sent["domain"], "example.local")
        self.assertEqual(sent["qtype"], "A")

    def test_unsupported_response_version_raises(self):
        fake_socket = FakeSocket(_response_payload(version="v2"))
        client = DNSClient(enable_cache=False)

        with patch("browser.core.dns_client.socket.socket", return_value=fake_socket):
            with patch("browser.core.dns_client.uuid.uuid4", return_value=SimpleNamespace(hex="req-123")):
                with self.assertRaises(DNSError) as ctx:
                    client.resolve("example.local")

        self.assertIn("unsupported protocol version", str(ctx.exception).lower())

    def test_unsupported_qtype_error_is_exposed(self):
        fake_socket = FakeSocket(
            _response_payload(
                status="UNSUPPORTED_QTYPE",
                qtype="AAAA",
                ip=None,
                ttl=None,
                message="Unsupported qtype: 'AAAA'",
            )
        )
        client = DNSClient(enable_cache=False)

        with patch("browser.core.dns_client.socket.socket", return_value=fake_socket):
            with patch("browser.core.dns_client.uuid.uuid4", return_value=SimpleNamespace(hex="req-123")):
                with self.assertRaises(DNSError) as ctx:
                    client.resolve("example.local")

        self.assertIn("UNSUPPORTED_QTYPE", str(ctx.exception))

    def test_cache_hit_returns_without_socket_call(self):
        client = DNSClient(enable_cache=True)
        client._cache["example.local"] = DNSResult(
            domain="example.local",
            ip="127.0.0.1",
            expire_at=2000.0,
        )

        with patch("browser.core.dns_client.time.time", return_value=1000.0):
            with patch(
                "browser.core.dns_client.socket.socket",
                side_effect=AssertionError("socket should not be created"),
            ):
                result = client.resolve("example.local")

        self.assertTrue(result.from_cache)
        self.assertEqual(result.ip, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
