"""Unit tests for the browser DNS client (RFC 1035 wire format)."""

import unittest
from unittest.mock import patch

from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, QTYPE, RCODE, RR

from browser.core.dns_client import DNSClient, DNSError, DNSResult


def _wire_response(ip="127.0.0.1", ttl=30, domain="example.local", rcode=RCODE.NOERROR) -> bytes:
    header = DNSHeader(
        id=12345,
        qr=1, aa=1, ra=0,
        rcode=rcode,
    )
    questions = [DNSQuestion(domain, qtype=QTYPE.A)]
    rr_list = []
    if rcode == RCODE.NOERROR:
        rr_list = [RR(rname=domain, rtype=QTYPE.A, rclass=1, ttl=ttl, rdata=A(ip))]
    record = DNSRecord(header=header, questions=questions, rr=rr_list)
    return bytes(record.pack())


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
        return self.response_bytes, ("127.0.0.1", 53)

    def close(self):
        self.closed = True


class TestDNSClient(unittest.IsolatedAsyncioTestCase):
    async def test_query_uses_wire_format_and_converts_ttl_to_expiry(self):
        fake_socket = FakeSocket(_wire_response(ip="127.0.0.1", ttl=30))
        client = DNSClient(server_host="127.0.0.1", server_port=53, enable_cache=False)

        with patch("browser.core.dns_client.socket.socket", return_value=fake_socket):
            with patch("browser.core.dns_client.time.time", return_value=1000.0):
                result = await client.resolve("Example.Local.")

        self.assertEqual(result.domain, "example.local")
        self.assertEqual(result.ip, "127.0.0.1")
        self.assertEqual(result.expire_at, 1030.0)
        sent_record = DNSRecord.parse(fake_socket.sent_payload)
        self.assertEqual(len(sent_record.questions), 1)
        sent_q = sent_record.questions[0]
        self.assertEqual(str(sent_q.qname).rstrip("."), "example.local")
        self.assertEqual(sent_q.qtype, QTYPE.A)

    async def test_nxdomain_raises(self):
        fake_socket = FakeSocket(_wire_response(rcode=RCODE.NXDOMAIN))
        client = DNSClient(enable_cache=False)

        with patch("browser.core.dns_client.socket.socket", return_value=fake_socket):
            with self.assertRaises(DNSError) as ctx:
                await client.resolve("unknown.local")

        self.assertIn("error", str(ctx.exception).lower())

    async def test_cache_hit_returns_without_socket_call(self):
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
                result = await client.resolve("example.local")

        self.assertTrue(result.from_cache)
        self.assertEqual(result.ip, "127.0.0.1")

    async def test_ipv4_literal_bypasses_dns_query(self):
        client = DNSClient(enable_cache=True)

        with patch(
            "browser.core.dns_client.socket.socket",
            side_effect=AssertionError("socket should not be created for IPv4 literals"),
        ):
            result = await client.resolve("127.0.0.1")

        self.assertEqual(result.domain, "127.0.0.1")
        self.assertEqual(result.ip, "127.0.0.1")
        self.assertFalse(result.from_cache)
        self.assertIsNone(result.expire_at)


if __name__ == "__main__":
    unittest.main()
