import unittest
import struct
from dns.wire import encode_query, decode_query, encode_response, encode_error, QueryInfo


class TestWireProtocol(unittest.TestCase):
    def setUp(self):
        self.domain = b"example.com"
        self.qtype_a = 1
        self.qclass_in = 1

    def test_encode_query_produces_valid_dns_packet(self):
        packet = encode_query(self.domain, self.qtype_a)
        self.assertIsInstance(packet, bytes)
        self.assertGreaterEqual(len(packet), 12)
        tid = struct.unpack("!H", packet[:2])[0]
        self.assertGreater(tid, 0)

    def test_encode_query_different_ids(self):
        p1 = encode_query(self.domain, self.qtype_a)
        p2 = encode_query(self.domain, self.qtype_a)
        self.assertNotEqual(struct.unpack("!H", p1[:2])[0], struct.unpack("!H", p2[:2])[0])

    def test_decode_query_parses_valid_packet(self):
        packet = encode_query(self.domain, self.qtype_a)
        info = decode_query(packet)
        self.assertIsNotNone(info)
        self.assertEqual(info.domain, b"example.com")
        self.assertEqual(info.qtype, self.qtype_a)
        self.assertEqual(info.qclass, self.qclass_in)

    def test_decode_query_rejects_bad_truncated_packet(self):
        info = decode_query(b"\x00\x00")
        self.assertIsNone(info)

    def test_decode_query_extracts_transaction_id(self):
        from dnslib import DNSRecord
        q = DNSRecord.question("test.local")
        packet = bytes(q.pack())
        info = decode_query(packet)
        self.assertEqual(info.transaction_id, q.header.id)
        self.assertEqual(info.domain, b"test.local")

    def test_encode_response_builds_answer(self):
        packet = encode_query(self.domain, self.qtype_a)
        info = decode_query(packet)
        resp = encode_response(info, [(b"example.com", 1, 1, 300, b"\x7f\x00\x00\x01")])
        self.assertGreater(len(resp), len(packet))

    def test_encode_response_includes_answers(self):
        info = QueryInfo(1234, b"myweb.local", 1, 1)
        resp = encode_response(info, [(b"myweb.local", 1, 1, 60, b"\x0a\xb2\x34\x80")])
        record = decode_query(resp)
        self.assertIsNotNone(record)

    def test_encode_error_returns_nxdomain(self):
        info = QueryInfo(42, b"missing.local", 1, 1)
        packet = encode_error(info, 3)
        self.assertGreater(len(packet), 12)


if __name__ == "__main__":
    unittest.main()
