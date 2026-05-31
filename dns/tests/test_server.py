import asyncio
import json
import unittest
import socket
import threading
import time
from pathlib import Path
from dnslib import DNSRecord

TEST_PORT = 5353


def _run_server(server):
    asyncio.run(server.serve_forever())


class TestDNSServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from dns.server import DNSServer
        cls.server = DNSServer(port=TEST_PORT)
        cls._thread = threading.Thread(target=_run_server, args=(cls.server,), daemon=True)
        cls._thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        asyncio.run_coroutine_threadsafe(cls.server.stop(), cls.server.loop).result(timeout=5)
        cls._thread.join(timeout=2)

    def _send_query(self, domain: str, timeout: float = 2.0) -> bytes | None:
        from dns.wire import encode_query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            packet = encode_query(domain.encode())
            sock.sendto(packet, ("127.0.0.1", TEST_PORT))
            data, _ = sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        finally:
            sock.close()

    def test_health(self):
        data = self._send_query("myweb.local")
        self.assertIsNotNone(data)

    def test_resolves_known_domain(self):
        data = self._send_query("myweb.local")
        self.assertIsNotNone(data)
        record = DNSRecord.parse(data)
        self.assertEqual(record.header.rcode, 0)
        self.assertGreater(len(record.rr), 0)
        records = json.loads((Path(__file__).resolve().parents[1] / "dns_records.json").read_text(encoding="utf-8"))
        self.assertEqual(str(record.rr[0].rdata), records["myweb.local"]["ip"])

    def test_unknown_domain_returns_nxdomain(self):
        data = self._send_query("nonexistent.local")
        self.assertIsNotNone(data)
        record = DNSRecord.parse(data)
        self.assertEqual(record.header.rcode, 3)

    def test_unsupported_qtype_returns_notimp(self):
        from dns.wire import encode_query
        from dnslib import QTYPE
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            packet = encode_query(b"myweb.local", qtype=QTYPE.AAAA)
            sock.sendto(packet, ("127.0.0.1", TEST_PORT))
            data, _ = sock.recvfrom(4096)
            sock.close()
            record = DNSRecord.parse(data)
            self.assertEqual(record.header.rcode, 4)
        except socket.timeout:
            self.fail("Request timed out")


if __name__ == "__main__":
    unittest.main()
