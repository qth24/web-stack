import unittest

from server.shared.access_log import peer_label, request_line_from_raw


class TestAccessLogHelpers(unittest.TestCase):
    def test_request_line_from_raw_extracts_method_and_target(self):
        raw = b"GET /hello?x=1 HTTP/1.1\r\nHost: example.local\r\n\r\n"
        method, target = request_line_from_raw(raw)
        self.assertEqual(method, "GET")
        self.assertEqual(target, "/hello?x=1")

    def test_request_line_from_raw_handles_empty_input(self):
        method, target = request_line_from_raw(b"")
        self.assertEqual(method, "-")
        self.assertEqual(target, "-")

    def test_peer_label_formats_host_and_port(self):
        self.assertEqual(peer_label(("127.0.0.1", 8081)), "127.0.0.1:8081")
        self.assertEqual(peer_label(None), "-")


if __name__ == "__main__":
    unittest.main()
