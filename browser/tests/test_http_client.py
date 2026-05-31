"""Tests for browser HTTP response parsing helpers."""

import unittest

from browser.core.http_client import HTTPClient


class TestHTTPClient(unittest.TestCase):
    def test_header_lookup_is_case_insensitive(self):
        client = HTTPClient(timeout=1)
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"content-type: text/html; charset=utf-8\r\n"
            b"cache-control: max-age=60\r\n"
            b"content-length: 13\r\n"
            b"\r\n"
            b"<h1>Hello</h1>"
        )

        response = client._parse_response(raw)

        self.assertEqual(response.header("Content-Type"), "text/html; charset=utf-8")
        self.assertEqual(response.header("content-type"), "text/html; charset=utf-8")
        self.assertEqual(response.header("Cache-Control"), "max-age=60")

    def test_chunked_transfer_encoding_is_detected_case_insensitively(self):
        client = HTTPClient(timeout=1)
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"transfer-encoding: chunked\r\n"
            b"content-type: text/plain\r\n"
            b"\r\n"
            b"5\r\nHello\r\n0\r\n\r\n"
        )

        response = client._parse_response(raw)

        self.assertEqual(response.body, "Hello")
        self.assertEqual(response.header("Content-Type"), "text/plain")


if __name__ == "__main__":
    unittest.main()
