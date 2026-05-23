"""Comprehensive unit tests for the HTTP server module.

Covers: request parsing, routing, static file serving, path traversal protection,
response headers (security + cache), ETag/304, and the static cache.

Run from http-server/src/:
    python3 -m unittest test_http_server -v
"""

import json
import os
import sys
import time
import unittest
from pathlib import Path

# Ensure the src directory is on the import path.
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from http_parser import parse_request
from http_response import build_response, STATUS_TEXT
from router import (
    handle_request,
    serve_static_file,
    resolve_static_path,
    SECURITY_HEADERS,
    create_text_response,
    create_json_response,
)
from static_cache import StaticCache, static_cache
from mime_types import get_mime_type, MIME_TYPES
from config import PUBLIC_DIR, CACHE_TTL, SERVER_NAME


# ---------------------------------------------------------------------------
# TestParseRequest
# ---------------------------------------------------------------------------

class TestParseRequest(unittest.TestCase):
    """Tests for http_parser.parse_request."""

    def test_valid_get(self):
        raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = parse_request(raw)
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["target"], "/index.html")
        self.assertEqual(result["http_version"], "HTTP/1.1")
        self.assertEqual(result["headers"]["host"], "example.com")
        self.assertEqual(result["body"], "")

    def test_valid_post_with_body(self):
        body = "name=test&value=1"
        raw = (
            b"POST /api HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 17\r\n"
            b"\r\n"
            + body.encode()
        )
        result = parse_request(raw)
        self.assertEqual(result["method"], "POST")
        self.assertEqual(result["target"], "/api")
        self.assertEqual(result["headers"]["content-length"], "17")
        self.assertEqual(result["body"], body)

    def test_missing_headers(self):
        """Request with only request line, no headers."""
        raw = b"GET / HTTP/1.1\r\n\r\n"
        result = parse_request(raw)
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["target"], "/")
        self.assertEqual(result["headers"], {})

    def test_empty_request(self):
        raw = b""
        with self.assertRaises(ValueError) as ctx:
            parse_request(raw)
        self.assertIn("Empty", str(ctx.exception))

    def test_non_utf8(self):
        raw = b"\xff\xfe GET / HTTP/1.1\r\n\r\n"
        with self.assertRaises(ValueError) as ctx:
            parse_request(raw)
        self.assertIn("UTF-8", str(ctx.exception))

    def test_invalid_request_line(self):
        """Request line with wrong number of parts."""
        raw = b"GET / HTTP/1.1 EXTRA\r\n\r\n"
        with self.assertRaises(ValueError) as ctx:
            parse_request(raw)
        self.assertIn("Invalid request line", str(ctx.exception))

    def test_headers_without_colon_skipped(self):
        """Header lines without ':' are silently skipped."""
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nBadHeader\r\nAccept: text/html\r\n\r\n"
        result = parse_request(raw)
        self.assertEqual(result["headers"]["host"], "example.com")
        self.assertEqual(result["headers"]["accept"], "text/html")
        self.assertNotIn("badheader", result["headers"])


# ---------------------------------------------------------------------------
# TestBuildResponse
# ---------------------------------------------------------------------------

class TestBuildResponse(unittest.TestCase):
    """Tests for http_response.build_response."""

    def _parse_response(self, response_bytes):
        """Helper to split response into status line, headers dict, body."""
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        status_line = lines[0]
        headers = {}
        for line in lines[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
        return status_line, headers, body

    def test_200_ok(self):
        resp = build_response(200, {}, b"Hello")
        status_line, headers, body = self._parse_response(resp)
        self.assertEqual(status_line, "HTTP/1.1 200 OK")
        self.assertEqual(body, b"Hello")
        self.assertEqual(headers["Content-Length"], "5")

    def test_custom_headers(self):
        resp = build_response(200, {"X-Custom": "value"}, b"")
        status_line, headers, body = self._parse_response(resp)
        self.assertEqual(headers["X-Custom"], "value")

    def test_body_as_string(self):
        resp = build_response(200, {}, "text body")
        _, _, body = self._parse_response(resp)
        self.assertEqual(body, b"text body")

    def test_body_as_bytes(self):
        resp = build_response(200, {}, b"binary body")
        _, _, body = self._parse_response(resp)
        self.assertEqual(body, b"binary body")

    def test_404(self):
        resp = build_response(404, {}, b"Not Found")
        status_line, _, _ = self._parse_response(resp)
        self.assertEqual(status_line, "HTTP/1.1 404 Not Found")

    def test_304(self):
        resp = build_response(304, {"ETag": '"abc123"'}, b"")
        status_line, headers, body = self._parse_response(resp)
        self.assertEqual(status_line, "HTTP/1.1 304 Not Modified")
        self.assertEqual(headers["ETag"], '"abc123"')
        self.assertEqual(body, b"")

    def test_unknown_status_code(self):
        resp = build_response(999, {}, b"")
        status_line, _, _ = self._parse_response(resp)
        self.assertIn("999", status_line)
        self.assertIn("Unknown", status_line)


# ---------------------------------------------------------------------------
# TestRouter
# ---------------------------------------------------------------------------

class TestRouter(unittest.TestCase):
    """Tests for router.handle_request."""

    def _parse_response(self, response_bytes):
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        status_line = lines[0]
        headers = {}
        for line in lines[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
        return status_line, headers, body

    def test_get_root_200(self):
        req = {"method": "GET", "target": "/", "headers": {}, "body": ""}
        resp = handle_request(req)
        status_line, _, body = self._parse_response(resp)
        self.assertIn("200", status_line)
        self.assertTrue(len(body) > 0)

    def test_get_health_200_json(self):
        req = {"method": "GET", "target": "/health", "headers": {}, "body": ""}
        resp = handle_request(req)
        status_line, headers, body = self._parse_response(resp)
        self.assertIn("200", status_line)
        self.assertIn("application/json", headers["Content-Type"])
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "ok")

    def test_post_root_405(self):
        req = {"method": "POST", "target": "/", "headers": {}, "body": ""}
        resp = handle_request(req)
        status_line, _, body = self._parse_response(resp)
        self.assertIn("405", status_line)

    def test_get_nonexistent_404(self):
        req = {"method": "GET", "target": "/nonexistent", "headers": {}, "body": ""}
        resp = handle_request(req)
        status_line, _, body = self._parse_response(resp)
        self.assertIn("404", status_line)

    def test_delete_root_405(self):
        req = {"method": "DELETE", "target": "/", "headers": {}, "body": ""}
        resp = handle_request(req)
        status_line, _, _ = self._parse_response(resp)
        self.assertIn("405", status_line)


# ---------------------------------------------------------------------------
# TestStaticFileServing
# ---------------------------------------------------------------------------

class TestStaticFileServing(unittest.TestCase):
    """Tests for router.serve_static_file."""

    def _parse_response(self, response_bytes):
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        status_line = lines[0]
        headers = {}
        for line in lines[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
        return status_line, headers, body

    def test_serves_index_html_for_root(self):
        resp = serve_static_file("/")
        status_line, headers, body = self._parse_response(resp)
        self.assertIn("200", status_line)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"<!DOCTYPE html>", body)

    def test_serves_styles_css(self):
        resp = serve_static_file("/styles.css")
        status_line, headers, body = self._parse_response(resp)
        self.assertIn("200", status_line)
        self.assertIn("text/css", headers["Content-Type"])
        self.assertTrue(len(body) > 0)

    def test_correct_mime_types(self):
        """Verify MIME types for served files."""
        resp_html = serve_static_file("/index.html")
        _, headers_html, _ = self._parse_response(resp_html)
        self.assertIn("text/html", headers_html["Content-Type"])

        resp_css = serve_static_file("/styles.css")
        _, headers_css, _ = self._parse_response(resp_css)
        self.assertIn("text/css", headers_css["Content-Type"])

    def test_path_traversal_blocked(self):
        """Path traversal via ../etc/passwd must be blocked."""
        resp = serve_static_file("/../../../etc/passwd")
        status_line, _, _ = self._parse_response(resp)
        self.assertIn("404", status_line)

    def test_nonexistent_file_404(self):
        resp = serve_static_file("/does-not-exist.html")
        status_line, _, _ = self._parse_response(resp)
        self.assertIn("404", status_line)


# ---------------------------------------------------------------------------
# TestSecurityHeaders
# ---------------------------------------------------------------------------

class TestSecurityHeaders(unittest.TestCase):
    """Verify all responses include security headers."""

    def _parse_response(self, response_bytes):
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        headers = {}
        for line in lines[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
        return headers

    def _assert_security_headers(self, headers):
        for key, expected_value in SECURITY_HEADERS.items():
            self.assertEqual(
                headers.get(key),
                expected_value,
                f"Missing or wrong security header: {key}",
            )

    def test_static_file_has_security_headers(self):
        from router import serve_static_file
        resp = serve_static_file("/")
        headers = self._parse_response(resp)
        self._assert_security_headers(headers)

    def test_health_has_security_headers(self):
        req = {"method": "GET", "target": "/health", "headers": {}, "body": ""}
        resp = handle_request(req)
        headers = self._parse_response(resp)
        self._assert_security_headers(headers)

    def test_404_has_security_headers(self):
        req = {"method": "GET", "target": "/nonexistent", "headers": {}, "body": ""}
        resp = handle_request(req)
        headers = self._parse_response(resp)
        self._assert_security_headers(headers)

    def test_405_has_security_headers(self):
        req = {"method": "POST", "target": "/", "headers": {}, "body": ""}
        resp = handle_request(req)
        headers = self._parse_response(resp)
        self._assert_security_headers(headers)


# ---------------------------------------------------------------------------
# TestCacheHeaders
# ---------------------------------------------------------------------------

class TestCacheHeaders(unittest.TestCase):
    """Static file responses include Cache-Control and ETag."""

    def _parse_response(self, response_bytes):
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        headers = {}
        for line in lines[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
        return headers

    def test_static_file_has_cache_control(self):
        resp = serve_static_file("/index.html")
        headers = self._parse_response(resp)
        self.assertIn("Cache-Control", headers)
        self.assertIn("max-age", headers["Cache-Control"])

    def test_static_file_has_etag(self):
        resp = serve_static_file("/index.html")
        headers = self._parse_response(resp)
        self.assertIn("ETag", headers)
        self.assertTrue(headers["ETag"].startswith('"'))
        self.assertTrue(headers["ETag"].endswith('"'))

    def test_cache_control_ttl_matches_config(self):
        resp = serve_static_file("/styles.css")
        headers = self._parse_response(resp)
        self.assertIn(f"max-age={CACHE_TTL}", headers["Cache-Control"])


# ---------------------------------------------------------------------------
# TestETag304
# ---------------------------------------------------------------------------

class TestETag304(unittest.TestCase):
    """If-None-Match matching ETag returns 304, non-matching returns 200."""

    def _parse_response(self, response_bytes):
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        status_line = lines[0]
        headers = {}
        for line in lines[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
        return status_line, headers, body

    def test_matching_etag_returns_304(self):
        # First request to get the ETag
        resp1 = serve_static_file("/index.html")
        _, headers1, _ = self._parse_response(resp1)
        etag = headers1["ETag"]

        # Second request with If-None-Match
        resp2 = serve_static_file(
            "/index.html",
            request_headers={"if-none-match": etag},
        )
        status_line, _, body = self._parse_response(resp2)
        self.assertIn("304", status_line)
        self.assertEqual(body, b"")

    def test_non_matching_etag_returns_200(self):
        resp = serve_static_file(
            "/index.html",
            request_headers={"if-none-match": '"wrong-etag"'},
        )
        status_line, _, body = self._parse_response(resp)
        self.assertIn("200", status_line)
        self.assertTrue(len(body) > 0)

    def test_no_if_none_match_returns_200(self):
        resp = serve_static_file("/index.html", request_headers={})
        status_line, _, body = self._parse_response(resp)
        self.assertIn("200", status_line)
        self.assertTrue(len(body) > 0)


# ---------------------------------------------------------------------------
# TestStaticCache
# ---------------------------------------------------------------------------

class TestStaticCache(unittest.TestCase):
    """Tests for StaticCache: put/get, TTL expiry, max-size eviction, ETag."""

    def setUp(self):
        """Use a fresh cache for each test."""
        self.cache = StaticCache(max_size=3, ttl_seconds=1)

    def test_put_get_roundtrip(self):
        self.cache.put("/test.html", b"content", '"etag1"', "text/html")
        result = self.cache.get("/test.html")
        self.assertIsNotNone(result)
        content_bytes, etag, last_modified, content_type = result
        self.assertEqual(content_bytes, b"content")
        self.assertEqual(etag, '"etag1"')
        self.assertEqual(content_type, "text/html")

    def test_get_missing_key_returns_none(self):
        self.assertIsNone(self.cache.get("/missing.html"))

    def test_ttl_expiry(self):
        short_cache = StaticCache(max_size=10, ttl_seconds=0)
        short_cache.put("/test.html", b"content", '"etag"', "text/html")
        # With ttl_seconds=0, any elapsed time > 0 means expired.
        time.sleep(0.01)
        self.assertIsNone(short_cache.get("/test.html"))

    def test_max_size_eviction(self):
        """Cache with max_size=3 evicts oldest when 4th item added."""
        self.cache.put("/a.html", b"a", '"a"', "text/html")
        self.cache.put("/b.html", b"b", '"b"', "text/html")
        self.cache.put("/c.html", b"c", '"c"', "text/html")
        # Add 4th item — should evict /a.html
        self.cache.put("/d.html", b"d", '"d"', "text/html")
        self.assertIsNone(self.cache.get("/a.html"))
        self.assertIsNotNone(self.cache.get("/b.html"))
        self.assertIsNotNone(self.cache.get("/c.html"))
        self.assertIsNotNone(self.cache.get("/d.html"))

    def test_compute_etag(self):
        etag = StaticCache.compute_etag(b"hello")
        self.assertTrue(etag.startswith('"'))
        self.assertTrue(etag.endswith('"'))
        # Same content → same etag
        self.assertEqual(
            StaticCache.compute_etag(b"hello"),
            StaticCache.compute_etag(b"hello"),
        )
        # Different content → different etag
        self.assertNotEqual(
            StaticCache.compute_etag(b"hello"),
            StaticCache.compute_etag(b"world"),
        )

    def test_update_existing_entry(self):
        """Updating an existing key replaces the value."""
        self.cache.put("/test.html", b"v1", '"etag1"', "text/html")
        self.cache.put("/test.html", b"v2", '"etag2"', "text/html")
        result = self.cache.get("/test.html")
        self.assertEqual(result[0], b"v2")
        self.assertEqual(result[1], '"etag2"')


# ---------------------------------------------------------------------------
# TestResolveStaticPath
# ---------------------------------------------------------------------------

class TestResolveStaticPath(unittest.TestCase):
    """Tests for router.resolve_static_path."""

    def test_root_normalizes_to_index_html(self):
        result = resolve_static_path("/")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "index.html")

    def test_strips_query_strings(self):
        result = resolve_static_path("/styles.css?v=1")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "styles.css")

    def test_blocks_path_traversal(self):
        result = resolve_static_path("/../../../etc/passwd")
        self.assertIsNone(result)

    def test_blocks_traversal_via_encoded_dots(self):
        """URL-encoded traversal stays as literal filename inside public/."""
        result = resolve_static_path("/..%2F..%2Fetc/passwd")
        self.assertIsNotNone(result)
        self.assertIn(PUBLIC_DIR.resolve(), [result, *result.parents])

    def test_valid_file_returns_path(self):
        result = resolve_static_path("/index.html")
        self.assertIsNotNone(result)
        self.assertTrue(result.exists())

    def test_nonexistent_file_returns_path_but_not_found(self):
        """resolve_static_path returns a Path even for non-existent files
        (the caller checks .exists())."""
        result = resolve_static_path("/nonexistent.html")
        # The path is resolved but the file doesn't exist.
        self.assertIsNotNone(result)
        self.assertFalse(result.exists())


# ---------------------------------------------------------------------------
# TestMimeTypes
# ---------------------------------------------------------------------------

class TestMimeTypes(unittest.TestCase):
    """Tests for mime_types.get_mime_type."""

    def test_html(self):
        self.assertEqual(
            get_mime_type(Path("file.html")),
            "text/html; charset=utf-8",
        )

    def test_css(self):
        self.assertEqual(
            get_mime_type(Path("file.css")),
            "text/css; charset=utf-8",
        )

    def test_js(self):
        self.assertEqual(
            get_mime_type(Path("file.js")),
            "application/javascript; charset=utf-8",
        )

    def test_json(self):
        self.assertEqual(
            get_mime_type(Path("file.json")),
            "application/json; charset=utf-8",
        )

    def test_png(self):
        self.assertEqual(
            get_mime_type(Path("file.png")),
            "image/png",
        )

    def test_txt(self):
        self.assertEqual(
            get_mime_type(Path("file.txt")),
            "text/plain; charset=utf-8",
        )

    def test_unknown_extension(self):
        self.assertEqual(
            get_mime_type(Path("file.xyz")),
            "application/octet-stream",
        )

    def test_case_insensitive(self):
        self.assertEqual(
            get_mime_type(Path("file.HTML")),
            "text/html; charset=utf-8",
        )

    def test_no_extension(self):
        self.assertEqual(
            get_mime_type(Path("README")),
            "application/octet-stream",
        )


if __name__ == "__main__":
    unittest.main()
