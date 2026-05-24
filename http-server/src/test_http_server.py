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
    create_text_response,
    create_json_response,
)
from security import build_security_headers, BASELINE_HEADERS, waf_inspect
from static_cache import StaticCache, static_cache
from mime_types import get_mime_type, MIME_TYPES
from proxy import match_proxy_route, ProxyRoundRobin, forward_request, _proxy_error
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
        """Non-UTF8 body bytes are preserved as-is in body_bytes.
        Headers with high-byte chars parse via ISO-8859-1."""
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" + b"\xff\xfe\x00"
        result = parse_request(raw)
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["body"], "\ufffd\ufffd\x00")
        self.assertEqual(result["body_bytes"], b"\xff\xfe\x00")

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
        req = {"method": "GET", "target": "/", "headers": {}, "body": "", "scheme": "http"}
        resp = handle_request(req)
        status_line, _, body = self._parse_response(resp)
        self.assertIn("200", status_line)
        self.assertTrue(len(body) > 0)

    def test_get_health_200_json(self):
        req = {"method": "GET", "target": "/health", "headers": {}, "body": "", "scheme": "http"}
        resp = handle_request(req)
        status_line, headers, body = self._parse_response(resp)
        self.assertIn("200", status_line)
        self.assertIn("application/json", headers["Content-Type"])
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "ok")

    def test_post_root_405(self):
        req = {"method": "POST", "target": "/", "headers": {}, "body": "", "scheme": "http"}
        resp = handle_request(req)
        status_line, _, body = self._parse_response(resp)
        self.assertIn("405", status_line)

    def test_get_nonexistent_404(self):
        req = {"method": "GET", "target": "/nonexistent", "headers": {}, "body": "", "scheme": "http"}
        resp = handle_request(req)
        status_line, _, body = self._parse_response(resp)
        self.assertIn("404", status_line)

    def test_delete_root_405(self):
        req = {"method": "DELETE", "target": "/", "headers": {}, "body": "", "scheme": "http"}
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
    """Verify all responses include baseline security headers."""

    def _parse_response(self, response_bytes):
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        headers = {}
        for line in lines[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
        return headers

    def _assert_baseline_headers(self, headers):
        for key, expected_value in BASELINE_HEADERS.items():
            self.assertEqual(
                headers.get(key),
                expected_value,
                f"Missing or wrong security header: {key}",
            )

    def test_static_file_has_baseline_headers(self):
        from router import serve_static_file
        resp = serve_static_file("/")
        headers = self._parse_response(resp)
        self._assert_baseline_headers(headers)

    def test_static_file_has_csp_when_enabled(self):
        from router import serve_static_file
        from config import ENABLE_CSP, CSP_POLICY
        resp = serve_static_file("/")
        headers = self._parse_response(resp)
        if ENABLE_CSP:
            self.assertIn("Content-Security-Policy", headers)
            self.assertEqual(headers["Content-Security-Policy"], CSP_POLICY)
        else:
            self.assertNotIn("Content-Security-Policy", headers)

    def test_health_has_baseline_headers(self):
        req = {"method": "GET", "target": "/health", "headers": {}, "body": "", "scheme": "http"}
        resp = handle_request(req)
        headers = self._parse_response(resp)
        self._assert_baseline_headers(headers)

    def test_404_has_baseline_headers(self):
        req = {"method": "GET", "target": "/nonexistent", "headers": {}, "body": "", "scheme": "http"}
        resp = handle_request(req)
        headers = self._parse_response(resp)
        self._assert_baseline_headers(headers)

    def test_405_has_baseline_headers(self):
        req = {"method": "POST", "target": "/", "headers": {}, "body": "", "scheme": "http"}
        resp = handle_request(req)
        headers = self._parse_response(resp)
        self._assert_baseline_headers(headers)

    def test_hsts_absent_on_http(self):
        resp = serve_static_file("/", scheme="http")
        headers = self._parse_response(resp)
        self.assertNotIn("Strict-Transport-Security", headers)

    def test_hsts_present_on_https_when_enabled(self):
        from router import serve_static_file
        from config import ENABLE_HSTS, HSTS_MAX_AGE, HSTS_INCLUDE_SUBDOMAINS
        resp = serve_static_file("/", scheme="https")
        headers = self._parse_response(resp)
        if ENABLE_HSTS:
            self.assertIn("Strict-Transport-Security", headers)
            sts = headers["Strict-Transport-Security"]
            self.assertIn(f"max-age={HSTS_MAX_AGE}", sts)
            if HSTS_INCLUDE_SUBDOMAINS:
                self.assertIn("includeSubDomains", sts)
        else:
            self.assertNotIn("Strict-Transport-Security", headers)


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


# ---------------------------------------------------------------------------
# TestWAF
# ---------------------------------------------------------------------------

class TestWAF(unittest.TestCase):
    """Tests for the basic WAF request inspection."""

    def _make_req(self, target, headers=None):
        req = {"method": "GET", "target": target, "headers": headers or {}, "body": "", "scheme": "http"}
        return req

    def _parse_response(self, response_bytes):
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        status_line = lines[0]
        return status_line, body

    def test_block_raw_traversal(self):
        req = self._make_req("/../../../etc/passwd")
        resp = handle_request(req)
        status_line, body = self._parse_response(resp)
        self.assertIn("403", status_line)

    def test_block_percent_decoded_traversal(self):
        req = self._make_req("/..%2F..%2F..%2Fetc/passwd")
        resp = handle_request(req)
        status_line, body = self._parse_response(resp)
        self.assertIn("403", status_line)

    def test_block_dot_git(self):
        req = self._make_req("/.git/config")
        resp = handle_request(req)
        status_line, _ = self._parse_response(resp)
        self.assertIn("403", status_line)

    def test_block_dot_env(self):
        req = self._make_req("/.env")
        resp = handle_request(req)
        status_line, _ = self._parse_response(resp)
        self.assertIn("403", status_line)

    def test_block_etc_passwd(self):
        req = self._make_req("/etc/passwd")
        resp = handle_request(req)
        status_line, _ = self._parse_response(resp)
        self.assertIn("403", status_line)

    def test_block_script_injection(self):
        req = self._make_req("/page?q=<script>alert(1)</script>")
        resp = handle_request(req)
        status_line, _ = self._parse_response(resp)
        self.assertIn("403", status_line)

    def test_allow_normal_routes(self):
        for target in ["/", "/health", "/styles.css?v=1"]:
            with self.subTest(target=target):
                req = self._make_req(target)
                resp = handle_request(req)
                status_line, _ = self._parse_response(resp)
                self.assertNotIn("403", status_line)

    def test_safe_post_returns_405_not_403(self):
        req = {"method": "POST", "target": "/", "headers": {}, "body": "", "scheme": "http"}
        resp = handle_request(req)
        status_line, _ = self._parse_response(resp)
        self.assertIn("405", status_line)

    def test_404_has_security_headers_via_waf(self):
        from security import BASELINE_HEADERS
        head, _, _ = handle_request(self._make_req("/nonexistent")).partition(b"\r\n\r\n")
        headers_text = head.decode("utf-8")
        for key, val in BASELINE_HEADERS.items():
            self.assertIn(f"{key}: {val}", headers_text)

    def test_403_has_security_headers(self):
        from security import BASELINE_HEADERS
        resp = handle_request(self._make_req("/.git/config"))
        head, _, _ = resp.partition(b"\r\n\r\n")
        headers_text = head.decode("utf-8")
        for key, val in BASELINE_HEADERS.items():
            self.assertIn(f"{key}: {val}", headers_text)

    def test_block_via_x_original_url_header(self):
        req = self._make_req("/safe", headers={"x-original-url": "/.git/config"})
        resp = handle_request(req)
        status_line, _ = self._parse_response(resp)
        self.assertIn("403", status_line)

    def test_block_via_x_rewrite_url_header(self):
        req = self._make_req("/safe", headers={"x-rewrite-url": "/../../../etc/passwd"})
        resp = handle_request(req)
        status_line, _ = self._parse_response(resp)
        self.assertIn("403", status_line)

    def test_null_byte_blocked(self):
        req = self._make_req("/page\0hidden")
        resp = handle_request(req)
        status_line, _ = self._parse_response(resp)
        self.assertIn("403", status_line)


# ---------------------------------------------------------------------------
# TestSecurityConfig
# ---------------------------------------------------------------------------

class TestSecurityConfig(unittest.TestCase):
    """Tests for CSP/HSTS/WAF config toggles."""

    def _parse_response(self, response_bytes):
        head, _, body = response_bytes.partition(b"\r\n\r\n")
        lines = head.decode("utf-8").split("\r\n")
        headers = {}
        for line in lines[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
        return headers

    def test_200_has_csp_when_enabled(self):
        resp = serve_static_file("/")
        headers = self._parse_response(resp)
        from config import ENABLE_CSP
        if ENABLE_CSP:
            self.assertIn("Content-Security-Policy", headers)

    def test_200_has_hsts_only_on_https_and_enabled(self):
        from config import ENABLE_HSTS
        resp_http = serve_static_file("/", scheme="http")
        headers_http = self._parse_response(resp_http)
        self.assertNotIn("Strict-Transport-Security", headers_http)

        resp_https = serve_static_file("/", scheme="https")
        headers_https = self._parse_response(resp_https)
        if ENABLE_HSTS:
            self.assertIn("Strict-Transport-Security", headers_https)
            sts = headers_https["Strict-Transport-Security"]
            from config import HSTS_MAX_AGE, HSTS_INCLUDE_SUBDOMAINS
            self.assertIn(f"max-age={HSTS_MAX_AGE}", sts)
            if HSTS_INCLUDE_SUBDOMAINS:
                self.assertIn("includeSubDomains", sts)

    def test_304_has_baseline_headers(self):
        from security import BASELINE_HEADERS
        resp1 = serve_static_file("/index.html")
        head1, _, _ = resp1.partition(b"\r\n\r\n")
        lines = head1.decode("utf-8").split("\r\n")
        etag = None
        for line in lines[1:]:
            if line.startswith("ETag: "):
                etag = line.split(": ", 1)[1]
                break
        self.assertIsNotNone(etag)

        resp2 = serve_static_file("/index.html", request_headers={"if-none-match": etag})
        h2 = self._parse_response(resp2)
        for key, val in BASELINE_HEADERS.items():
            self.assertEqual(h2.get(key), val, f"304 missing header: {key}")

    def test_400_and_500_have_baseline_headers(self):
        from security import BASELINE_HEADERS
        from http_response import build_response, STATUS_TEXT
        scheme = "http"
        sh = build_security_headers(scheme)
        sh["Content-Type"] = "text/plain; charset=utf-8"
        resp400 = build_response(400, headers=sh, body="bad")
        resp500 = build_response(500, headers=sh, body="err")
        for resp in (resp400, resp500):
            head, _, _ = resp.partition(b"\r\n\r\n")
            htext = head.decode("utf-8")
            for key, val in BASELINE_HEADERS.items():
                self.assertIn(f"{key}: {val}", htext)


# ---------------------------------------------------------------------------
# TestProxyRouteMatching
# ---------------------------------------------------------------------------

class TestProxyRouteMatching(unittest.TestCase):
    """Tests for proxy route matching logic."""

    def setUp(self):
        self.routes = [
            {
                "name": "api",
                "hosts": ["api.local"],
                "path_prefixes": ["/api"],
                "upstreams": [{"scheme": "http", "host": "127.0.0.1", "port": 9001}],
            },
            {
                "name": "web",
                "hosts": ["myweb.local"],
                "path_prefixes": None,
                "upstreams": [{"scheme": "http", "host": "127.0.0.1", "port": 9002}],
            },
            {
                "name": "catchall",
                "hosts": None,
                "path_prefixes": ["/proxy"],
                "upstreams": [{"scheme": "http", "host": "127.0.0.1", "port": 9003}],
            },
        ]

    def test_match_by_host_only(self):
        req = {"method": "GET", "target": "/anything", "headers": {"host": "myweb.local"}}
        idx = match_proxy_route(req, self.routes)
        self.assertEqual(idx, 1)

    def test_match_by_path_only(self):
        req = {"method": "GET", "target": "/proxy/data", "headers": {"host": "unknown.local"}}
        idx = match_proxy_route(req, self.routes)
        self.assertEqual(idx, 2)

    def test_match_by_host_and_path(self):
        req = {"method": "GET", "target": "/api/v1/users", "headers": {"host": "api.local"}}
        idx = match_proxy_route(req, self.routes)
        self.assertEqual(idx, 0)

    def test_first_match_wins(self):
        routes = [
            {
                "name": "first",
                "hosts": ["shared.local"],
                "path_prefixes": ["/api"],
                "upstreams": [],
            },
            {
                "name": "second",
                "hosts": ["shared.local"],
                "path_prefixes": ["/api"],
                "upstreams": [],
            },
        ]
        req = {"method": "GET", "target": "/api/test", "headers": {"host": "shared.local"}}
        idx = match_proxy_route(req, routes)
        self.assertEqual(idx, 0)

    def test_no_match_returns_none(self):
        req = {"method": "GET", "target": "/other", "headers": {"host": "other.local"}}
        idx = match_proxy_route(req, self.routes)
        self.assertIsNone(idx)

    def test_unmatched_falls_back_to_local(self):
        from router import handle_request
        req = {"method": "GET", "target": "/", "headers": {"host": "localhost"}, "body": "", "body_bytes": b"", "scheme": "http"}
        resp = handle_request(req)
        self.assertIn(b"200", resp[:100])

    def test_host_match_ignores_port(self):
        req = {"method": "GET", "target": "/", "headers": {"host": "myweb.local:8000"}}
        idx = match_proxy_route(req, self.routes)
        self.assertEqual(idx, 1)

    def test_path_prefix_match_strips_query(self):
        req = {"method": "GET", "target": "/proxy/data?q=1", "headers": {"host": "any.local"}}
        idx = match_proxy_route(req, self.routes)
        self.assertEqual(idx, 2)


# ---------------------------------------------------------------------------
# TestProxyForwarding (integration with fake upstream)
# ---------------------------------------------------------------------------

class TestProxyForwarding(unittest.TestCase):
    """Integration tests with a simple TCP echo/relay upstream."""

    def setUp(self):
        self._routes = [
            {
                "name": "test_upstream",
                "hosts": None,
                "path_prefixes": ["/proxy"],
                "upstreams": [
                    {"scheme": "http", "host": "127.0.0.1", "port": 19999},
                ],
            }
        ]

    def test_proxy_hop_by_hop_headers_stripped(self):
        """Client hop-by-hop headers (Transfer-Encoding, Keep-Alive) are stripped.
        Proxy adds its own Connection: close."""
        import threading
        import socket as sock_mod

        received_upstream = {}

        def fake_upstream():
            srv = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            srv.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 19999))
            srv.listen(1)
            srv.settimeout(2.0)
            try:
                conn, _ = srv.accept()
                with conn:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    received_upstream["raw"] = data
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            finally:
                srv.close()

        t = threading.Thread(target=fake_upstream, daemon=True)
        t.start()
        import time
        time.sleep(0.05)

        req = {
            "method": "GET", "target": "/proxy/test",
            "headers": {
                "host": "test.local",
                "keep-alive": "timeout=5",
                "transfer-encoding": "identity",
            },
            "body": "", "body_bytes": b"", "scheme": "http",
        }
        rr = ProxyRoundRobin()
        resp = forward_request(req, self._routes, 0, "127.0.0.1", rr)
        t.join(timeout=2)
        self.assertIn(b"200", resp[:100])

        raw = received_upstream.get("raw", b"")
        raw_str = raw.decode("iso-8859-1")
        self.assertNotIn("keep-alive", raw_str.lower())
        self.assertNotIn("transfer-encoding", raw_str.lower())
        self.assertIn("x-forwarded-for", raw_str.lower())
        self.assertIn("x-forwarded-proto", raw_str.lower())
        self.assertIn("x-forwarded-host", raw_str.lower())

    def test_proxy_method_and_path_preserved(self):
        import threading
        import socket as sock_mod

        received = {}

        def fake_upstream():
            srv = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            srv.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 19999))
            srv.listen(1)
            srv.settimeout(2.0)
            try:
                conn, _ = srv.accept()
                with conn:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    received["request"] = data
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            finally:
                srv.close()

        t = threading.Thread(target=fake_upstream, daemon=True)
        t.start()
        import time
        time.sleep(0.05)

        req = {
            "method": "POST", "target": "/proxy/submit?foo=bar",
            "headers": {"host": "test.local", "content-type": "text/plain"},
            "body": "hello body", "body_bytes": b"hello body", "scheme": "http",
        }
        rr = ProxyRoundRobin()
        resp = forward_request(req, self._routes, 0, "127.0.0.1", rr)
        t.join(timeout=2)
        self.assertIn(b"200", resp)

        raw = received.get("request", b"")
        raw_str = raw.decode("iso-8859-1")
        self.assertIn("POST /proxy/submit?foo=bar", raw_str)
        self.assertIn("hello body", raw_str)

    def test_proxy_binary_body_preserved(self):
        import threading
        import socket as sock_mod
        import hashlib

        binary_body = bytes(range(256))
        received = {}

        def fake_upstream():
            srv = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            srv.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 19999))
            srv.listen(1)
            srv.settimeout(2.0)
            try:
                conn, _ = srv.accept()
                with conn:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    received["raw"] = data
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            finally:
                srv.close()

        t = threading.Thread(target=fake_upstream, daemon=True)
        t.start()
        import time
        time.sleep(0.05)

        req = {
            "method": "POST", "target": "/proxy/bin",
            "headers": {"host": "test.local"},
            "body": "", "body_bytes": binary_body, "scheme": "http",
        }
        rr = ProxyRoundRobin()
        forward_request(req, self._routes, 0, "127.0.0.1", rr)
        t.join(timeout=2)

        raw = received.get("raw", b"")
        self.assertIn(binary_body, raw)
        self.assertEqual(len(raw), len(binary_body) + raw.index(binary_body))


# ---------------------------------------------------------------------------
# TestProxyRoundRobin
# ---------------------------------------------------------------------------

class TestProxyRoundRobin(unittest.TestCase):
    def test_round_robin_alternates(self):
        from proxy import ProxyRoundRobin
        rr = ProxyRoundRobin()
        results = [rr.next_index(0, 3) for _ in range(6)]
        self.assertEqual(results, [0, 1, 2, 0, 1, 2])

    def test_separate_routes_independent(self):
        from proxy import ProxyRoundRobin
        rr = ProxyRoundRobin()
        a = rr.next_index(0, 2)
        b = rr.next_index(1, 2)
        self.assertEqual(a, 0)
        self.assertEqual(b, 0)


# ---------------------------------------------------------------------------
# TestChunkedTransferDetection
# ---------------------------------------------------------------------------

class TestChunkedTransferDetection(unittest.TestCase):
    def test_chunked_returns_501(self):
        from server import _has_chunked_transfer
        req = {"headers": {"transfer-encoding": "chunked"}}
        self.assertTrue(_has_chunked_transfer(req))

        req2 = {"headers": {"transfer-encoding": "identity"}}
        self.assertFalse(_has_chunked_transfer(req2))

        req3 = {"headers": {}}
        self.assertFalse(_has_chunked_transfer(req3))


# ---------------------------------------------------------------------------
# TestProxyErrorCodes
# ---------------------------------------------------------------------------

class TestProxyErrorCodes(unittest.TestCase):
    def test_502_bad_gateway(self):
        from proxy import _proxy_error
        resp = _proxy_error(502, "Bad Gateway")
        self.assertIn(b"502", resp[:100])

    def test_504_gateway_timeout(self):
        from proxy import _proxy_error
        resp = _proxy_error(504, "Gateway Timeout")
        self.assertIn(b"504", resp[:100])

    def test_upstream_connection_refused_returns_502(self):
        from proxy import forward_request, ProxyRoundRobin
        routes = [{
            "name": "bad",
            "hosts": None,
            "upstreams": [{"scheme": "http", "host": "127.0.0.1", "port": 65535}],
        }]
        req = {
            "method": "GET", "target": "/",
            "headers": {"host": "test.local"},
            "body": "", "body_bytes": b"", "scheme": "http",
        }
        rr = ProxyRoundRobin()
        resp = forward_request(req, routes, 0, "127.0.0.1", rr)
        self.assertIn(b"502", resp[:100])


# ---------------------------------------------------------------------------
# TestProxyRequestBodyBytes
# ---------------------------------------------------------------------------

class TestProxyRequestBodyBytes(unittest.TestCase):
    def test_parse_request_preserves_body_bytes(self):
        from http_parser import parse_request
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody bytes"
        req = parse_request(raw)
        self.assertEqual(req["body"], "body bytes")
        self.assertEqual(req["body_bytes"], b"body bytes")

    def test_parse_request_binary_body_bytes(self):
        from http_parser import parse_request
        raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n" + b"\x00\x01\x02\x03"
        req = parse_request(raw)
        self.assertEqual(req["body_bytes"], b"\x00\x01\x02\x03")
        self.assertEqual(len(req["body_bytes"]), 4)

    def test_full_binary_range_in_body(self):
        from http_parser import parse_request
        binary = bytes(range(256))
        raw = b"POST /bin HTTP/1.1\r\nHost: example.com\r\nContent-Length: 256\r\n\r\n" + binary
        req = parse_request(raw)
        self.assertEqual(req["body_bytes"], binary)
        self.assertEqual(len(req["body_bytes"]), 256)


if __name__ == "__main__":
    unittest.main()
