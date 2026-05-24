"""Unit tests for the HTTPCache module."""

import tempfile
import time
import unittest
from pathlib import Path

from browser.core.http_cache import HTTPCache, _compute_fresh_until


class TestCacheFreshness(unittest.TestCase):
    def test_max_age_fresh_until_is_future(self):
        fu = _compute_fresh_until({"Cache-Control": "max-age=3600"})
        self.assertIsNotNone(fu)
        self.assertGreater(fu, time.time())

    def test_no_cache_returns_none(self):
        fu = _compute_fresh_until({"Cache-Control": "no-cache"})
        self.assertIsNone(fu)

    def test_no_cache_control_returns_none(self):
        fu = _compute_fresh_until({})
        self.assertIsNone(fu)

    def test_expires_header_parsed(self):
        from email.utils import formatdate
        future = formatdate(time.time() + 7200, usegmt=True)
        fu = _compute_fresh_until({"Expires": future})
        self.assertIsNotNone(fu)
        self.assertGreater(fu, time.time())


class TestHTTPCacheStoreAndLookup(unittest.TestCase):
    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.cache = HTTPCache(self._tmpdir / "cache", max_mb=1)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_cache_fresh_200_and_lookup_returns_entry(self):
        body = b"<html>hello</html>"
        entry = self.cache.store(
            "http", "example.local", 80, "/page",
            200, "OK",
            {"Content-Type": "text/html", "Cache-Control": "max-age=3600", "ETag": '"abc"'},
            body,
        )
        self.assertIsNotNone(entry)
        self.assertTrue(entry.is_fresh)

        cached = self.cache.lookup("http", "example.local", 80, "/page")
        self.assertIsNotNone(cached)
        self.assertEqual(cached.body_bytes, body)
        self.assertEqual(cached.etag, '"abc"')

    def test_no_store_bypasses_cache(self):
        entry = self.cache.store(
            "http", "example.local", 80, "/nostore",
            200, "OK",
            {"Cache-Control": "no-store"},
            b"should not store",
        )
        self.assertIsNone(entry)
        cached = self.cache.lookup("http", "example.local", 80, "/nostore")
        self.assertIsNone(cached)

    def test_non_200_not_cached(self):
        entry = self.cache.store(
            "http", "example.local", 80, "/404",
            404, "Not Found",
            {"Cache-Control": "max-age=3600"},
            b"not found",
        )
        self.assertIsNone(entry)

    def test_no_cacheability_headers_skips_caching(self):
        entry = self.cache.store(
            "http", "example.local", 80, "/noinfo",
            200, "OK",
            {"Content-Type": "text/plain"},
            b"no cache info",
        )
        self.assertIsNone(entry)

    def test_cache_with_only_etag_is_stale_immediately(self):
        entry = self.cache.store(
            "http", "example.local", 80, "/etagonly",
            200, "OK",
            {"Content-Type": "text/html", "ETag": '"xyz"'},
            b"etag only body",
        )
        self.assertIsNotNone(entry)
        self.assertIsNone(entry.fresh_until)
        self.assertTrue(entry.is_stale())
        self.assertTrue(entry.can_revalidate())

    def test_cache_with_only_last_modified_is_stale(self):
        from email.utils import formatdate
        past = formatdate(time.time() - 100, usegmt=True)
        entry = self.cache.store(
            "http", "example.local", 80, "/lm",
            200, "OK",
            {"Content-Type": "text/html", "Last-Modified": past},
            b"lm body",
        )
        self.assertIsNotNone(entry)
        self.assertIsNone(entry.fresh_until)
        self.assertTrue(entry.is_stale())

    def test_fresh_entry_not_revalidated(self):
        self.cache.store(
            "http", "example.local", 80, "/fresh",
            200, "OK",
            {"Cache-Control": "max-age=3600", "ETag": '"etag1"'},
            b"fresh body",
        )
        cached = self.cache.lookup("http", "example.local", 80, "/fresh")
        self.assertIsNotNone(cached)
        self.assertTrue(cached.is_fresh)

    def test_lru_eviction_by_size(self):
        small_cache = HTTPCache(self._tmpdir / "small_cache", max_mb=1, max_entry_mb=0)
        body = b"x" * 1024
        entry = small_cache.store(
            "http", "example.local", 80, "/page",
            200, "OK",
            {"Cache-Control": "max-age=3600", "ETag": '"abc"'},
            body,
        )
        self.assertIsNone(entry)

    def test_clear_removes_all_entries(self):
        self.cache.store(
            "http", "example.local", 80, "/a",
            200, "OK",
            {"Cache-Control": "max-age=3600", "ETag": '"a"'},
            b"body a",
        )
        self.cache.store(
            "http", "example.local", 80, "/b",
            200, "OK",
            {"Cache-Control": "max-age=3600", "ETag": '"b"'},
            b"body b",
        )
        self.assertEqual(self.cache.entry_count(), 2)
        self.cache.clear()
        self.assertEqual(self.cache.entry_count(), 0)

    def test_empty_entry_count_is_zero(self):
        self.assertEqual(self.cache.entry_count(), 0)
        self.assertEqual(self.cache.total_size_bytes(), 0)


if __name__ == "__main__":
    unittest.main()
