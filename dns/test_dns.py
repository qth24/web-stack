"""Comprehensive unit tests for the DNS module.

Run from project root:
    python3 -m unittest dns.test_dns -v
"""

import json
import sys
import time
import unittest
from unittest.mock import patch

# Ensure the dns package is importable when running as a script.
if __name__ == "__main__" and __package__ is None:
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.dns_cache import CacheEntry, DNSCache
from dns.dns_resolver import (
    StaticResolver,
    is_valid_domain,
    is_valid_ipv4,
    normalize_domain,
)
from dns.dns_server import DNSRequestHandler
from dns.rate_limiter import RateLimiter

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SAMPLE_RECORDS = {
    "myweb.local": "127.0.0.1",
    "example.local": {"ip": "127.0.0.1", "ttl": 5},
    "api.local": {"ip": "127.0.0.1", "ttl": 8},
    "test.local": "192.168.1.5",
    "example.com": "104.20.23.154",
}

CLIENT_ADDR = ("192.168.1.100", 54321)


def _make_payload(domain: str) -> bytes:
    return json.dumps({"domain": domain}).encode("utf-8")


# ---------------------------------------------------------------------------
# TestDNSCache
# ---------------------------------------------------------------------------


class TestDNSCache(unittest.TestCase):
    """Tests for DNSCache: set/get roundtrip, cache hit, miss, expiry."""

    def setUp(self):
        self.cache = DNSCache()
        self.now = 1000000.0

    def test_set_get_roundtrip(self):
        entry = self.cache.set("example.local", "127.0.0.1", 60, now=self.now)
        self.assertEqual(entry.ip, "127.0.0.1")
        self.assertEqual(entry.ttl, 60)
        self.assertEqual(entry.expire_at, self.now + 60)

    def test_cache_hit(self):
        self.cache.set("example.local", "127.0.0.1", 60, now=self.now)
        entry, state = self.cache.get("example.local", now=self.now + 10)
        self.assertEqual(state, "HIT")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "127.0.0.1")

    def test_cache_miss(self):
        entry, state = self.cache.get("nonexistent.local", now=self.now)
        self.assertIsNone(entry)
        self.assertEqual(state, "MISS")

    def test_cache_expired(self):
        self.cache.set("example.local", "127.0.0.1", 10, now=self.now)
        entry, state = self.cache.get("example.local", now=self.now + 15)
        self.assertIsNone(entry)
        self.assertEqual(state, "EXPIRED")

    def test_cache_expired_entry_deleted(self):
        self.cache.set("example.local", "127.0.0.1", 10, now=self.now)
        self.cache.get("example.local", now=self.now + 15)
        # After expiry, the entry should be lazily deleted.
        entry2, state2 = self.cache.get("example.local", now=self.now + 20)
        self.assertIsNone(entry2)
        self.assertEqual(state2, "MISS")

    def test_cache_ttl_minimum_is_one(self):
        entry = self.cache.set("example.local", "127.0.0.1", -5, now=self.now)
        self.assertEqual(entry.ttl, 1)
        self.assertEqual(entry.expire_at, self.now + 1)

    def test_cache_overwrite_existing(self):
        self.cache.set("example.local", "127.0.0.1", 60, now=self.now)
        self.cache.set("example.local", "10.0.0.1", 30, now=self.now)
        entry, state = self.cache.get("example.local", now=self.now + 5)
        self.assertEqual(state, "HIT")
        self.assertEqual(entry.ip, "10.0.0.1")
        self.assertEqual(entry.ttl, 30)

    def test_cache_get_without_now_uses_time(self):
        self.cache.set("example.local", "127.0.0.1", 999999)
        entry, state = self.cache.get("example.local")
        self.assertEqual(state, "HIT")
        self.assertEqual(entry.ip, "127.0.0.1")


# ---------------------------------------------------------------------------
# TestStaticResolver
# ---------------------------------------------------------------------------


class TestStaticResolver(unittest.TestCase):
    """Tests for StaticResolver: valid lookup, NXDOMAIN, per-record TTL,
    default TTL, invalid records skipped."""

    def test_valid_lookup_string_record(self):
        resolver = StaticResolver({"example.local": "127.0.0.1"}, default_ttl=10)
        result = resolver.resolve("example.local")
        self.assertIsNotNone(result)
        ip, ttl = result
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(ttl, 10)

    def test_valid_lookup_dict_record_with_ttl(self):
        resolver = StaticResolver(
            {"example.local": {"ip": "10.0.0.1", "ttl": 30}},
            default_ttl=10,
        )
        result = resolver.resolve("example.local")
        self.assertIsNotNone(result)
        ip, ttl = result
        self.assertEqual(ip, "10.0.0.1")
        self.assertEqual(ttl, 30)

    def test_nxdomain_unknown_domain(self):
        resolver = StaticResolver({"example.local": "127.0.0.1"}, default_ttl=10)
        result = resolver.resolve("unknown.local")
        self.assertIsNone(result)

    def test_per_record_ttl_overrides_default(self):
        resolver = StaticResolver(
            {
                "a.local": {"ip": "1.1.1.1", "ttl": 5},
                "b.local": {"ip": "2.2.2.2", "ttl": 30},
            },
            default_ttl=10,
        )
        _, ttl_a = resolver.resolve("a.local")
        _, ttl_b = resolver.resolve("b.local")
        self.assertEqual(ttl_a, 5)
        self.assertEqual(ttl_b, 30)

    def test_default_ttl_applied_to_string_records(self):
        resolver = StaticResolver({"example.local": "127.0.0.1"}, default_ttl=25)
        _, ttl = resolver.resolve("example.local")
        self.assertEqual(ttl, 25)

    def test_invalid_ip_record_skipped(self):
        resolver = StaticResolver(
            {"bad.local": {"ip": "not-an-ip", "ttl": 10}},
            default_ttl=10,
        )
        self.assertIsNone(resolver.resolve("bad.local"))

    def test_invalid_domain_skipped(self):
        resolver = StaticResolver(
            {"-bad.local": "127.0.0.1"},
            default_ttl=10,
        )
        self.assertIsNone(resolver.resolve("-bad.local"))

    def test_non_dict_non_string_value_skipped(self):
        resolver = StaticResolver(
            {"weird.local": 12345},
            default_ttl=10,
        )
        self.assertIsNone(resolver.resolve("weird.local"))

    def test_domain_normalization_in_resolver(self):
        resolver = StaticResolver(
            {"Example.Local.": "127.0.0.1"},
            default_ttl=10,
        )
        result = resolver.resolve("example.local")
        self.assertIsNotNone(result)

    def test_empty_records(self):
        resolver = StaticResolver({}, default_ttl=10)
        self.assertIsNone(resolver.resolve("anything.local"))

    def test_ttl_minimum_is_one(self):
        resolver = StaticResolver(
            {"example.local": {"ip": "127.0.0.1", "ttl": -5}},
            default_ttl=10,
        )
        _, ttl = resolver.resolve("example.local")
        self.assertEqual(ttl, 1)

    def test_invalid_ttl_falls_back_to_default(self):
        resolver = StaticResolver(
            {"example.local": {"ip": "127.0.0.1", "ttl": "bad"}},
            default_ttl=15,
        )
        _, ttl = resolver.resolve("example.local")
        self.assertEqual(ttl, 15)


# ---------------------------------------------------------------------------
# TestNormalizeDomain
# ---------------------------------------------------------------------------


class TestNormalizeDomain(unittest.TestCase):
    """Tests for normalize_domain: strip whitespace, lowercase, trailing dot."""

    def test_strips_leading_whitespace(self):
        self.assertEqual(normalize_domain("  example.local"), "example.local")

    def test_strips_trailing_whitespace(self):
        self.assertEqual(normalize_domain("example.local  "), "example.local")

    def test_lowercases_domain(self):
        self.assertEqual(normalize_domain("EXAMPLE.LOCAL"), "example.local")

    def test_removes_trailing_dot(self):
        self.assertEqual(normalize_domain("example.local."), "example.local")

    def test_combined_operations(self):
        self.assertEqual(
            normalize_domain("  EXAMPLE.Local.  "),
            "example.local",
        )

    def test_no_change_for_already_normal(self):
        self.assertEqual(normalize_domain("example.local"), "example.local")

    def test_empty_string(self):
        self.assertEqual(normalize_domain(""), "")

    def test_whitespace_only(self):
        self.assertEqual(normalize_domain("   "), "")


# ---------------------------------------------------------------------------
# TestIsValidDomain
# ---------------------------------------------------------------------------


class TestIsValidDomain(unittest.TestCase):
    """Tests for is_valid_domain: valid and invalid domain formats."""

    # --- Valid domains ---

    def test_simple_domain(self):
        self.assertTrue(is_valid_domain("example.local"))

    def test_single_label(self):
        self.assertTrue(is_valid_domain("localhost"))

    def test_domain_with_hyphen(self):
        self.assertTrue(is_valid_domain("my-web.local"))

    def test_multi_level_domain(self):
        self.assertTrue(is_valid_domain("sub.example.local"))

    def test_numeric_labels(self):
        self.assertTrue(is_valid_domain("123.local"))

    # --- Invalid domains ---

    def test_empty_string(self):
        self.assertFalse(is_valid_domain(""))

    def test_too_long_domain(self):
        self.assertFalse(is_valid_domain("a" * 254))

    def test_empty_label(self):
        self.assertFalse(is_valid_domain("example..local"))

    def test_label_too_long(self):
        self.assertFalse(is_valid_domain("a" * 64 + ".local"))

    def test_leading_hyphen(self):
        self.assertFalse(is_valid_domain("-example.local"))

    def test_trailing_hyphen(self):
        self.assertFalse(is_valid_domain("example-.local"))

    def test_underscore_not_allowed(self):
        self.assertFalse(is_valid_domain("example_domain.local"))

    def test_space_not_allowed(self):
        self.assertFalse(is_valid_domain("example domain.local"))

    def test_special_chars_not_allowed(self):
        self.assertFalse(is_valid_domain("exam!ple.local"))


# ---------------------------------------------------------------------------
# TestDNSRequestHandler
# ---------------------------------------------------------------------------


class TestDNSRequestHandler(unittest.TestCase):
    """Tests for DNSRequestHandler: valid lookup, NXDOMAIN, malformed payload,
    invalid domain, rate limit rejection."""

    def setUp(self):
        self.cache = DNSCache()
        self.resolver = StaticResolver(SAMPLE_RECORDS, default_ttl=10)
        self.handler = DNSRequestHandler(
            cache=self.cache,
            resolver=self.resolver,
            rate_limiter=None,
        )
        self.now = 1000000.0

    def _handle(self, domain: str, now: float | None = None) -> dict:
        """Helper: build payload, call handle_packet with time mocked."""
        payload = _make_payload(domain)
        with patch("time.time", return_value=now or self.now):
            return self.handler.handle_packet(payload, CLIENT_ADDR)

    # --- Valid lookup ---

    def test_valid_lookup_returns_ok(self):
        resp = self._handle("myweb.local")
        self.assertEqual(resp["status"], "OK")
        self.assertEqual(resp["domain"], "myweb.local")
        self.assertEqual(resp["ip"], "127.0.0.1")
        self.assertIn("expire_at", resp)

    def test_valid_lookup_caches_result(self):
        self._handle("myweb.local")
        resp2 = self._handle("myweb.local")
        self.assertEqual(resp2["status"], "OK")
        # Second call should be a cache hit (same expire_at).

    def test_valid_lookup_with_per_record_ttl(self):
        resp = self._handle("example.local")
        self.assertEqual(resp["status"], "OK")
        self.assertEqual(resp["ip"], "127.0.0.1")

    # --- NXDOMAIN ---

    def test_nxdomain_for_unknown_domain(self):
        resp = self._handle("unknown.local")
        self.assertEqual(resp["status"], "NXDOMAIN")
        self.assertEqual(resp["domain"], "unknown.local")
        self.assertIsNone(resp["ip"])
        self.assertIn("message", resp)

    # --- Malformed payload ---

    def test_malformed_json_returns_bad_request(self):
        payload = b"not json at all"
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")
        self.assertIsNone(resp["domain"])
        self.assertIsNone(resp["ip"])

    def test_empty_payload_returns_bad_request(self):
        payload = b""
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")

    def test_non_object_json_returns_bad_request(self):
        payload = b'[1, 2, 3]'
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")

    def test_missing_domain_field_returns_bad_request(self):
        payload = json.dumps({"foo": "bar"}).encode("utf-8")
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")

    def test_non_string_domain_returns_bad_request(self):
        payload = json.dumps({"domain": 123}).encode("utf-8")
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")

    def test_empty_string_domain_returns_bad_request(self):
        payload = json.dumps({"domain": ""}).encode("utf-8")
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")

    def test_whitespace_only_domain_returns_bad_request(self):
        payload = json.dumps({"domain": "   "}).encode("utf-8")
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")

    def test_non_utf8_payload_returns_bad_request(self):
        payload = b"\xff\xfe\x00\x01"
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")

    # --- Invalid domain ---

    def test_invalid_domain_format_returns_bad_request(self):
        resp = self._handle("-invalid.local")
        self.assertEqual(resp["status"], "BAD_REQUEST")
        self.assertEqual(resp["message"], "Invalid domain format")

    # --- Rate limit ---

    def test_rate_limit_rejection(self):
        limiter = RateLimiter(max_queries=2, window_seconds=10)
        handler = DNSRequestHandler(
            cache=self.cache,
            resolver=self.resolver,
            rate_limiter=limiter,
        )
        # First two requests should succeed.
        for _ in range(2):
            payload = _make_payload("myweb.local")
            with patch("time.time", return_value=self.now):
                resp = handler.handle_packet(payload, CLIENT_ADDR)
            self.assertEqual(resp["status"], "OK")

        # Third request should be rate limited.
        payload = _make_payload("myweb.local")
        with patch("time.time", return_value=self.now):
            resp = handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "RATE_LIMITED")
        self.assertIsNone(resp["domain"])
        self.assertIsNone(resp["ip"])
        self.assertIn("retry_after", resp)

    # --- Packet too large ---

    def test_oversized_packet_returns_bad_request(self):
        handler = DNSRequestHandler(
            cache=self.cache,
            resolver=self.resolver,
            max_request_bytes=64,
        )
        payload = b'{"domain": "' + b"x" * 100 + b'"}'
        with patch("time.time", return_value=self.now):
            resp = handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], "BAD_REQUEST")
        self.assertIn("too large", resp["message"])


# ---------------------------------------------------------------------------
# TestRateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter(unittest.TestCase):
    """Tests for RateLimiter: within limit, over limit, per-IP isolation,
    retry_after, window expiry."""

    def test_allows_within_limit(self):
        limiter = RateLimiter(max_queries=3, window_seconds=10)
        for _ in range(3):
            self.assertTrue(limiter.is_allowed("1.2.3.4"))

    def test_blocks_over_limit(self):
        limiter = RateLimiter(max_queries=2, window_seconds=10)
        self.assertTrue(limiter.is_allowed("1.2.3.4"))
        self.assertTrue(limiter.is_allowed("1.2.3.4"))
        self.assertFalse(limiter.is_allowed("1.2.3.4"))

    def test_per_ip_isolation(self):
        limiter = RateLimiter(max_queries=1, window_seconds=10)
        self.assertTrue(limiter.is_allowed("1.1.1.1"))
        self.assertFalse(limiter.is_allowed("1.1.1.1"))
        # Different IP should still be allowed.
        self.assertTrue(limiter.is_allowed("2.2.2.2"))

    def test_retry_after_positive_when_blocked(self):
        limiter = RateLimiter(max_queries=1, window_seconds=10)
        limiter.is_allowed("1.2.3.4")
        retry = limiter.get_retry_after("1.2.3.4")
        self.assertGreater(retry, 0.0)

    def test_retry_after_zero_when_not_blocked(self):
        limiter = RateLimiter(max_queries=5, window_seconds=10)
        retry = limiter.get_retry_after("1.2.3.4")
        self.assertEqual(retry, 0.0)

    def test_window_expiry_allows_again(self):
        limiter = RateLimiter(max_queries=1, window_seconds=10)
        now = 1000000.0

        with patch("time.time", return_value=now):
            self.assertTrue(limiter.is_allowed("1.2.3.4"))
            self.assertFalse(limiter.is_allowed("1.2.3.4"))

        # After window expires, should be allowed again.
        with patch("time.time", return_value=now + 11):
            self.assertTrue(limiter.is_allowed("1.2.3.4"))

    def test_max_queries_minimum_is_one(self):
        limiter = RateLimiter(max_queries=-5, window_seconds=10)
        self.assertEqual(limiter.max_queries, 1)

    def test_window_seconds_minimum(self):
        limiter = RateLimiter(max_queries=5, window_seconds=-1)
        self.assertGreaterEqual(limiter.window_seconds, 0.1)


# ---------------------------------------------------------------------------
# TestIsValidIPv4
# ---------------------------------------------------------------------------


class TestIsValidIPv4(unittest.TestCase):
    """Tests for is_valid_ipv4 helper."""

    def test_valid_ipv4(self):
        self.assertTrue(is_valid_ipv4("127.0.0.1"))
        self.assertTrue(is_valid_ipv4("192.168.1.5"))
        self.assertTrue(is_valid_ipv4("104.20.23.154"))

    def test_invalid_ipv4(self):
        self.assertFalse(is_valid_ipv4("not-an-ip"))
        self.assertFalse(is_valid_ipv4("256.256.256.256"))
        self.assertFalse(is_valid_ipv4(""))
        self.assertFalse(is_valid_ipv4("abc.def.ghi.jkl"))


if __name__ == "__main__":
    unittest.main()
