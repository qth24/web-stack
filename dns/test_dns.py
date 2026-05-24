"""Comprehensive unit tests for the DNS module.

Run from project root:
    python3 -m unittest dns.test_dns -v
"""

import json
import socket
import sys
import threading
import unittest
from unittest.mock import patch

# Ensure the dns package is importable when running as a script.
if __name__ == "__main__" and __package__ is None:
    import os

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.dns_cache import DNSCache
from dns.dns_resolver import (
    HybridResolver,
    StaticResolver,
    SystemForwardingResolver,
    create_resolver,
    is_valid_domain,
    is_valid_ipv4,
    normalize_domain,
)
from dns.dns_server import DNSRequestHandler
from dns.protocol import (
    PROTOCOL_VERSION,
    QTYPE_A,
    RESOLVE_OPERATION,
    STATUS_BAD_REQUEST,
    STATUS_ERROR,
    STATUS_NXDOMAIN,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNSUPPORTED_QTYPE,
    STATUS_UNSUPPORTED_VERSION,
    ProtocolError,
    build_success_response,
    decode_request,
    encode_response,
)
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


def _make_request_data(domain: str = "example.local", request_id: str = "req-1", **overrides) -> dict:
    data = {
        "version": PROTOCOL_VERSION,
        "id": request_id,
        "op": RESOLVE_OPERATION,
        "domain": domain,
        "qtype": QTYPE_A,
    }
    data.update(overrides)
    return data


def _make_payload(domain: str = "example.local", request_id: str = "req-1", **overrides) -> bytes:
    return json.dumps(_make_request_data(domain=domain, request_id=request_id, **overrides)).encode("utf-8")


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
# TestForwardingResolvers
# ---------------------------------------------------------------------------


class _FakeForwardingResolver:
    def __init__(self, result=None, side_effect=None):
        self.result = result
        self.side_effect = side_effect
        self.calls = []

    def resolve(self, domain: str):
        self.calls.append(domain)
        if self.side_effect is not None:
            raise self.side_effect
        return self.result


class TestForwardingResolvers(unittest.TestCase):
    def test_system_forwarding_resolver_returns_first_ipv4_and_fixed_ttl(self):
        resolver = SystemForwardingResolver(ttl_seconds=45)
        with patch(
            "dns.dns_resolver.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 0)),
            ],
        ):
            self.assertEqual(resolver.resolve("example.com"), ("93.184.216.34", 45))

    def test_system_forwarding_resolver_returns_none_on_gaierror(self):
        resolver = SystemForwardingResolver(ttl_seconds=45)
        with patch("dns.dns_resolver.socket.getaddrinfo", side_effect=socket.gaierror):
            self.assertIsNone(resolver.resolve("missing.example"))

    def test_hybrid_resolver_prefers_static_records(self):
        static_resolver = StaticResolver({"example.local": {"ip": "127.0.0.1", "ttl": 11}}, default_ttl=10)
        forwarding_resolver = _FakeForwardingResolver(side_effect=AssertionError("forwarder should not be called"))
        resolver = HybridResolver(static_resolver, forwarding_resolver)
        self.assertEqual(resolver.resolve("example.local"), ("127.0.0.1", 11))

    def test_hybrid_resolver_falls_back_to_forwarding(self):
        static_resolver = StaticResolver({}, default_ttl=10)
        forwarding_resolver = _FakeForwardingResolver(result=("93.184.216.34", 30))
        resolver = HybridResolver(static_resolver, forwarding_resolver)
        self.assertEqual(resolver.resolve("example.com"), ("93.184.216.34", 30))
        self.assertEqual(forwarding_resolver.calls, ["example.com"])

    def test_create_resolver_uses_expected_mode(self):
        self.assertIsInstance(
            create_resolver("static", SAMPLE_RECORDS, default_ttl=10, forward_ttl_seconds=20),
            StaticResolver,
        )
        self.assertIsInstance(
            create_resolver("forward", SAMPLE_RECORDS, default_ttl=10, forward_ttl_seconds=20),
            SystemForwardingResolver,
        )
        self.assertIsInstance(
            create_resolver("hybrid", SAMPLE_RECORDS, default_ttl=10, forward_ttl_seconds=20),
            HybridResolver,
        )

    def test_create_resolver_rejects_invalid_mode(self):
        with self.assertRaises(ValueError):
            create_resolver("weird", SAMPLE_RECORDS, default_ttl=10, forward_ttl_seconds=20)


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
# TestProtocol
# ---------------------------------------------------------------------------


class TestProtocol(unittest.TestCase):
    """Tests for UDP JSON v1 request decoding and response builders."""

    def test_decode_request_roundtrip(self):
        payload = _make_payload("Example.Local.", request_id="req-42")
        query = decode_request(payload)
        self.assertEqual(query.request_id, "req-42")
        self.assertEqual(query.domain, "example.local")
        self.assertEqual(query.qtype, QTYPE_A)
        self.assertEqual(query.version, PROTOCOL_VERSION)
        self.assertEqual(query.op, RESOLVE_OPERATION)

    def test_missing_id_is_bad_request(self):
        payload = json.dumps(_make_request_data(id=None)).encode("utf-8")
        with self.assertRaises(ProtocolError) as ctx:
            decode_request(payload)
        self.assertEqual(ctx.exception.status, STATUS_BAD_REQUEST)
        self.assertIn("id", str(ctx.exception))

    def test_unsupported_version(self):
        payload = _make_payload(version="v2")
        with self.assertRaises(ProtocolError) as ctx:
            decode_request(payload)
        self.assertEqual(ctx.exception.status, STATUS_UNSUPPORTED_VERSION)

    def test_wrong_operation_is_bad_request(self):
        payload = _make_payload(op="lookup")
        with self.assertRaises(ProtocolError) as ctx:
            decode_request(payload)
        self.assertEqual(ctx.exception.status, STATUS_BAD_REQUEST)
        self.assertIn("op", str(ctx.exception))

    def test_unsupported_qtype(self):
        payload = _make_payload(qtype="AAAA")
        with self.assertRaises(ProtocolError) as ctx:
            decode_request(payload)
        self.assertEqual(ctx.exception.status, STATUS_UNSUPPORTED_QTYPE)

    def test_build_success_response_contains_ttl(self):
        query = decode_request(_make_payload("example.local", request_id="req-ok"))
        response = build_success_response(query, "127.0.0.1", 60)
        self.assertEqual(response["version"], PROTOCOL_VERSION)
        self.assertEqual(response["id"], "req-ok")
        self.assertEqual(response["status"], STATUS_OK)
        self.assertEqual(response["ttl"], 60)


# ---------------------------------------------------------------------------
# TestDNSRequestHandler
# ---------------------------------------------------------------------------


class TestDNSRequestHandler(unittest.TestCase):
    """Tests for DNSRequestHandler: valid lookup, NXDOMAIN, malformed payload,
    invalid protocol fields, rate limit rejection."""

    def setUp(self):
        self.cache = DNSCache()
        self.resolver = StaticResolver(SAMPLE_RECORDS, default_ttl=10)
        self.handler = DNSRequestHandler(
            cache=self.cache,
            resolver=self.resolver,
            rate_limiter=None,
        )
        self.now = 1000000.0

    def _handle(
        self,
        domain: str = "myweb.local",
        request_id: str = "req-1",
        now: float | None = None,
        **overrides,
    ) -> dict:
        payload = _make_payload(domain=domain, request_id=request_id, **overrides)
        with patch("time.time", return_value=now or self.now):
            return self.handler.handle_packet(payload, CLIENT_ADDR)

    def test_valid_lookup_returns_ok(self):
        resp = self._handle("myweb.local", request_id="req-ok")
        self.assertEqual(resp["version"], PROTOCOL_VERSION)
        self.assertEqual(resp["id"], "req-ok")
        self.assertEqual(resp["status"], STATUS_OK)
        self.assertEqual(resp["domain"], "myweb.local")
        self.assertEqual(resp["qtype"], QTYPE_A)
        self.assertEqual(resp["ip"], "127.0.0.1")
        self.assertEqual(resp["ttl"], 10)

    def test_valid_lookup_caches_result(self):
        resp1 = self._handle("myweb.local", request_id="req-1")
        resp2 = self._handle("myweb.local", request_id="req-2")
        self.assertEqual(resp1["status"], STATUS_OK)
        self.assertEqual(resp2["status"], STATUS_OK)
        self.assertEqual(resp2["id"], "req-2")
        self.assertEqual(resp2["ttl"], 10)

    def test_valid_lookup_with_per_record_ttl(self):
        resp = self._handle("example.local", request_id="req-ttl")
        self.assertEqual(resp["status"], STATUS_OK)
        self.assertEqual(resp["ip"], "127.0.0.1")
        self.assertEqual(resp["ttl"], 5)

    def test_forwarded_lookup_is_cached_with_forward_ttl(self):
        handler = DNSRequestHandler(
            cache=DNSCache(),
            resolver=SystemForwardingResolver(ttl_seconds=45),
            rate_limiter=None,
        )
        payload_1 = _make_payload("example.com", request_id="req-forward-1")
        payload_2 = _make_payload("example.com", request_id="req-forward-2")

        with patch(
            "dns.dns_resolver.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
        ) as mocked_getaddrinfo:
            with patch("time.time", return_value=self.now):
                resp1 = handler.handle_packet(payload_1, CLIENT_ADDR)
                resp2 = handler.handle_packet(payload_2, CLIENT_ADDR)

        self.assertEqual(resp1["status"], STATUS_OK)
        self.assertEqual(resp1["ttl"], 45)
        self.assertEqual(resp2["status"], STATUS_OK)
        self.assertEqual(resp2["ttl"], 45)
        self.assertEqual(mocked_getaddrinfo.call_count, 1)

    def test_nxdomain_for_unknown_domain(self):
        resp = self._handle("unknown.local", request_id="req-miss")
        self.assertEqual(resp["version"], PROTOCOL_VERSION)
        self.assertEqual(resp["id"], "req-miss")
        self.assertEqual(resp["status"], STATUS_NXDOMAIN)
        self.assertEqual(resp["domain"], "unknown.local")
        self.assertEqual(resp["qtype"], QTYPE_A)
        self.assertIsNone(resp["ip"])
        self.assertIsNone(resp["ttl"])
        self.assertIn("message", resp)

    def test_malformed_json_returns_bad_request(self):
        payload = b"not json at all"
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)
        self.assertIsNone(resp["id"])
        self.assertIsNone(resp["ip"])

    def test_empty_payload_returns_bad_request(self):
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(b"", CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)

    def test_non_object_json_returns_bad_request(self):
        payload = b'[1, 2, 3]'
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)

    def test_missing_domain_field_returns_bad_request(self):
        payload = json.dumps(
            {
                "version": PROTOCOL_VERSION,
                "id": "req-1",
                "op": RESOLVE_OPERATION,
                "qtype": QTYPE_A,
            }
        ).encode("utf-8")
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)

    def test_non_string_domain_returns_bad_request(self):
        payload = json.dumps(_make_request_data(domain=123)).encode("utf-8")
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)

    def test_empty_string_domain_returns_bad_request(self):
        payload = json.dumps(_make_request_data(domain="")).encode("utf-8")
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)

    def test_whitespace_only_domain_returns_bad_request(self):
        payload = json.dumps(_make_request_data(domain="   ")).encode("utf-8")
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)

    def test_non_utf8_payload_returns_bad_request(self):
        payload = b"\xff\xfe\x00\x01"
        with patch("time.time", return_value=self.now):
            resp = self.handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)

    def test_invalid_domain_format_returns_bad_request(self):
        resp = self._handle("-invalid.local", request_id="req-bad")
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)
        self.assertEqual(resp["message"], "Invalid domain format")
        self.assertEqual(resp["domain"], "-invalid.local")

    def test_rate_limit_rejection(self):
        limiter = RateLimiter(max_queries=2, window_seconds=10)
        handler = DNSRequestHandler(
            cache=self.cache,
            resolver=self.resolver,
            rate_limiter=limiter,
        )
        for request_id in ("req-1", "req-2"):
            payload = _make_payload("myweb.local", request_id=request_id)
            with patch("time.time", return_value=self.now):
                resp = handler.handle_packet(payload, CLIENT_ADDR)
            self.assertEqual(resp["status"], STATUS_OK)

        payload = _make_payload("myweb.local", request_id="req-3")
        with patch("time.time", return_value=self.now):
            resp = handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_RATE_LIMITED)
        self.assertEqual(resp["id"], "req-3")
        self.assertEqual(resp["domain"], "myweb.local")
        self.assertIn("retry_after", resp)

    def test_oversized_packet_returns_bad_request(self):
        handler = DNSRequestHandler(
            cache=self.cache,
            resolver=self.resolver,
            max_request_bytes=64,
        )
        payload = _make_payload("example.local", request_id="x" * 100)
        with patch("time.time", return_value=self.now):
            resp = handler.handle_packet(payload, CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_BAD_REQUEST)
        self.assertIn("too large", resp["message"])

    def test_resolver_exception_returns_error_with_request_context(self):
        handler = DNSRequestHandler(
            cache=DNSCache(),
            resolver=_FakeForwardingResolver(side_effect=RuntimeError("boom")),
            rate_limiter=None,
        )
        with patch("time.time", return_value=self.now):
            resp = handler.handle_packet(_make_payload("example.com", request_id="req-error"), CLIENT_ADDR)
        self.assertEqual(resp["status"], STATUS_ERROR)
        self.assertEqual(resp["id"], "req-error")
        self.assertEqual(resp["domain"], "example.com")


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


# ---------------------------------------------------------------------------
# TestDNSUDPJSONV1Smoke
# ---------------------------------------------------------------------------


class TestDNSUDPJSONV1Smoke(unittest.TestCase):
    """Live UDP roundtrip test for the v1 JSON contract."""

    def test_live_udp_query_roundtrip(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except PermissionError as exc:
            self.skipTest(f"UDP sockets are not available in this environment: {exc}")

        handler = DNSRequestHandler(
            cache=DNSCache(),
            resolver=StaticResolver({"example.local": {"ip": "127.0.0.1", "ttl": 12}}, default_ttl=10),
            rate_limiter=None,
        )
        server_socket.bind(("127.0.0.1", 0))
        server_socket.settimeout(1)
        host, port = server_socket.getsockname()

        def serve_one():
            try:
                payload, client_addr = server_socket.recvfrom(2048)
                response = handler.handle_packet(payload, client_addr)
                server_socket.sendto(encode_response(response), client_addr)
            finally:
                server_socket.close()

        thread = threading.Thread(target=serve_one, daemon=True)
        thread.start()

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(1)
        try:
            client_socket.sendto(_make_payload("example.local", request_id="smoke-1"), (host, port))
            data, _ = client_socket.recvfrom(2048)
        finally:
            client_socket.close()

        thread.join(timeout=1)
        response = json.loads(data.decode("utf-8"))
        self.assertEqual(response["version"], PROTOCOL_VERSION)
        self.assertEqual(response["id"], "smoke-1")
        self.assertEqual(response["status"], STATUS_OK)
        self.assertEqual(response["domain"], "example.local")
        self.assertEqual(response["qtype"], QTYPE_A)
        self.assertEqual(response["ip"], "127.0.0.1")
        self.assertEqual(response["ttl"], 12)


if __name__ == "__main__":
    unittest.main()
