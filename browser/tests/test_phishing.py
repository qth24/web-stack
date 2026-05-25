"""Unit tests for the phishing detection V2 engine."""

import time
import unittest
from typing import Optional
from browser.core.phishing import (
    ThreatAssessment,
    SignalHit,
    ReputationHit,
    ReputationData,
    assess_url,
    assess_content,
    merge_assessments,
    get_top_reasons,
    _is_ipv4,
    _normalize_confusable,
    _brand_token_matches_hostname,
    load_reputation,
    set_external_reputation_lookup,
    _EXTERNAL_REPUTATION_CACHE,
)

_TEST_REPUTATION = ReputationData(
    blocked_domains={"bad-example.com"},
    blocked_url_prefixes=["https://evil.test/collect"],
    protected_brands=[
        {
            "name": "PayPal",
            "domains": ["paypal.com", "paypal.me"],
            "trusted_host_suffixes": [],
            "related_domains": [],
        },
        {
            "name": "Google",
            "domains": ["google.com", "accounts.google.com"],
            "trusted_host_suffixes": [],
            "related_domains": ["youtube.com"],
        },
    ],
    suspicious_keywords={"login", "verify", "secure", "account", "wallet", "otp", "seed"},
    trusted_hosts=set(),
    external_reputation=None,
)


class TestSignalHit(unittest.TestCase):
    def test_signal_hit_fields(self):
        s = SignalHit(
            id="test_hit", category="technical", severity="low",
            score=8, reason="test reason",
        )
        self.assertEqual(s.id, "test_hit")
        self.assertEqual(s.category, "technical")
        self.assertEqual(s.severity, "low")
        self.assertEqual(s.score, 8)
        self.assertEqual(s.reason, "test reason")


class TestThreatAssessment(unittest.TestCase):
    def test_defaults(self):
        a = ThreatAssessment(score=0, verdict="safe")
        self.assertEqual(a.action, "allow")
        self.assertEqual(a.confidence, 0.0)
        self.assertEqual(a.signals, [])
        self.assertFalse(a.trusted_host)

    def test_full_fields(self):
        s = SignalHit(id="x", category="generic", severity="low", score=5, reason="r")
        a = ThreatAssessment(
            score=35, verdict="suspicious", action="warn",
            confidence=0.75, reasons=["r"], signals=[s],
            matched_brand="PayPal", trusted_host=False,
        )
        self.assertEqual(a.verdict, "suspicious")
        self.assertEqual(a.score, 35)
        self.assertEqual(a.matched_brand, "PayPal")
        self.assertFalse(a.trusted_host)


class TestReputationHit(unittest.TestCase):
    def test_reputation_hit_fields(self):
        rh = ReputationHit(source="test", verdict="clean", ttl_seconds=3600)
        self.assertEqual(rh.source, "test")
        self.assertEqual(rh.verdict, "clean")
        self.assertEqual(rh.ttl_seconds, 3600)


class TestIPv4Detection(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(_is_ipv4("192.168.1.1"))
        self.assertTrue(_is_ipv4("127.0.0.1"))

    def test_invalid_ipv4(self):
        self.assertFalse(_is_ipv4("example.com"))
        self.assertFalse(_is_ipv4("256.1.1.1"))
        self.assertFalse(_is_ipv4("1.2.3"))


class TestConfusable(unittest.TestCase):
    def test_normalize_cyrillic_a(self):
        self.assertEqual(_normalize_confusable("payp\u0430l"), "paypal")

    def test_normalize_cyrillic_o(self):
        self.assertEqual(_normalize_confusable("g\u043e\u043egle"), "google")

    def test_normalize_mixed(self):
        result = _normalize_confusable("PayPal")
        self.assertIn("paypal", result)


class TestURLScoring(unittest.TestCase):
    def test_ipv4_host_scores_twelve(self):
        a = assess_url("http://192.168.1.1/login", _TEST_REPUTATION)
        ipv4_signals = [s for s in a.signals if s.id == "ipv4_host"]
        self.assertEqual(len(ipv4_signals), 1)
        self.assertEqual(ipv4_signals[0].score, 12)

    def test_http_scheme_scores_eight(self):
        a = assess_url("http://example.com", _TEST_REPUTATION)
        http_signals = [s for s in a.signals if s.id == "http_scheme"]
        self.assertEqual(len(http_signals), 1)
        self.assertEqual(http_signals[0].score, 8)

    def test_https_no_http_penalty(self):
        a = assess_url("https://example.com", _TEST_REPUTATION)
        http_signals = [s for s in a.signals if s.id == "http_scheme"]
        self.assertEqual(len(http_signals), 0)

    def test_suspicious_keyword_in_path(self):
        a = assess_url("http://example.com/login", _TEST_REPUTATION)
        kw_signals = [s for s in a.signals if s.id == "suspicious_keyword"]
        self.assertEqual(len(kw_signals), 1)
        self.assertEqual(kw_signals[0].score, 5)

    def test_suspicious_keyword_in_host(self):
        a = assess_url("http://login-example.com", _TEST_REPUTATION)
        kw_signals = [s for s in a.signals if s.id == "suspicious_keyword"]
        self.assertEqual(len(kw_signals), 1)

    def test_long_hostname_scores_four(self):
        a = assess_url("http://very-long-hostname-that-exceeds-thirty-five-characters.example.com", _TEST_REPUTATION)
        long_signals = [s for s in a.signals if s.id == "long_hostname"]
        self.assertEqual(len(long_signals), 1)
        self.assertEqual(long_signals[0].score, 4)

    def test_four_labels_scores_four(self):
        a = assess_url("http://a.b.c.d.example.com", _TEST_REPUTATION)
        label_signals = [s for s in a.signals if s.id == "many_labels"]
        self.assertEqual(len(label_signals), 1)
        self.assertEqual(label_signals[0].score, 4)

    def test_punycode_scores_fifteen(self):
        a = assess_url("http://xn--example-5cd.com", _TEST_REPUTATION)
        puny_signals = [s for s in a.signals if s.id == "punycode"]
        self.assertEqual(len(puny_signals), 1)
        self.assertEqual(puny_signals[0].score, 15)

    def test_low_signals_only_suspicious_at_most(self):
        a = assess_url("http://very-long-hostname-that-exceeds-thirty-five-characters.a.b.c.d.example.com/login", _TEST_REPUTATION)
        self.assertNotEqual(a.verdict, "phishing")


class TestBrandMatching(unittest.TestCase):
    def test_brand_spoof_hostname_untrusted(self):
        a = assess_url("http://paypal.verify.example.com", _TEST_REPUTATION)
        spoof_signals = [s for s in a.signals if s.id == "brand_spoof_hostname"]
        self.assertTrue(len(spoof_signals) > 0, f"signals: {a.signals}")
        self.assertEqual(spoof_signals[0].score, 35)

    def test_legitimate_paypal_no_spoof(self):
        a = assess_url("https://paypal.com/login", _TEST_REPUTATION)
        spoof_signals = [s for s in a.signals if s.id == "brand_spoof_hostname"]
        self.assertEqual(len(spoof_signals), 0)

    def test_paypal_subdomain_trusted(self):
        a = assess_url("https://www.paypal.com/login", _TEST_REPUTATION)
        spoof_signals = [s for s in a.signals if s.id == "brand_spoof_hostname"]
        self.assertEqual(len(spoof_signals), 0)

    def test_confusable_brand_detected(self):
        a = assess_url("http://payp\u0430l.example.com", _TEST_REPUTATION)
        spoof_signals = [s for s in a.signals if s.id == "brand_spoof_hostname"]
        self.assertTrue(len(spoof_signals) > 0, f"signals: {a.signals}")


class TestBlockedDomains(unittest.TestCase):
    def test_blocked_domain_immediate_phishing(self):
        a = assess_url("http://bad-example.com/page", _TEST_REPUTATION)
        self.assertEqual(a.verdict, "phishing")
        self.assertEqual(a.action, "block")
        bl_signals = [s for s in a.signals if s.id == "blocklist_hit"]
        self.assertEqual(len(bl_signals), 1)
        self.assertEqual(bl_signals[0].severity, "critical")

    def test_blocked_url_prefix_immediate_phishing(self):
        a = assess_url("https://evil.test/collect/data?x=1", _TEST_REPUTATION)
        self.assertEqual(a.verdict, "phishing")
        self.assertEqual(a.action, "block")

    def test_blocked_url_prefix_no_match(self):
        a = assess_url("https://evil.test/other", _TEST_REPUTATION)
        self.assertNotEqual(a.verdict, "phishing")


class TestBenignTargets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._rep = ReputationData(
            blocked_domains={"bad-example.com"},
            blocked_url_prefixes=[],
            protected_brands=[
                {
                    "name": "Microsoft",
                    "domains": ["microsoft.com", "login.microsoftonline.com", "outlook.com", "live.com", "office.com"],
                    "trusted_host_suffixes": [],
                    "related_domains": [],
                },
                {
                    "name": "PayPal",
                    "domains": ["paypal.com", "paypal.me", "paypalobjects.com"],
                    "trusted_host_suffixes": [],
                    "related_domains": [],
                },
                {
                    "name": "Facebook",
                    "domains": ["facebook.com", "fb.com", "messenger.com"],
                    "trusted_host_suffixes": [],
                    "related_domains": [],
                },
                {
                    "name": "YouTube",
                    "domains": ["youtube.com", "youtu.be"],
                    "trusted_host_suffixes": [],
                    "related_domains": [],
                },
            ],
            suspicious_keywords={
                "login", "verify", "secure", "account", "wallet", "otp", "seed", "recovery",
                "unlock", "restore", "confirm", "validate", "update-payment", "billing",
            },
            trusted_hosts=set(),
            external_reputation=None,
        )

    def test_microsoft_com_safe(self):
        a = assess_url("https://www.microsoft.com/vi-vn", self._rep)
        self.assertEqual(a.verdict, "safe")

    def test_paypal_com_safe(self):
        a = assess_url("https://www.paypal.com/vn/home", self._rep)
        self.assertEqual(a.verdict, "safe")

    def test_facebook_com_safe(self):
        a = assess_url("https://www.facebook.com/", self._rep)
        self.assertEqual(a.verdict, "safe")

    def test_youtube_com_safe(self):
        a = assess_url("https://www.youtube.com/", self._rep)
        self.assertEqual(a.verdict, "safe")


class TestSuppressors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._rep = ReputationData(
            blocked_domains=set(),
            blocked_url_prefixes=[],
            protected_brands=[
                {
                    "name": "PayPal",
                    "domains": ["paypal.com", "paypal.me"],
                    "trusted_host_suffixes": [],
                    "related_domains": [],
                },
            ],
            suspicious_keywords={"login", "secure"},
            trusted_hosts=set(),
            external_reputation=None,
        )

    def test_trusted_host_password_form_not_phishing(self):
        html = (
            "<html><head><title>PayPal Login</title></head>"
            "<body><h1>Sign in to PayPal</h1>"
            "<form><input type='password' name='pass'></form>"
            "</body></html>"
        )
        url = assess_url("https://www.paypal.com/login", self._rep)
        content = assess_content("https://www.paypal.com/login", html, self._rep)
        merged = merge_assessments(url, content)
        self.assertNotEqual(merged.verdict, "phishing")

    def test_untrusted_host_brand_focused_form_is_phishing(self):
        html = (
            "<html><head><title>PayPal Login</title></head>"
            "<body><h1>Sign in to PayPal</h1>"
            "<form><input type='password' name='pass'><button>Log In</button></form>"
            "</body></html>"
        )
        url = assess_url("http://phishing.test/login", self._rep)
        content = assess_content("http://phishing.test/login", html, self._rep)
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "phishing")

    def test_multiple_brands_no_credentials_safe(self):
        html = (
            "<html><head><title>Compare Payment Options</title></head>"
            "<body><h1>PayPal vs Google Pay</h1>"
            "<p>Both PayPal and Google offer secure payments.</p>"
            "</body></html>"
        )
        rep = ReputationData(
            blocked_domains=set(),
            blocked_url_prefixes=[],
            protected_brands=[
                {"name": "PayPal", "domains": ["paypal.com"], "trusted_host_suffixes": [], "related_domains": []},
                {"name": "Google", "domains": ["google.com"], "trusted_host_suffixes": [], "related_domains": []},
            ],
            suspicious_keywords={"secure"},
            trusted_hosts=set(),
            external_reputation=None,
        )
        content = assess_content("http://some-site.test/page", html, rep)
        mismatch_signals = [s for s in content.signals if s.id == "brand_text_mismatch"]
        self.assertEqual(len(mismatch_signals), 0)

    def test_hidden_iframe_no_form_no_signal(self):
        html = (
            "<html><body>"
            "<iframe hidden src='https://evil.com/frame'></iframe>"
            "</body></html>"
        )
        content = assess_content("http://test.local/page", html, self._rep)
        iframe_signals = [s for s in content.signals if s.id == "hidden_iframe_with_form"]
        self.assertEqual(len(iframe_signals), 0)

    def test_hidden_iframe_with_form_scores(self):
        html = (
            "<html><body>"
            "<form><input type='password' name='pass'></form>"
            "<iframe hidden src='https://evil.com/frame'></iframe>"
            "</body></html>"
        )
        content = assess_content("http://test.local/page", html, self._rep)
        iframe_signals = [s for s in content.signals if s.id == "hidden_iframe_with_form"]
        self.assertEqual(len(iframe_signals), 1)


class TestContentAnalysis(unittest.TestCase):
    def test_password_input_in_form_scores_collection(self):
        html = (
            "<html><body><form>"
            "<input type='password' name='pass'>"
            "</form></body></html>"
        )
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        cred_signals = [s for s in a.signals if s.id == "credential_collection"]
        self.assertTrue(len(cred_signals) > 0, f"signals: {a.signals}")

    def test_no_password_no_credential_signal(self):
        html = "<html><body><form><input type='text' name='user'></form></body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        cred_signals = [s for s in a.signals if s.id == "credential_collection"]
        self.assertEqual(len(cred_signals), 0)

    def test_cross_origin_form_scores_exfiltration(self):
        html = "<html><body><form action='https://evil.com/collect'></form></body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        cross_signals = [s for s in a.signals if s.id == "cross_origin_form"]
        self.assertEqual(len(cross_signals), 1)
        self.assertEqual(cross_signals[0].score, 35)

    def test_form_same_origin_no_cross_origin_signal(self):
        html = "<html><body><form action='/submit'></form></body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        cross_signals = [s for s in a.signals if s.id == "cross_origin_form"]
        self.assertEqual(len(cross_signals), 0)

    def test_obfuscated_script_detected(self):
        html = (
            "<html><body><script>eval(atob('dGhpcyBpcyBvYmZ1c2NhdGVk'))</script></body></html>"
        )
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        obfuscated_signals = [s for s in a.signals if s.id == "obfuscated_script"]
        self.assertEqual(len(obfuscated_signals), 1)
        self.assertEqual(obfuscated_signals[0].score, 15)

    def test_brand_text_in_title_scores_mismatch(self):
        html = (
            "<html><head><title>PayPal - Log In</title></head>"
            "<body><h1>Welcome to PayPal</h1></body></html>"
        )
        a = assess_content("http://phishing.example.com", html, _TEST_REPUTATION)
        mismatch_signals = [s for s in a.signals if s.id == "brand_text_mismatch"]
        self.assertTrue(len(mismatch_signals) > 0, f"signals: {a.signals}")
        self.assertEqual(mismatch_signals[0].score, 20)

    def test_non_html_skips(self):
        a = assess_content("http://test.local/file.pdf", "raw data not html", _TEST_REPUTATION)
        self.assertEqual(a.score, 0)
        self.assertEqual(a.verdict, "safe")

    def test_empty_html_safe(self):
        a = assess_content("http://test.local/page", "", _TEST_REPUTATION)
        self.assertEqual(a.verdict, "safe")


class TestMergeAssessments(unittest.TestCase):
    def test_safe_plus_safe_remains_safe(self):
        url = ThreatAssessment(
            score=10, verdict="safe", signals=[
                SignalHit(id="http_scheme", category="technical", severity="low", score=8, reason="http")
            ]
        )
        content = ThreatAssessment(score=0, verdict="safe", signals=[])
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "safe")

    def test_blocked_plus_safe_is_phishing(self):
        url = ThreatAssessment(
            score=100, verdict="phishing", action="block",
            signals=[
                SignalHit(id="blocklist_hit", category="identity", severity="critical", score=100, reason="blocked")
            ]
        )
        content = ThreatAssessment(score=0, verdict="safe", signals=[])
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "phishing")

    def test_spoof_plus_credential_collection_is_phishing(self):
        url = ThreatAssessment(
            score=35, verdict="suspicious", signals=[
                SignalHit(id="brand_spoof_hostname", category="identity", severity="high", score=35, reason="spoof")
            ]
        )
        content = ThreatAssessment(
            score=25, verdict="suspicious", signals=[
                SignalHit(id="credential_collection", category="collection", severity="high", score=25, reason="creds")
            ]
        )
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "phishing")

    def test_deduplicates_signals(self):
        url = ThreatAssessment(
            score=35, verdict="suspicious", signals=[
                SignalHit(id="brand_spoof_hostname", category="identity", severity="high", score=35, reason="x"),
            ]
        )
        content = ThreatAssessment(
            score=35, verdict="suspicious", signals=[
                SignalHit(id="brand_spoof_hostname", category="identity", severity="high", score=35, reason="x"),
            ]
        )
        merged = merge_assessments(url, content)
        self.assertEqual(len(merged.signals), 1)


class TestDecisionPolicy(unittest.TestCase):
    def test_identity_gte_20_and_collection_gte_20_is_phishing(self):
        url = ThreatAssessment(
            score=35, verdict="suspicious", signals=[
                SignalHit(id="brand_spoof_hostname", category="identity", severity="high", score=35, reason="x"),
            ]
        )
        content = ThreatAssessment(
            score=25, verdict="suspicious", signals=[
                SignalHit(id="credential_collection", category="collection", severity="high", score=25, reason="y"),
            ]
        )
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "phishing")

    def test_collection_20_and_exfiltration_35_is_phishing(self):
        url = ThreatAssessment(score=0, verdict="safe", signals=[])
        content = ThreatAssessment(
            score=60, verdict="suspicious", signals=[
                SignalHit(id="credential_collection", category="collection", severity="high", score=25, reason="creds"),
                SignalHit(id="cross_origin_form", category="exfiltration", severity="high", score=35, reason="cross"),
            ]
        )
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "phishing")

    def test_total_60_with_two_cats_is_phishing(self):
        url = ThreatAssessment(
            score=35, verdict="suspicious", signals=[
                SignalHit(id="brand_spoof_hostname", category="identity", severity="high", score=35, reason="x"),
            ]
        )
        content = ThreatAssessment(
            score=25, verdict="suspicious", signals=[
                SignalHit(id="cross_origin_form", category="exfiltration", severity="high", score=35, reason="y"),
            ]
        )
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "phishing")


class TestExternalReputation(unittest.TestCase):
    def setUp(self):
        set_external_reputation_lookup(None)

    def tearDown(self):
        set_external_reputation_lookup(None)

    def test_disabled_by_default_no_call(self):
        rep = ReputationData(
            blocked_domains=set(),
            blocked_url_prefixes=[],
            protected_brands=[],
            suspicious_keywords=set(),
            trusted_hosts=set(),
            external_reputation={"enabled": False, "provider": "test", "timeout_ms": 500, "ttl_seconds": 3600},
        )
        called = []

        def lookup(url, host):
            called.append(1)
            return ReputationHit(source="test", verdict="malicious", ttl_seconds=3600)

        set_external_reputation_lookup(lookup)
        a = assess_url("http://test.example.com/page", rep)
        self.assertEqual(len(called), 0)
        self.assertNotEqual(a.verdict, "phishing")

    def test_external_malicious_escalates(self):
        rep = ReputationData(
            blocked_domains=set(),
            blocked_url_prefixes=[],
            protected_brands=[],
            suspicious_keywords=set(),
            trusted_hosts=set(),
            external_reputation={"enabled": True, "provider": "test", "timeout_ms": 500, "ttl_seconds": 3600},
        )

        def lookup(url, host):
            return ReputationHit(source="test", verdict="malicious", ttl_seconds=3600)

        set_external_reputation_lookup(lookup)
        a = assess_url("http://test.example.com/page", rep)
        self.assertEqual(a.verdict, "phishing")

    def test_external_clean_does_not_downgrade(self):
        rep = ReputationData(
            blocked_domains={"bad-example.com"},
            blocked_url_prefixes=[],
            protected_brands=[],
            suspicious_keywords=set(),
            trusted_hosts=set(),
            external_reputation={"enabled": True, "provider": "test", "timeout_ms": 500, "ttl_seconds": 3600},
        )

        def lookup(url, host):
            return ReputationHit(source="test", verdict="clean", ttl_seconds=3600)

        set_external_reputation_lookup(lookup)
        a = assess_url("http://bad-example.com/page", rep)
        self.assertEqual(a.verdict, "phishing")

    def test_external_timeout_fails_open(self):
        rep = ReputationData(
            blocked_domains=set(),
            blocked_url_prefixes=[],
            protected_brands=[],
            suspicious_keywords=set(),
            trusted_hosts=set(),
            external_reputation={"enabled": True, "provider": "test", "timeout_ms": 500, "ttl_seconds": 3600},
        )

        def lookup(url, host):
            raise TimeoutError("simulated timeout")

        set_external_reputation_lookup(lookup)
        a = assess_url("http://test.example.com/page", rep)
        self.assertIsNotNone(a)


class TestGetTopReasons(unittest.TestCase):
    def test_top_reasons_by_score(self):
        a = ThreatAssessment(
            score=50, verdict="suspicious", signals=[
                SignalHit(id="a", category="identity", severity="high", score=35, reason="high reason"),
                SignalHit(id="b", category="technical", severity="low", score=4, reason="low reason"),
                SignalHit(id="c", category="exfiltration", severity="medium", score=15, reason="medium reason"),
                SignalHit(id="d", category="generic", severity="low", score=5, reason="generic reason"),
            ]
        )
        top = get_top_reasons(a, 3)
        self.assertEqual(len(top), 3)
        self.assertEqual(top[0], "high reason")
        self.assertEqual(top[1], "medium reason")
        self.assertEqual(top[2], "generic reason")


class TestReputationLoading(unittest.TestCase):
    def test_load_builtin_defaults(self):
        rep = load_reputation()
        self.assertIsInstance(rep, ReputationData)
        self.assertTrue(len(rep.protected_brands) > 0)
        self.assertTrue(len(rep.suspicious_keywords) > 0)

    def test_load_with_nonexistent_user_path(self):
        import tempfile, os
        from pathlib import Path
        tmp = Path(tempfile.mkdtemp()) / "nonexistent_rules.json"
        try:
            rep = load_reputation(tmp)
            self.assertIsInstance(rep, ReputationData)
            self.assertTrue(tmp.exists(), "Should create starter JSON")
        finally:
            import shutil
            shutil.rmtree(tmp.parent, ignore_errors=True)

    def test_user_rules_extend_builtin(self):
        import tempfile, json
        from pathlib import Path
        tmpdir = Path(tempfile.mkdtemp())
        user_path = tmpdir / "rules.json"
        user_path.write_text(json.dumps({
            "blocked_domains": ["my-custom-evil.com"],
            "blocked_url_prefixes": [],
            "protected_brands": [],
            "suspicious_keywords": ["custom-keyword"],
            "trusted_hosts": ["my-trusted.com"],
        }))
        try:
            rep = load_reputation(user_path)
            self.assertIn("my-custom-evil.com", rep.blocked_domains)
            self.assertIn("custom-keyword", rep.suspicious_keywords)
            self.assertIn("my-trusted.com", rep.trusted_hosts)
            self.assertTrue(len(rep.protected_brands) > 0)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_malformed_json_falls_back(self):
        import tempfile, json
        from pathlib import Path
        tmpdir = Path(tempfile.mkdtemp())
        user_path = tmpdir / "bad.json"
        user_path.write_text("not valid json {{{")
        try:
            rep = load_reputation(user_path)
            self.assertIsInstance(rep, ReputationData)
            self.assertTrue(len(rep.protected_brands) > 0)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestReputationDataHelpers(unittest.TestCase):
    def test_is_host_trusted(self):
        rep = ReputationData(trusted_hosts={"example.com"})
        self.assertTrue(rep.is_host_trusted("example.com"))
        self.assertTrue(rep.is_host_trusted("www.example.com"))
        self.assertFalse(rep.is_host_trusted("evil.com"))

    def test_is_host_trusted_for_brand(self):
        rep = ReputationData(
            protected_brands=[
                {
                    "name": "PayPal",
                    "domains": ["paypal.com"],
                    "trusted_host_suffixes": ["paypalobjects.com"],
                    "related_domains": [],
                },
            ],
            trusted_hosts={"youtube.com"},
        )
        self.assertTrue(rep.is_host_trusted_for_brand("www.paypal.com", "PayPal"))
        self.assertTrue(rep.is_host_trusted_for_brand("cdn.paypalobjects.com", "PayPal"))
        self.assertTrue(rep.is_host_trusted_for_brand("www.youtube.com", "Google"))
        self.assertFalse(rep.is_host_trusted_for_brand("evil.com", "PayPal"))

    def test_find_matching_brand(self):
        rep = ReputationData(
            protected_brands=[
                {
                    "name": "Google",
                    "domains": ["google.com"],
                    "trusted_host_suffixes": [],
                    "related_domains": ["youtube.com"],
                },
            ]
        )
        self.assertEqual(rep.find_matching_brand("youtube"), "Google")


class TestExternalReputation(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self._rep = ReputationData(
            external_reputation={"enabled": True, "ttl_seconds": 3600, "timeout_ms": 5000},
        )

    def tearDown(self):
        _EXTERNAL_REPUTATION_CACHE.clear()
        set_external_reputation_lookup(None)
        super().tearDown()

    def test_external_malicious_blocks_as_phishing(self):
        def malicious_lookup(_url: str, _host: str) -> Optional[ReputationHit]:
            return ReputationHit(source="test", verdict="malicious", ttl_seconds=60)
        set_external_reputation_lookup(malicious_lookup)

        a = assess_url("http://any-evil.test/login", self._rep)
        self.assertEqual(a.verdict, "phishing")
        self.assertGreaterEqual(a.score, 1)

    def test_external_safe_bypasses_local_checks(self):
        def clean_lookup(_url: str, _host: str) -> Optional[ReputationHit]:
            return ReputationHit(source="test", verdict="safe", ttl_seconds=60)
        set_external_reputation_lookup(clean_lookup)

        a = assess_url("http://192.168.1.1/login", self._rep)
        self.assertEqual(a.verdict, "safe")
        self.assertEqual(a.score, 0)
        self.assertEqual(len(a.signals), 0)

    def test_external_unreachable_falls_back_to_local(self):
        def unreachable_lookup(_url: str, _host: str) -> Optional[ReputationHit]:
            return None
        set_external_reputation_lookup(unreachable_lookup)

        a = assess_url("http://192.168.1.1/login", self._rep)
        self.assertGreaterEqual(a.score, 20)
        self.assertIn("IPv4 address", str(a.reasons))

    def test_external_lookup_cached_internally(self):
        call_count = 0

        def counting_lookup(_url: str, _host: str) -> Optional[ReputationHit]:
            nonlocal call_count
            call_count += 1
            return None
        set_external_reputation_lookup(counting_lookup)

        rep = ReputationData(
            external_reputation={"enabled": True, "ttl_seconds": 3600, "timeout_ms": 5000},
        )
        assess_url("http://cached.test/page", rep)
        assess_url("http://cached.test/page", rep)
        self.assertEqual(call_count, 1, "cache should prevent redundant API call for same URL")

    def test_external_lookup_not_called_when_disabled(self):
        call_count = 0

        def never_called(_url: str, _host: str) -> Optional[ReputationHit]:
            nonlocal call_count
            call_count += 1
            return ReputationHit(source="test", verdict="malicious", ttl_seconds=60)
        set_external_reputation_lookup(never_called)

        rep = ReputationData(external_reputation={"enabled": False, "ttl_seconds": 3600})
        a = assess_url("http://example.com/page", rep)
        self.assertEqual(a.verdict, "safe")
        self.assertEqual(call_count, 0)

    def test_google_safe_browsing_lookup_returns_valid_hit(self):
        import browser.core.safe_browsing as sb
        original = getattr(sb, "GOOGLE_SAFE_BROWSING_API_KEY", "")
        sb.GOOGLE_SAFE_BROWSING_API_KEY = ""
        try:
            result = sb.google_safe_browsing_lookup("http://evil.test/")
            self.assertIsNone(result)
        finally:
            sb.GOOGLE_SAFE_BROWSING_API_KEY = original


if __name__ == "__main__":
    unittest.main()
