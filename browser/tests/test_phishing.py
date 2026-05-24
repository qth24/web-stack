"""Unit tests for the phishing detection module."""

import time
import unittest
from browser.core.phishing import (
    ThreatAssessment,
    ReputationData,
    assess_url,
    assess_content,
    merge_assessments,
    _is_ipv4,
    _normalize_confusable,
    _brand_token_matches_hostname,
    _score_verdict,
    load_reputation,
)

_TEST_REPUTATION = ReputationData(
    blocked_domains={"bad-example.com"},
    blocked_url_prefixes=["https://evil.test/collect"],
    protected_brands=[
        {"name": "PayPal", "domains": ["paypal.com", "paypal.me"]},
        {"name": "Google", "domains": ["google.com", "accounts.google.com"]},
    ],
    suspicious_keywords={"login", "verify", "secure", "account", "wallet", "otp", "seed"},
)


class TestURLScoring(unittest.TestCase):
    def test_ipv4_address_scores_30(self):
        a = assess_url("http://192.168.1.1/login", _TEST_REPUTATION)
        self.assertIn("IPv4 address", str(a.reasons))

    def test_http_scheme_scores_15(self):
        a = assess_url("http://example.com", _TEST_REPUTATION)
        self.assertIn("scheme is http", str(a.reasons))

    def test_https_no_http_penalty(self):
        a = assess_url("https://example.com", _TEST_REPUTATION)
        self.assertNotIn("scheme is http", str(a.reasons))

    def test_suspicious_keyword_scores_15(self):
        a = assess_url("http://example.com/login", _TEST_REPUTATION)
        keywords_in_reason = any("login" in r for r in a.reasons)
        self.assertTrue(keywords_in_reason)

    def test_suspicious_keyword_in_host(self):
        a = assess_url("http://login-example.com", _TEST_REPUTATION)
        keywords_in_reason = any("login" in r for r in a.reasons)
        self.assertTrue(keywords_in_reason)

    def test_long_hostname_scores_10(self):
        a = assess_url("http://very-long-hostname-that-exceeds-thirty-five-characters.example.com", _TEST_REPUTATION)
        self.assertIn("hostname length", str(a.reasons))

    def test_four_labels_scores_10(self):
        a = assess_url("http://a.b.c.d.example.com", _TEST_REPUTATION)
        self.assertIn("4+ labels", str(a.reasons))

    def test_punycode_scores_25(self):
        a = assess_url("http://xn--example-5cd.com", _TEST_REPUTATION)
        has_punycode = any("punycode" in r.lower() or "xn--" in r for r in a.reasons)
        self.assertTrue(has_punycode, f"reasons: {a.reasons}")


class TestBrandMatching(unittest.TestCase):
    def test_brand_token_mismatch_scores_25(self):
        a = assess_url("http://paypa1.example.com", _TEST_REPUTATION)
        brand_reasons = [r for r in a.reasons if "brand" in r.lower()]
        self.assertTrue(len(brand_reasons) > 0, f"reasons: {a.reasons}")

    def test_legitimate_paypal_domain_no_brand_penalty(self):
        a = assess_url("https://paypal.com/login", _TEST_REPUTATION)
        brand_reasons = [r for r in a.reasons if "brand" in r.lower()]
        self.assertEqual(len(brand_reasons), 0, f"brand reasons on legit: {brand_reasons}")

    def test_paypal_subdomain_trusted(self):
        a = assess_url("https://www.paypal.com/login", _TEST_REPUTATION)
        brand_reasons = [r for r in a.reasons if "brand" in r.lower()]
        self.assertEqual(len(brand_reasons), 0, f"brand reasons: {brand_reasons}")

    def test_paypal_in_hostname_untrusted_scores(self):
        a = assess_url("http://paypal.verify.example.com", _TEST_REPUTATION)
        brand_reasons = [r for r in a.reasons if "brand" in r.lower()]
        self.assertTrue(len(brand_reasons) > 0, f"reasons: {a.reasons}")


class TestBlockedDomains(unittest.TestCase):
    def test_exact_blocked_domain_returns_phishing(self):
        a = assess_url("http://bad-example.com/page", _TEST_REPUTATION)
        self.assertEqual(a.verdict, "phishing")
        self.assertIn("blocked domain", str(a.reasons))

    def test_blocked_url_prefix_returns_phishing(self):
        a = assess_url("https://evil.test/collect/data?x=1", _TEST_REPUTATION)
        self.assertEqual(a.verdict, "phishing")
        self.assertIn("blocked URL prefix", str(a.reasons))

    def test_blocked_url_prefix_no_match(self):
        a = assess_url("https://evil.test/other", _TEST_REPUTATION)
        self.assertNotEqual(a.verdict, "phishing")


class TestConfusable(unittest.TestCase):
    def test_normalize_cyrillic_a_to_latin_a(self):
        result = _normalize_confusable("paypаl")
        self.assertEqual(result, "paypal")

    def test_normalize_cyrillic_o_to_latin_o(self):
        result = _normalize_confusable("gооgle")
        self.assertEqual(result, "google")

    def test_normalize_mixed_cyrillic_latin(self):
        result = _normalize_confusable("РаyРаl")
        self.assertEqual(result, "paypal")

    def test_confusable_brand_hostname_detected(self):
        a = assess_url("http://paypаl.example.com", _TEST_REPUTATION)
        brand_reasons = [r for r in a.reasons if "brand" in r.lower()]
        self.assertTrue(len(brand_reasons) > 0, f"reasons: {a.reasons}")


class TestContentAnalysis(unittest.TestCase):
    def test_password_input_scores_20(self):
        html = "<html><body><form><input type='password' name='pass'></form></body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        self.assertIn("password input", str(a.reasons))
        self.assertGreaterEqual(a.score, 20)

    def test_no_password_input_no_score(self):
        html = "<html><body><form><input type='text' name='user'></form></body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        password_reasons = [r for r in a.reasons if "password" in r.lower()]
        self.assertEqual(len(password_reasons), 0)

    def test_credit_card_keywords_score_25(self):
        html = "<html><body>Please enter your credit card number and CVV</body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        self.assertIn("sensitive payment", str(a.reasons))

    def test_otp_keywords_score_25(self):
        html = "<html><body>Enter your OTP code to continue</body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        self.assertIn("sensitive payment", str(a.reasons))

    def test_form_cross_origin_scores_30(self):
        html = "<html><body><form action='https://evil.com/collect'></form></body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        self.assertIn("form submits to different host", str(a.reasons))

    def test_form_same_origin_no_score(self):
        html = "<html><body><form action='/submit'></form></body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        cross_origin = [r for r in a.reasons if "different host" in r]
        self.assertEqual(len(cross_origin), 0)

    def test_hidden_iframe_scores_15(self):
        html = "<html><body><iframe hidden src='https://evil.com/frame'></iframe></body></html>"
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        self.assertIn("hidden or tiny iframe", str(a.reasons))

    def test_obfuscation_patterns_score_20(self):
        html = (
            "<html><body><script>eval(atob('dGhpcyBpcyBvYmZ1c2NhdGVk'))</script></body></html>"
        )
        a = assess_content("http://test.local/page", html, _TEST_REPUTATION)
        self.assertIn("obfuscated", str(a.reasons))

    def test_brand_text_mismatch_scores_25(self):
        html = (
            "<html><head><title>PayPal Login</title></head>"
            "<body><h1>Welcome to PayPal</h1></body></html>"
        )
        a = assess_content("http://phishing.example.com", html, _TEST_REPUTATION)
        brand_reasons = [r for r in a.reasons if "PayPal" in r]
        self.assertTrue(len(brand_reasons) > 0, f"reasons: {a.reasons}")

    def test_non_html_content_skips(self):
        a = assess_content("http://test.local/file.pdf", "raw data not html", _TEST_REPUTATION)
        self.assertEqual(a.score, 0)

    def test_empty_html_safe(self):
        a = assess_content("http://test.local/page", "", _TEST_REPUTATION)
        self.assertEqual(a.verdict, "safe")


class TestMergeAssessments(unittest.TestCase):
    def test_safe_plus_safe_remains_safe(self):
        url = ThreatAssessment(score=10, verdict="safe", reasons=["r1"])
        content = ThreatAssessment(score=15, verdict="safe", reasons=["r2"])
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "safe")
        self.assertEqual(merged.score, 25)

    def test_safe_plus_suspicious_becomes_suspicious(self):
        url = ThreatAssessment(score=20, verdict="safe", reasons=["r1"])
        content = ThreatAssessment(score=20, verdict="safe", reasons=["r2"])
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "suspicious")
        self.assertEqual(merged.score, 40)

    def test_suspicious_plus_content_becomes_phishing(self):
        url = ThreatAssessment(score=30, verdict="safe", reasons=["r1"])
        content = ThreatAssessment(score=35, verdict="suspicious", reasons=["r2"])
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "phishing")
        self.assertEqual(merged.score, 65)

    def test_url_phishing_with_content_remains_phishing(self):
        url = ThreatAssessment(score=100, verdict="phishing", reasons=["blocked"])
        content = ThreatAssessment(score=0, verdict="safe", reasons=[])
        merged = merge_assessments(url, content)
        self.assertEqual(merged.verdict, "phishing")


class TestScoreVerdict(unittest.TestCase):
    def test_score_0_is_safe(self):
        self.assertEqual(_score_verdict(0), "safe")

    def test_score_30_is_safe(self):
        self.assertEqual(_score_verdict(30), "safe")

    def test_score_31_is_suspicious(self):
        self.assertEqual(_score_verdict(31), "suspicious")

    def test_score_60_is_suspicious(self):
        self.assertEqual(_score_verdict(60), "suspicious")

    def test_score_61_is_phishing(self):
        self.assertEqual(_score_verdict(61), "phishing")


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
        }))
        try:
            rep = load_reputation(user_path)
            self.assertIn("my-custom-evil.com", rep.blocked_domains)
            self.assertIn("custom-keyword", rep.suspicious_keywords)
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


class TestIPv4Detection(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(_is_ipv4("192.168.1.1"))
        self.assertTrue(_is_ipv4("127.0.0.1"))

    def test_invalid_ipv4(self):
        self.assertFalse(_is_ipv4("example.com"))
        self.assertFalse(_is_ipv4("256.1.1.1"))
        self.assertFalse(_is_ipv4("1.2.3"))


if __name__ == "__main__":
    unittest.main()
