"""Unit tests for the CookieJar module."""

import time
import unittest
from browser.core.cookies import Cookie, CookieJar


class TestCookieMatching(unittest.TestCase):
    def setUp(self):
        self.jar = CookieJar()

    def test_simple_set_cookie_and_match(self):
        self.jar.store_from_set_cookie("session=abc", "example.local", "http", "/")
        matched = self.jar.matching_cookies("example.local", "http", "/")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].name, "session")
        self.assertEqual(matched[0].value, "abc")

    def test_host_only_cookie_matches_exact_domain(self):
        self.jar.store_from_set_cookie("a=1", "sub.example.local", "http", "/")
        self.assertEqual(len(self.jar.matching_cookies("sub.example.local", "http", "/")), 1)
        self.assertEqual(len(self.jar.matching_cookies("other.example.local", "http", "/")), 0)

    def test_domain_cookie_matches_subdomains(self):
        self.jar.store_from_set_cookie("a=1; Domain=.example.local", "sub.example.local", "http", "/")
        self.assertEqual(len(self.jar.matching_cookies("sub.example.local", "http", "/")), 1)
        self.assertEqual(len(self.jar.matching_cookies("other.example.local", "http", "/")), 1)
        self.assertEqual(len(self.jar.matching_cookies("example.local", "http", "/")), 1)

    def test_path_matching(self):
        self.jar.store_from_set_cookie("a=1; Path=/app", "example.local", "http", "/app")
        self.assertEqual(len(self.jar.matching_cookies("example.local", "http", "/app")), 1)
        self.assertEqual(len(self.jar.matching_cookies("example.local", "http", "/app/page")), 1)
        self.assertEqual(len(self.jar.matching_cookies("example.local", "http", "/other")), 0)

    def test_root_path_matches_everything(self):
        self.jar.store_from_set_cookie("a=1; Path=/", "example.local", "http", "/")
        self.assertEqual(len(self.jar.matching_cookies("example.local", "http", "/anything/here")), 1)

    def test_secure_cookie_https_only(self):
        self.jar.store_from_set_cookie("token=sec; Secure", "example.local", "https", "/")
        self.assertEqual(len(self.jar.matching_cookies("example.local", "https", "/")), 1)
        self.assertEqual(len(self.jar.matching_cookies("example.local", "http", "/")), 0)

    def test_request_cookie_header(self):
        self.jar.store_from_set_cookie("a=1", "example.local", "http", "/")
        self.jar.store_from_set_cookie("b=2", "example.local", "http", "/")
        header = self.jar.request_cookie_header("example.local", "http", "/")
        self.assertIsNotNone(header)
        self.assertIn("a=1", header)
        self.assertIn("b=2", header)


class TestCookieExpiry(unittest.TestCase):
    def test_max_age_zero_deletes_cookie(self):
        jar = CookieJar()
        jar.store_from_set_cookie("a=1", "example.local", "http", "/")
        self.assertEqual(len(jar), 1)
        jar.store_from_set_cookie("a=1; Max-Age=0", "example.local", "http", "/")
        self.assertEqual(len(jar), 0)
        self.assertIsNone(jar.request_cookie_header("example.local", "http", "/"))

    def test_expired_cookie_pruned(self):
        jar = CookieJar()
        jar.store_from_set_cookie("a=1; Max-Age=3600", "example.local", "http", "/")
        cookie = jar.cookie_list[0]
        cookie.expires_at = time.time() - 100
        matched = jar.matching_cookies("example.local", "http", "/")
        self.assertEqual(len(matched), 0)

    def test_prune_removes_expired(self):
        jar = CookieJar()
        jar.store_from_set_cookie("fresh=1; Max-Age=3600", "example.local", "http", "/")
        jar.store_from_set_cookie("stale=1; Max-Age=3600", "example.local", "http", "/")
        jar._cookies[1].expires_at = time.time() - 100
        jar.prune_expired()
        self.assertEqual(len(jar), 1)
        self.assertEqual(jar._cookies[0].name, "fresh")


class TestCookieStorage(unittest.TestCase):
    def test_store_overwrites_existing_by_name_domain_path(self):
        jar = CookieJar()
        jar.store_from_set_cookie("a=1", "example.local", "http", "/")
        jar.store_from_set_cookie("a=2", "example.local", "http", "/")
        self.assertEqual(len(jar), 1)
        self.assertEqual(jar.cookie_list[0].value, "2")

    def test_same_name_different_paths_both_stored(self):
        jar = CookieJar()
        jar.store_from_set_cookie("a=1; Path=/one", "example.local", "http", "/one")
        jar.store_from_set_cookie("a=2; Path=/two", "example.local", "http", "/two")
        self.assertEqual(len(jar), 2)

    def test_clear_removes_all(self):
        jar = CookieJar()
        jar.store_from_set_cookie("a=1", "example.local", "http", "/")
        jar.store_from_set_cookie("b=2", "example.local", "http", "/")
        jar.clear()
        self.assertEqual(len(jar), 0)


class TestLegacyMigration(unittest.TestCase):
    def test_old_format_migrates_to_structured(self):
        jar = CookieJar()
        jar.load_from_state({"cookies": {"example.local": {"a": "1", "b": "2"}}})
        self.assertEqual(len(jar), 2)
        cookies = jar.matching_cookies("example.local", "http", "/")
        self.assertEqual(len(cookies), 2)
        self.assertEqual({c.name: c.value for c in cookies}, {"a": "1", "b": "2"})
        self.assertTrue(all(c.host_only for c in cookies))

    def test_new_format_loads_directly(self):
        jar = CookieJar()
        jar.load_from_state({"cookies": [
            {"name": "a", "value": "1", "domain": "test.local", "host_only": False,
             "path": "/app", "secure": True, "http_only": True,
             "expires_at": None, "same_site": "Strict", "created_at": time.time()}
        ]})
        self.assertEqual(len(jar), 1)
        c = jar.cookie_list[0]
        self.assertEqual(c.domain, "test.local")
        self.assertFalse(c.host_only)
        self.assertEqual(c.path, "/app")
        self.assertTrue(c.secure)
        self.assertTrue(c.http_only)

    def test_mixed_both_formats_merged(self):
        jar = CookieJar()
        raw = {
            "cookies": [
                {"name": "a", "value": "1", "domain": "test.local", "host_only": True,
                 "path": "/", "secure": False, "http_only": False,
                 "expires_at": None, "same_site": "Lax", "created_at": time.time()},
                {"name": "b", "value": "2", "domain": "other.local", "host_only": True,
                 "path": "/", "secure": False, "http_only": False,
                 "expires_at": None, "same_site": "Lax", "created_at": time.time()},
            ]
        }
        jar.load_from_state(raw)
        self.assertEqual(len(jar), 2)


class TestSaveAndToDict(unittest.TestCase):
    def test_to_dict_includes_all_fields(self):
        jar = CookieJar()
        jar.store_from_set_cookie("a=1; Domain=.example.local; Path=/app; Secure; HttpOnly; SameSite=Strict",
                                  "example.local", "https", "/app")
        c = jar.cookie_list[0]
        d = c.to_dict()
        self.assertEqual(d["name"], "a")
        self.assertEqual(d["value"], "1")
        self.assertEqual(d["domain"], "example.local")
        self.assertEqual(d["host_only"], False)
        self.assertEqual(d["path"], "/app")
        self.assertTrue(d["secure"])
        self.assertTrue(d["http_only"])
        self.assertEqual(d["same_site"], "Strict")


if __name__ == "__main__":
    unittest.main()
