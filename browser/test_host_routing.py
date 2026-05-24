"""Tests for pure browser host-routing helpers."""

import unittest

from browser.core.host_routing import is_ipv4_address, should_use_custom_dns


class TestHostRouting(unittest.TestCase):
    def test_is_ipv4_address(self):
        self.assertTrue(is_ipv4_address("127.0.0.1"))
        self.assertFalse(is_ipv4_address("example.local"))

    def test_default_custom_dns_scope_matches_current_behavior(self):
        self.assertTrue(should_use_custom_dns("localhost"))
        self.assertTrue(should_use_custom_dns("example.local"))
        self.assertTrue(should_use_custom_dns("127.0.0.1"))
        self.assertFalse(should_use_custom_dns("example.com"))

    def test_force_all_hosts_routes_normal_domains_through_custom_dns(self):
        self.assertTrue(should_use_custom_dns("example.com", force_all_hosts=True))
        self.assertTrue(should_use_custom_dns("github.com", force_all_hosts=True))


if __name__ == "__main__":
    unittest.main()
