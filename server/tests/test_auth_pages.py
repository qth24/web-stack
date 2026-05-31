"""Unit tests for the HTML auth pages."""

import unittest

from server.app.auth import render_auth_page


class TestAuthPages(unittest.TestCase):
    def test_login_page_contains_form_and_bridge_hook(self):
        response = render_auth_page("login", next_url="/welcome", error="Bad credentials")

        self.assertEqual(response.status_code, 200)
        body = response.body.decode("utf-8")
        self.assertIn('action="/auth/login"', body)
        self.assertIn('name="next" value="/welcome"', body)
        self.assertIn("submitAuth", body)
        self.assertIn("qrc:///qtwebchannel/qwebchannel.js", body)
        self.assertIn("Bad credentials", body)

    def test_register_page_contains_confirm_password_field(self):
        response = render_auth_page("register", next_url="/", values={"username": "demo"})

        self.assertEqual(response.status_code, 200)
        body = response.body.decode("utf-8")
        self.assertIn('action="/auth/register"', body)
        self.assertIn('name="confirm_password"', body)
        self.assertIn("Create Account", body)


if __name__ == "__main__":
    unittest.main()
