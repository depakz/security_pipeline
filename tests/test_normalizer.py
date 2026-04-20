import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.normalizer import normalize_endpoints


class TestSmartNormalizer(unittest.TestCase):
    def test_dedup_and_param_extraction(self):
        raw = [
            "https://example.com/api/users",
            "https://example.com/api/users/",
            "https://example.com/api/users?id=1",
            "https://example.com/api/users?id=2&foo=bar",
        ]

        eps = normalize_endpoints(raw, target="example.com")
        self.assertEqual(len(eps), 1)

        ep = eps[0]
        self.assertEqual(ep["url"], "/api/users")
        self.assertEqual(ep["method"], "GET")
        self.assertEqual(ep["params"], ["foo", "id"])
        self.assertIn("api", ep["tags"])
        self.assertIn("params", ep["tags"])

    def test_noise_filtering(self):
        raw = [
            "https://example.com/static/app.js",
            "https://example.com/images/logo.png",
            "https://example.com/fonts/inter.woff2",
            "https://example.com/api/user?id=1",
        ]

        eps = normalize_endpoints(raw, target="example.com")
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0]["url"], "/api/user")

    def test_tagging(self):
        raw = [
            "https://example.com/admin",
            "https://example.com/login",
            "https://example.com/api/search?q=test",
            "https://example.com/upload?file=abc",
        ]

        eps = {e["url"]: e for e in normalize_endpoints(raw, target="example.com")}

        self.assertIn("admin_panel", eps["/admin"]["tags"])
        self.assertIn("auth", eps["/login"]["tags"])

        self.assertIn("api", eps["/api/search"]["tags"])
        self.assertIn("params", eps["/api/search"]["tags"])

        self.assertIn("file", eps["/upload"]["tags"])
        self.assertIn("params", eps["/upload"]["tags"])

    def test_in_scope_filtering(self):
        raw = [
            "https://other.com/api/user?id=1",
            "/api/local?id=2",
        ]

        eps = normalize_endpoints(raw, target="example.com")
        urls = {e["url"] for e in eps}

        self.assertIn("/api/local", urls)
        self.assertNotIn("/api/user", urls)


if __name__ == "__main__":
    unittest.main()
