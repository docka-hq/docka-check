"""net: one count per server however its URL is spelled, and no credential in anything recorded, in any of the
forms an error message can give it."""

import json
import socket
import unittest

from docka_check.net import Budget, OutOfBudget, RateLimited, Session, scrub_deep, server_key


class Budgets(unittest.TestCase):
    def test_one_server_one_count(self):
        self.assertEqual(server_key("https://Example.com/mcp"), "example.com:443")
        self.assertEqual(server_key("https://example.com:443/other"), "example.com:443")
        self.assertEqual(server_key("http://example.com/x"), "example.com:80")
        b = Budget(per_host=1)
        b.take(server_key("https://Example.com/mcp"))
        with self.assertRaises(OutOfBudget):
            b.take(server_key("https://example.com:443/.well-known/oauth-protected-resource"))

    def test_a_429_stops_that_server_only(self):
        b = Budget()
        b.saw("a:443", 429)
        with self.assertRaises(RateLimited):
            b.take("a:443")
        b.take("b:443")


class Scrubbing(unittest.TestCase):
    def test_a_malformed_header_value_never_reaches_the_log(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        secret = "tok-1234567890\nX"                     # made up  # gitleaks:allow
        sess = Session(["127.0.0.1"], secrets=[secret])
        r = sess.request("GET", f"http://127.0.0.1:{port}/mcp", headers={"Authorization": "Bearer " + secret})
        self.assertIsNone(r.status)
        text = json.dumps(sess.log) + (r.error or "")
        self.assertNotIn("tok-1234567890", text)
        self.assertIn("[credential]", r.error)

    def test_deep(self):
        out = scrub_deep({"s3cr3t-value": ["a s3cr3t-value b", {"k": "x"}], "n": 1}, ["s3cr3t-value"])
        self.assertEqual(out, {"[credential]": ["a [credential] b", {"k": "x"}], "n": 1})


if __name__ == "__main__":
    unittest.main()
