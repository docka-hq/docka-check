"""The CLI's outside mode: on a server not verified as yours a run sends at most 5 requests to each server, says so in
the report, and leaves what it could not reach as "not checked"; on this machine the same check runs to the end.
Verification itself is tested in test_owner."""

import contextlib
import io
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from docka_check import cli
from testserver import shapes

OUTSIDE = {"DOCKA_CHECK_TRUST_LOOPBACK": "0"}     # treat the local test server as somebody else's


def setUpModule():
    """No stored key, no key in the environment, and Docka's API on a port where nothing listens."""
    global _home
    _home = tempfile.TemporaryDirectory()
    _patch.start()
    os.environ.update({"DOCKA_CHECK_HOME": _home.name, "DOCKA_CHECK_API": "http://127.0.0.1:9/api/check"})
    os.environ.pop("DOCKA_CHECK_KEY", None)


def tearDownModule():
    _patch.stop()
    _home.cleanup()


_patch = mock.patch.dict(os.environ)


def run_cli(shape_set, *flags, token=None, url=None):
    srv = shapes.start(shape_set)
    with tempfile.TemporaryDirectory() as d:
        md, js = Path(d) / "r.md", Path(d) / "r.json"
        try:
            if token is not None:
                token.append(srv.mint_token())
                os.environ["DOCKA_CHECK_TEST_TOKEN"] = token[0]
                flags += ("--token-env", "DOCKA_CHECK_TEST_TOKEN")
            code = cli.main(["check", "--url", url(srv.url) if url else srv.url, "--format", "md", "--out", str(md),
                             "--json-out", str(js), *flags])
        finally:
            srv.stop()
            os.environ.pop("DOCKA_CHECK_TEST_TOKEN", None)
        return code, md.read_text(), json.loads(js.read_text()), list(srv.world.log)


def not_checked_for(report, rule):
    return [reason for reason, ids in report["not_checked"].items() if rule in ids]


class OutsideMode(unittest.TestCase):
    def test_at_most_five_requests_per_server(self):
        with mock.patch.dict(os.environ, OUTSIDE):
            code, md, r, log = run_cli({"get403"})
        for role in ("mcp", "as"):
            self.assertLessEqual(sum(1 for x in log if x["role"] == role), 5, role)
        self.assertIn("Outside mode: this server is not verified as yours (no key for it)", md)
        self.assertIn("Nothing was sent to Docka", md)
        self.assertTrue(any("outside mode" in why for why in not_checked_for(r, "OAUTH-DISC")))
        self.assertNotIn("OAUTH-DISC", {f["rule"] for f in r["findings"]})

    def test_a_token_does_not_make_a_server_yours(self):
        with mock.patch.dict(os.environ, OUTSIDE):
            code, md, r, log = run_cli({"get403"}, token=[])
        self.assertLessEqual(sum(1 for x in log if x["role"] == "mcp"), 5)
        self.assertIn("Outside mode", md)
        self.assertTrue(any("verified as yours" in why for why in not_checked_for(r, "RESULT-SCHEMA")))

    def test_owner_only_flags_stop_before_any_request(self):
        for flags in (("--register",), ("--interactive",), ("--client-id", "c1"), ("--client-id", ""), ("--auto-read",),
                      ("--calls-config", "examples/calls.json")):
            srv = shapes.start(())
            try:
                with mock.patch.dict(os.environ, OUTSIDE), self.assertRaises(SystemExit) as e, \
                        contextlib.redirect_stderr(io.StringIO()) as err:
                    cli.main(["check", "--url", srv.url, *flags])
            finally:
                srv.stop()
            self.assertEqual(e.exception.code, 2, flags)
            self.assertIn(f"{flags[0]} needs a server verified as yours (no key for it)", err.getvalue())
            self.assertEqual(srv.world.log, [], flags)

    def test_a_server_on_this_machine_runs_to_the_end(self):
        code, md, r, log = run_cli({"get403"})
        self.assertGreater(sum(1 for x in log if x["role"] == "mcp"), 5)
        self.assertNotIn("Outside mode", md)
        self.assertNotIn("sent to Docka", md)
        self.assertIn(("OAUTH-DISC", "copilot-studio", "blocker"),
                      {(f["rule"], f["client"], f["label"]) for f in r["findings"]})

    def test_no_registration_without_register(self):
        code, md, r, log = run_cli(())
        self.assertEqual([x for x in log if x["path"] == "/register"], [])


class Credentials(unittest.TestCase):
    def test_a_token_the_server_echoes_never_reaches_the_report(self):
        tok = []
        code, md, r, log = run_cli({"echo_token"}, token=tok)
        self.assertNotIn(tok[0], md)
        self.assertNotIn(tok[0], json.dumps(r))
        self.assertIn("echo_[credential]", md)                  # the echoed tool is still reported, scrubbed

    def test_nor_does_one_in_the_baseline(self):
        """The baseline's text is added after the report is built: the scrub has to come after it."""
        tok = []
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "base.json"

            def baseline(t):
                base.write_text(json.dumps({"findings": [{"rule": "UNTYPED", "client": "copilot-studio",
                                                          "label": "blocker", "evidence": "run",
                                                          "hits": [{"tool": "echo_" + t}]}]}))
                return str(base)
            srv = shapes.start(())
            try:
                tok.append(srv.mint_token())
                os.environ["DOCKA_CHECK_TEST_TOKEN"] = tok[0]
                out = Path(d) / "r.md"
                cli.main(["check", "--url", srv.url, "--token-env", "DOCKA_CHECK_TEST_TOKEN", "--format", "md",
                          "--out", str(out), "--baseline", baseline(tok[0])])
            finally:
                srv.stop()
                os.environ.pop("DOCKA_CHECK_TEST_TOKEN", None)
            md = out.read_text()
        self.assertIn("Gone blocker: UNTYPED on `echo_[credential]`", md)
        self.assertNotIn(tok[0], md)


class UrlCredentials(unittest.TestCase):
    """A key written into the URL is used for the requests and never shown: user:pass@, ?api_key=…, a random path
    segment."""

    def test_what_a_report_shows_of_a_url(self):
        key = "Ab12Cd34Ef56Gh78Ij90"                            # made up  # gitleaks:allow
        shown, found = cli.url_parts(f"https://bob:{key}@mcp.example.com/s/{key}/mcp?api_key=short&page=2#{key}")
        self.assertEqual(shown, "https://[credential]@mcp.example.com/s/[credential]/mcp?api_key=[credential]&page=2")
        self.assertIn(key, found)
        self.assertIn("api_key=short&page=2", found)            # an echo of the whole query hides "short" too
        self.assertNotIn("short", found)                        # too short to scrub from every text

    def test_a_plain_url_shows_as_given(self):
        for url in ("http://127.0.0.1:8941/mcp", "https://mcp.example.com/v1/mcp?page=2",
                    "https://api.example.com/2026-10-17/mcp", "https://[::1]:8941/mcp"):
            self.assertEqual(cli.url_parts(url), (url, []))

    def test_a_key_in_the_query_is_used_and_never_shown(self):
        key = "k" + secrets.token_hex(12)
        code, md, r, log = run_cli((), url=lambda u: f"{u}?api_key={key}")
        self.assertGreater(r["counts"]["checked"], 0)          # the server answered: the URL was used as given
        self.assertIn("?api_key=[credential]", md)
        self.assertNotIn(key, md)
        self.assertNotIn(key, json.dumps(r))

    def test_nor_one_in_the_path_or_before_the_host(self):
        key = "k" + secrets.token_hex(12)
        for url in (lambda u: u.replace("/mcp", f"/s/{key}/mcp"), lambda u: u.replace("://", f"://bob:{key}@")):
            code, md, r, log = run_cli((), url=url)
            self.assertNotIn(key, md)
            self.assertNotIn(key, json.dumps(r))


class PartialToolList(unittest.TestCase):
    def test_schema_never_runs_on_a_partial_list(self):
        srv = shapes.start({"tools_endless"})
        try:
            tools, why = cli.fetch_tools(srv.url, {"Authorization": "Bearer " + srv.mint_token()}, [])
        finally:
            srv.stop()
        self.assertIsNone(tools)
        self.assertEqual(why, "tools/list has more than 20 pages")


if __name__ == "__main__":
    unittest.main()
