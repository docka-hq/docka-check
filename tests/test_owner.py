"""A full run needs a server verified as yours, and a verified run sends its report to Docka. Docka's API runs
here in-process (server/verify_api.py) and the MCP server is our own test server, so nothing leaves this machine.
DOCKA_CHECK_TRUST_LOOPBACK=0 makes the local test server count as somebody else's."""

import contextlib
import http.client
import io
import json
import os
import secrets
import stat
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from docka_check import cli, owner
from testserver import shapes

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
import verify_api as api  # noqa: E402

EMAIL = "owner@example.com"


class Docka:
    """verify_api on a free port, with its state in a temp folder and http/loopback servers allowed."""

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = [mock.patch.multiple(api, STATE=self.tmp.name, ALLOW_PRIVATE=True, DRY=True,
                                            log=lambda *a: None),
                        mock.patch.dict(api._issued, clear=True), mock.patch.dict(api._keys, clear=True),
                        mock.patch.dict(api._hits, clear=True)]
        for p in self.patches:
            p.start()
        self.server = api.serve(port=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/api/check"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def reports(self):
        return [json.loads(f.read_text()) for f in sorted(Path(self.tmp.name).glob("reports/*/*.json"))]

    def events(self):
        path = Path(self.tmp.name) / "events.jsonl"
        return path.read_text() if path.exists() else ""


class OwnerCase(unittest.TestCase):
    def setUp(self):
        self.docka = Docka().__enter__()
        self.home = tempfile.TemporaryDirectory()
        env = mock.patch.dict(os.environ, {"DOCKA_CHECK_TRUST_LOOPBACK": "0", "DOCKA_CHECK_HOME": self.home.name,
                                           "DOCKA_CHECK_API": self.docka.base})
        env.start()
        os.environ.pop("DOCKA_CHECK_KEY", None)
        self.addCleanup(env.stop)
        self.addCleanup(self.home.cleanup)
        self.addCleanup(self.docka.__exit__)
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.stop()

    def server(self, shape_set=()):
        srv = shapes.start(shape_set)
        self.servers.append(srv)
        return srv

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def verify(self, srv):
        """Both steps of docka-check verify, as an owner does them: get the token, serve it, run verify again."""
        code, out, _ = self.cli("verify", "--url", srv.url, "--email", EMAIL)
        self.assertEqual(code, 1)
        token = owner._store()["pending"][owner.origin(srv.url)]["token"]
        self.assertIn(token, out)
        srv.world.verify_token = token
        code, out, _ = self.cli("verify", "--url", srv.url)
        self.assertEqual(code, 0, out)
        return owner.stored_key(srv.url)

    def check(self, srv, *flags, url=None):
        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "r.md"
            code, out, err = self.cli("check", "--url", url or srv.url, "--format", "md", "--out", str(md), *flags)
            return md.read_text(), err


class Verify(OwnerCase):
    def test_unverified_server_gets_an_outside_run_and_nothing_is_sent(self):
        srv = self.server({"get403"})
        md, err = self.check(srv)
        self.assertIn("Outside mode: this server is not verified as yours (no key for it)", md)
        self.assertLessEqual(sum(1 for x in srv.world.log if x["role"] == "mcp"), 5)
        self.assertEqual(self.docka.reports(), [])
        self.assertEqual(self.docka.events(), "")               # not even a key check: there was no key

    def test_verify_then_a_full_run_sends_one_report_without_credentials(self):
        srv = self.server({"get403"})
        key = self.verify(srv)
        self.assertTrue(key.startswith("dck_"))
        self.assertEqual(stat.S_IMODE((Path(self.home.name) / "keys.json").stat().st_mode), 0o600)
        mcp_token, url_key = srv.mint_token(), "k" + secrets.token_hex(12)
        os.environ["DOCKA_CHECK_TEST_TOKEN"] = mcp_token
        self.addCleanup(os.environ.pop, "DOCKA_CHECK_TEST_TOKEN", None)
        md, err = self.check(srv, "--token-env", "DOCKA_CHECK_TEST_TOKEN", url=f"{srv.url}?api_key={url_key}")
        self.assertIn(cli.VERIFIED_MODE, md)
        self.assertGreater(sum(1 for x in srv.world.log if x["role"] == "mcp"), 5)
        self.assertIn("report sent to Docka (verified owner)", err)
        self.assertNotIn(srv.world.mcp_base, err)                # CI logs never name the server
        [stored] = self.docka.reports()
        self.assertEqual((stored["origin"], stored["email"]), (owner.origin(srv.url), EMAIL))
        self.assertEqual(stored["report"]["target"]["url"], f"{srv.url}?api_key=[credential]")
        blob = json.dumps(stored)
        for secret in (mcp_token, url_key, key):
            self.assertNotIn(secret, blob)

    def test_docka_keeps_hashes_never_the_token_claim_or_key(self):
        srv = self.server()
        key = self.verify(srv)
        p = owner._store()
        self.assertEqual(p["pending"], {})
        events = self.docka.events()
        self.assertIn('"type": "verified"', events)
        self.assertNotIn(key, events)
        self.assertNotIn(srv.world.verify_token, events)
        self.assertNotIn("/mcp", events)                         # the origin only, never the path

    def test_the_key_command_prints_the_key_and_nothing_else(self):
        srv = self.server()
        key = self.verify(srv)
        code, out, err = self.cli("key", "--url", srv.url)
        self.assertEqual((code, out), (0, key + "\n"))

    def test_a_server_on_this_machine_needs_no_verification(self):
        srv = self.server()
        with mock.patch.dict(os.environ, {"DOCKA_CHECK_TRUST_LOOPBACK": "1"}):
            code, out, err = self.cli("verify", "--url", srv.url, "--email", EMAIL)
        self.assertEqual(code, 0)
        self.assertIn("need no verification", out)
        self.assertEqual(self.docka.events(), "")


class Keys(OwnerCase):
    def test_a_made_up_key_is_an_outside_run(self):
        srv = self.server()
        with mock.patch.dict(os.environ, {"DOCKA_CHECK_KEY": "dck_" + secrets.token_urlsafe(32)}):
            md, err = self.check(srv)
        self.assertIn("(DOCKA_CHECK_KEY was not accepted: Docka issued no such key)", md)
        self.assertEqual(self.docka.reports(), [])

    def test_a_key_for_another_server_is_an_outside_run_and_cannot_upload(self):
        a, b = self.server(), self.server()
        key_a = self.verify(a)
        with mock.patch.dict(os.environ, {"DOCKA_CHECK_KEY": key_a}):
            md, err = self.check(b)
            self.assertIn("this key is for another server", md)
            md, err = self.check(a)
            self.assertIn(cli.VERIFIED_MODE, md)                 # the same key from the environment, on its server
        status, body = owner._post("/report", {"origin": owner.origin(b.url), "report": {}}, key=key_a)
        self.assertEqual(status, 403)
        self.assertEqual(len(self.docka.reports()), 1)

    def test_when_docka_cannot_be_reached_the_run_is_an_outside_run(self):
        srv = self.server()
        self.verify(srv)
        with mock.patch.dict(os.environ, {"DOCKA_CHECK_API": "http://127.0.0.1:9/api/check"}):
            md, err = self.check(srv)
            self.assertIn("the stored key was not accepted: Docka could not be reached", md)
            self.assertIn("not sent", owner.upload(srv.url, "dck_x", {}))

    def test_owner_flags_work_once_verified(self):
        srv = self.server()
        self.verify(srv)
        md, err = self.check(srv, "--register")
        self.assertTrue(any(x["path"] == "/register" for x in srv.world.log))


class Confirm(OwnerCase):
    def start(self, srv):
        status, b = owner._post("/verify/start", {"url": owner.origin(srv.url), "email": EMAIL})
        self.assertEqual(status, 200)
        return b

    def confirm(self, srv, token, claim):
        return owner._post("/verify/confirm", {"url": owner.origin(srv.url), "token": token, "claim": claim})

    def test_a_reader_of_the_file_cannot_take_the_key(self):
        srv = self.server()
        b = self.start(srv)
        srv.world.verify_token = b["token"]
        self.assertEqual(self.confirm(srv, b["token"], "")[0], 403)
        self.assertEqual(self.confirm(srv, b["token"], secrets.token_urlsafe(32))[0], 403)
        status, ok = self.confirm(srv, b["token"], b["claim"])
        self.assertEqual(status, 200)
        self.assertEqual(ok["origin"], owner.origin(srv.url))

    def test_no_key_until_the_file_holds_the_token(self):
        srv = self.server()
        b = self.start(srv)
        status, body = self.confirm(srv, b["token"], b["claim"])
        self.assertEqual((status, body["detail"]), (409, f"{owner.origin(srv.url)}{api.FILE_PATH} answered HTTP 404"))
        srv.world.verify_token = "docka-verify-" + secrets.token_hex(16)
        status, body = self.confirm(srv, b["token"], b["claim"])
        self.assertEqual(status, 409)
        self.assertIn("without the token", body["detail"])

    def test_a_token_is_bound_to_its_server(self):
        a, other = self.server(), self.server()
        b = self.start(a)
        other.world.verify_token = b["token"]
        status, body = self.confirm(other, b["token"], b["claim"])
        self.assertEqual(status, 400)

    def test_a_redirect_is_not_followed(self):
        srv = self.server()
        b = self.start(srv)
        target = shapes.start(())
        self.servers.append(target)
        target.world.verify_token = b["token"]

        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", target.world.mcp_base + api.FILE_PATH)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        with ThreadingHTTPServer(("127.0.0.1", 0), Redirect) as hop:
            threading.Thread(target=hop.serve_forever, daemon=True).start()
            status, text = api.fetch_file(f"http://127.0.0.1:{hop.server_address[1]}")
            hop.shutdown()
        self.assertEqual(status, 302)


class Guards(unittest.TestCase):
    """The file fetch is the one request Docka's API makes to the outside: https only, public addresses only."""

    def test_what_counts_as_an_origin(self):
        self.assertIsNone(api.origin_of("http://mcp.example.com/mcp"))
        self.assertIsNone(api.origin_of("https://bob:pw@mcp.example.com/mcp"))
        self.assertIsNone(api.origin_of("ftp://mcp.example.com"))
        self.assertEqual(api.origin_of("https://MCP.example.com:443/mcp?x=1"), "https://mcp.example.com")
        self.assertEqual(api.origin_of("https://mcp.example.com:8443/mcp"), "https://mcp.example.com:8443")
        for url in ("https://MCP.example.com:443/mcp?x=1", "https://mcp.example.com:8443/mcp", "https://[::1]:9/mcp"):
            self.assertEqual(owner.origin(url), api.origin_of(url), url)

    def test_private_and_loopback_addresses_are_refused(self):
        for host in ("127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "::1", "fd00::1", "0.0.0.0",
                     "localhost"):
            self.assertIsNone(api.public_ip(host, 443), host)
        self.assertEqual(api.fetch_file("https://127.0.0.1")[0], None)

    def test_rate_limit(self):
        with mock.patch.dict(api._hits, clear=True):
            self.assertEqual([api.limited("t", "ip", (2, 60)) for _ in range(3)], [False, False, True])

    def test_a_report_over_the_limit_is_413_and_never_read(self):
        with Docka() as d:
            key = "dck_" + secrets.token_urlsafe(32)
            api._keys[api.sha(key)] = {"origin": "http://127.0.0.1:1", "email": EMAIL, "key_sha256": api.sha(key)}
            conn = http.client.HTTPConnection("127.0.0.1", d.server.server_address[1], timeout=5)
            conn.putrequest("POST", "/api/check/report")
            conn.putheader("Authorization", "Bearer " + key)
            conn.putheader("Content-Length", str(api.MAX_REPORT + 1))
            conn.endheaders()                                     # headers only: the body never comes
            self.assertEqual(conn.getresponse().status, 413)
            conn.close()

    def test_the_tool_does_not_send_a_report_over_the_limit(self):
        line = owner.upload("https://mcp.example.com/mcp", "dck_x", {"x": "y" * owner.MAX_REPORT})
        self.assertIn("over 1 MB, so it was not sent", line)
        self.assertEqual(owner.MAX_REPORT, api.MAX_REPORT)


if __name__ == "__main__":
    unittest.main()
