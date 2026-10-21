"""On the test server's shapes each known case is reported for the right clients and only for them, the Copilot path
matches the one we recorded on 2026-10-17 (tests/fixtures/wire/), and no request goes anywhere except the MCP host and
the auth host its document names. Everything runs against testserver/shapes.py on 127.0.0.1."""

import json
import socket
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from docka_check import findings, rules, signin
from testserver import shapes

TABLE = rules.load()
WIRE = Path(__file__).resolve().parent / "fixtures" / "wire" / "2026-10-17_copilot_signin_main.jsonl"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


class Owner:
    """The owner at the keyboard: approves at once in the browser (following the authorization server's redirect to
    the localhost callback), and answers the tool's question with what the page did."""

    def __init__(self):
        self.stuck = False

    def browser(self, url):
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            opener.open(url, timeout=5).read()
            self.stuck = True                    # a page that never redirects back (consent_broken)
            return
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            e.close()
        if loc and urlparse(loc).hostname in ("localhost", "127.0.0.1"):
            urllib.request.urlopen(loc.replace("localhost", "127.0.0.1"), timeout=5).read()

    def ask(self, question):
        return "y" if self.stuck else "n"


def signin_kw():
    owner = Owner()
    return {"open_browser": owner.browser, "ask": owner.ask, "callback_port": free_port(), "interactive_wait": 3}


def run(shape_set=(), **kw):
    srv = shapes.start(shape_set)
    try:
        res = signin.check_signin(srv.url, **{**signin_kw(), **kw})
        ev = findings.evaluate(TABLE, [res])
        return srv, res, ev
    finally:
        srv.stop()


def status(ev, rule):
    return ev["coverage"][rule]["status"]


def shown(ev, labels=("blocker", "likely")):
    return {(f["rule"], f["client"]) for f in ev["findings"] if f["label"] in labels}


class Shapes(unittest.TestCase):
    def test_clean_server_raises_nothing(self):
        srv, res, ev = run((), register=True, interactive=True)
        self.assertEqual(shown(ev), set())
        self.assertTrue(all(p["discovered"] for p in res["paths"].values()))

    def test_get403_is_copilot_only(self):
        srv, res, ev = run({"get403"})
        self.assertEqual({r for r, c in shown(ev) if r == "OAUTH-DISC"}, {"OAUTH-DISC"})
        self.assertEqual({c for r, c in shown(ev) if r == "OAUTH-DISC"}, {"copilot-studio"})
        for client in ("claude-ai", "chatgpt", "claude-code"):
            self.assertTrue(res["paths"][client]["discovered"], client)     # they read the 401 to POST

    def test_dcr_allowlist_is_copilot_only(self):
        srv, res, ev = run({"dcr_allowlist"}, register=True)
        self.assertEqual({c for r, c in shown(ev) if r == "DCR-REDIRECT"}, {"copilot-studio"})

    def test_scope_required(self):
        srv, res, ev = run({"scope_required"}, register=True)
        self.assertIn(("SCOPE-DEFAULT", "copilot-studio"), shown(ev))
        srv, res, ev = run((), register=True)
        self.assertNotIn(("SCOPE-DEFAULT", "copilot-studio"), shown(ev))

    def test_audience(self):
        srv, res, ev = run({"audience"}, register=True, interactive=True)
        self.assertIn(("TOKEN-AUDIENCE", "copilot-studio"), shown(ev))

    def test_consent_broken(self):
        srv, res, ev = run({"consent_broken"}, register=True, interactive=True)
        self.assertIn("CONSENT-PAGE", {r for r, c in shown(ev)})

    def test_consent_unconfirmed_is_not_a_finding(self):
        """Nothing came back and nobody says the page failed (CI, or a sign-in left unfinished): not checked."""
        srv, res, ev = run({"consent_broken"}, register=True, interactive=True, ask=lambda q: None)
        self.assertEqual(status(ev, "CONSENT-PAGE"), "not_checked")
        self.assertEqual(status(ev, "TOKEN-AUDIENCE"), "not_checked")

    def test_three_headers(self):
        srv, res, ev = run({"headers3"}, headers=dict(shapes.HEADER_KEYS))
        got = {c for r, c in shown(ev) if r == "HDR2"}
        self.assertEqual(got, {"claude-api", "copilot-studio", "chatgpt"})
        blockers = {(f["rule"], f["client"]) for f in ev["findings"] if f["label"] == "blocker"}
        self.assertIn(("HDR2", "claude-api"), blockers)                       # the Apideck case
        self.assertNotIn("openai-api", {c for r, c in shown(ev, ("blocker", "likely", "advisory"))})

    def test_one_key_no_oauth(self):
        srv, res, ev = run({"api_key_only"}, headers={"x-api-key": shapes.API_KEY})
        self.assertEqual({c for r, c in shown(ev) if r == "API-KEY-ONLY"}, {"chatgpt"})
        self.assertNotIn("HDR2", {r for r, c in shown(ev)})


class WithoutCredentials(unittest.TestCase):
    """An outside run gives no credentials. A server that refuses it without an OAuth challenge, or a URL where nothing
    serves MCP, leaves the credential rules not checked: never "not found"."""

    def test_an_apideck_shaped_server_is_not_cleared(self):
        srv, res, ev = run({"headers3"})
        for rule in ("HDR2", "API-KEY-ONLY"):
            self.assertEqual(status(ev, rule), "not_checked", rule)
            self.assertIn("pass the credentials it needs", ev["coverage"][rule]["reason"])

    def test_a_fixed_token_without_oauth_is_api_key_only(self):
        srv, res, ev = run({"api_key_only"}, token=True)
        self.assertEqual({c for r, c in shown(ev) if r == "API-KEY-ONLY"}, {"chatgpt"})
        self.assertEqual(status(ev, "HDR2"), "not_found")        # one credential: how many it needs is known

    def test_nothing_is_checked_where_nothing_serves_mcp(self):
        srv = shapes.start(())
        try:
            res = signin.check_signin(srv.url.replace("/mcp", "/nope"), **signin_kw())
        finally:
            srv.stop()
        cov = findings.evaluate(TABLE, [res])["coverage"]
        for rule in signin.SIGNIN_RULES:
            self.assertEqual(cov[rule]["status"], "not_checked", rule)
        self.assertIn("nothing serves MCP at this URL", cov["HDR2"]["reason"])


class Wire(unittest.TestCase):
    def test_copilot_path_matches_the_2026_10_17_record(self):
        recorded = [json.loads(x) for x in WIRE.read_text().splitlines()]
        first = [(r["role"], r["method"], r["path"]) for r in recorded[:3]]
        self.assertEqual(first, [("main", "GET", "/mcp"), ("main", "GET", "/.well-known/oauth-protected-resource/mcp"),
                                 ("as", "GET", "/.well-known/oauth-authorization-server")])
        srv, res, ev = run(())
        steps = res["paths"]["copilot-studio"]["steps"]
        self.assertEqual(steps[0]["step"], "protected-resource document (named by the 401 to GET)")
        self.assertTrue(steps[0]["url"].endswith("/.well-known/oauth-protected-resource/mcp"))
        self.assertEqual(steps[1]["step"], "authorization-server metadata")
        self.assertTrue(steps[1]["url"].endswith("/.well-known/oauth-authorization-server"))
        self.assertNotEqual(urlparse(steps[1]["url"]).port, urlparse(srv.url).port)    # the auth host, not the MCP host
        self.assertEqual(res["get"]["status"], 401)

    def test_copilot_fallback_urls_are_the_recorded_four(self):
        base = "https://mcp.example.com"
        self.assertEqual(signin.copilot_host_metadata_urls(base, "/v1/mcp"), [
            base + "/.well-known/oauth-authorization-server/v1/mcp", base + "/.well-known/oauth-authorization-server",
            base + "/.well-known/openid-configuration/v1/mcp", base + "/v1/mcp/.well-known/openid-configuration"])

    def test_only_the_mcp_host_and_its_auth_host(self):
        srv = shapes.start(())
        try:
            res = signin.check_signin(srv.url, register=True, interactive=True, **signin_kw())
            allowed = {urlparse(srv.url).netloc, urlparse(srv.world.as_base).netloc}
            self.assertEqual({urlparse(r["url"]).netloc for r in res["requests"]} - allowed, set())
            self.assertTrue(res["registered"] and all(r["deleted"] for r in res["registered"]))
        finally:
            srv.stop()

    def test_no_credential_in_the_record(self):
        srv, res, ev = run({"headers3"}, headers=dict(shapes.HEADER_KEYS))
        text = json.dumps(res)
        for v in shapes.HEADER_KEYS.values():
            self.assertNotIn(f'"{v}"', text)


class NoAnswer(unittest.TestCase):
    """A step that got no answer concludes nothing: "not checked" with the reason, never "not found", never a finding."""

    def test_steps_not_taken_are_not_checked(self):
        srv, res, ev = run(())                                     # no --register, no --interactive
        for rule in ("DCR-REDIRECT", "SCOPE-DEFAULT", "TOKEN-AUDIENCE", "CONSENT-PAGE"):
            self.assertEqual(status(ev, rule), "not_checked", rule)
        self.assertEqual(status(ev, "OAUTH-DISC"), "not_found")

    def test_unreachable_server(self):
        url = f"http://127.0.0.1:{free_port()}/mcp"                # nothing listens there
        res = signin.check_signin(url, **signin_kw())
        ev = findings.evaluate(TABLE, [res])
        self.assertEqual(ev["findings"], [])
        for rule in signin.SIGNIN_RULES:
            self.assertEqual(status(ev, rule), "not_checked", rule)

    def test_503_on_the_documents(self):
        srv, res, ev = run({"get403", "wellknown_503"})
        self.assertNotIn("OAUTH-DISC", {r for r, c in shown(ev)})
        self.assertEqual(status(ev, "OAUTH-DISC"), "not_checked")
        self.assertIn("HTTP 503", ev["coverage"]["OAUTH-DISC"]["reason"])

    def test_429_stops_every_request_to_that_server(self):
        srv, res, ev = run({"get403", "wellknown_429"})
        mcp = urlparse(srv.url).netloc
        sent = [r for r in res["requests"] if urlparse(r["url"]).netloc == mcp]
        first = next(i for i, r in enumerate(sent) if r["status"] == 429)
        self.assertEqual(sent[first + 1:], [])
        self.assertEqual(status(ev, "OAUTH-DISC"), "not_checked")
        self.assertIn("429", ev["coverage"]["OAUTH-DISC"]["reason"])

    def test_endpoints_on_another_host(self):
        """The authorization server's own metadata names its endpoints elsewhere: followed, and nothing crashes."""
        srv, res, ev = run({"endpoints_elsewhere"}, register=True, interactive=True)
        self.assertIn(f"localhost:{urlparse(srv.world.as_base).port}", {urlparse(r["url"]).netloc for r in res["requests"]})
        for rule in ("DCR-REDIRECT", "SCOPE-DEFAULT", "TOKEN-AUDIENCE", "CONSENT-PAGE"):
            self.assertEqual(status(ev, rule), "not_found", rule)

    def test_a_503_before_the_metadata_that_answered(self):
        """8414 answers 503, OIDC answers 200: no client's behaviour on that 503 is recorded, so nothing is concluded."""
        srv, res, ev = run({"as_8414_503"})
        self.assertEqual(status(ev, "OAUTH-DISC"), "not_checked")
        self.assertEqual(status(ev, "NO-DCR"), "not_checked")

    def test_a_skipped_client_is_named(self):
        srv, res, ev = run({"get403"}, register=True, interactive=True)      # Copilot finds no metadata
        self.assertEqual(status(ev, "SCOPE-DEFAULT"), "not_checked")
        self.assertTrue(ev["coverage"]["SCOPE-DEFAULT"]["reason"].startswith("Copilot Studio: "))


if __name__ == "__main__":
    unittest.main()
