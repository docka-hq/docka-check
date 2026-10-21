"""The calls tier on the test server: a result that breaks its own outputSchema is flagged for Anthropic's connector
and Claude Code and not for OpenAI or Copilot, Latin-1 bytes and an oversized result are flagged, and nothing outside
the owner's list (or the --auto-read rule) is ever called."""

import json
import unittest

from docka_check import calls, findings, rules
from testserver import shapes

TABLE = rules.load()
CONFIG = {"calls": [{"tool": "get_deal", "arguments": {"deal_id": "1"}}, {"tool": "list_deals", "arguments": {}}]}


def run(shape_set=(), config=CONFIG, **kw):
    srv = shapes.start(shape_set)
    try:
        tok = srv.mint_token()
        res = calls.check_calls(srv.url, {"Authorization": "Bearer " + tok}, config, **kw)
        called = [x for x in srv.world.log if x["method"] == "POST"]
        return res, findings.evaluate(TABLE, [res]), srv, tok
    finally:
        srv.stop()


def flagged(ev, rule):
    return {(f["client"], f["label"]) for f in ev["findings"] if f["rule"] == rule}


class TestServerShapes(unittest.TestCase):
    def test_clean_server_raises_nothing(self):
        res, ev, srv, tok = run(())
        self.assertEqual([f for f in ev["findings"] if f["label"] in ("blocker", "likely")], [])
        self.assertEqual({c["tool"] for c in res["calls"] if c.get("called")}, {"get_deal", "list_deals"})

    def test_outschema_mismatch(self):
        res, ev, srv, tok = run({"outschema_mismatch"})
        self.assertEqual(flagged(ev, "RESULT-SCHEMA"), {("claude-api", "blocker"), ("claude-code", "likely")})
        res, ev, srv, tok = run({"outschema_ok"})                  # the fixed variant
        self.assertEqual(flagged(ev, "RESULT-SCHEMA"), set())

    def test_latin1_bytes(self):
        res, ev, srv, tok = run({"latin1"})
        self.assertEqual(flagged(ev, "RESULT-UTF8"), {("openai-api", "advisory")})

    def test_oversized_result(self):
        res, ev, srv, tok = run({"big_result"})
        self.assertEqual(flagged(ev, "RESULT-SIZE"), {("claude-code", "likely")})

    def test_dropped_mcp_headers(self):
        res, ev, srv, tok = run({"drop_mcp_headers"})
        self.assertEqual(flagged(ev, "PROTOCOL-OPENING"), {("openai-api", "advisory")})
        res, ev, srv, tok = run(())
        self.assertEqual(flagged(ev, "PROTOCOL-OPENING"), set())

    def test_promised_tool_missing(self):
        res, ev, srv, tok = run((), {**CONFIG, "promised_tools": ["update_deal", "get_deal"]})
        got = [h["tool"] for h in res["hits"]["MISSING-PROMISED-TOOL"]]
        self.assertEqual(got, ["update_deal"])


class NothingElseIsCalled(unittest.TestCase):
    def test_only_the_owners_list(self):
        srv = shapes.start({"schema_copilot"})
        try:
            calls.check_calls(srv.url, {"Authorization": "Bearer " + srv.mint_token()},
                              {"calls": [{"tool": "get_deal", "arguments": {"deal_id": "1"}}]})
        finally:
            srv.stop()
        self.assertEqual(self._called(srv), ["get_deal"])

    def test_auto_read_adds_only_read_only_tools_without_required_input(self):
        srv = shapes.start({"schema_copilot"})
        try:
            res = calls.check_calls(srv.url, {"Authorization": "Bearer " + srv.mint_token()}, {}, auto_read=True)
        finally:
            srv.stop()
        # list_deals: readOnlyHint true, nothing required. get_deal and search need inputs; writes never.
        self.assertEqual(self._called(srv), ["list_deals"])
        self.assertEqual([p["tool"] for p in res["plan"]], ["list_deals"])

    @staticmethod
    def _called(srv):
        return [r["tool"] for r in srv.world.calls]


class NoCredentialsInTheRecord(unittest.TestCase):
    def test_token_scrubbed(self):
        res, ev, srv, tok = run(())
        self.assertNotIn(tok, json.dumps(res))


class NoAnswer(unittest.TestCase):
    """A call that got no result concludes nothing about results; a call still unanswered past claude.ai's limit is
    a CALL-TIME finding. The limits are shrunk here so the test takes seconds, not minutes."""

    def setUp(self):
        self.saved = calls.CLAUDE_AI_SECONDS, calls.CALL_MARGIN_S, shapes.SLOW_S
        calls.CLAUDE_AI_SECONDS, shapes.SLOW_S = 1, 3

    def tearDown(self):
        calls.CLAUDE_AI_SECONDS, calls.CALL_MARGIN_S, shapes.SLOW_S = self.saved

    def status(self, ev, rule):
        return ev["coverage"][rule]["status"]

    def test_unanswered_past_the_limit_is_call_time(self):
        calls.CALL_MARGIN_S = 1                                    # give up at 2 s; get_deal answers at 3 s
        res, ev, srv, tok = run({"call_slow"})
        self.assertEqual(flagged(ev, "CALL-TIME"), {("claude-ai", "likely")})
        self.assertIn("no answer within", res["hits"]["CALL-TIME"][0]["detail"])
        self.assertEqual(self.status(ev, "RESULT-SIZE"), "not_found")       # list_deals answered: checked on it

    def test_answered_late_is_call_time(self):
        calls.CALL_MARGIN_S = 10
        res, ev, srv, tok = run({"call_slow"})
        self.assertEqual(flagged(ev, "CALL-TIME"), {("claude-ai", "likely")})
        self.assertNotIn("no answer", res["hits"]["CALL-TIME"][0]["detail"])

    def test_no_result_concludes_nothing(self):
        res, ev, srv, tok = run({"call_error"})
        self.assertEqual(ev["findings"], [])
        for rule in calls.RESULT_RULES + ("CALL-TIME",):
            self.assertEqual(self.status(ev, rule), "not_checked", rule)
            self.assertIn("no call returned a result", ev["coverage"][rule]["reason"])

    def test_unreachable_server(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        res = calls.check_calls(f"http://127.0.0.1:{port}/mcp", {}, CONFIG)
        ev = findings.evaluate(TABLE, [res])
        self.assertEqual(ev["findings"], [])
        for rule in calls.CALLS_RULES:
            self.assertEqual(self.status(ev, rule), "not_checked", rule)


if __name__ == "__main__":
    unittest.main()
