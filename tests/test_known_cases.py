"""Every known case is flagged for exactly the clients our evidence names, every fixed variant is clean, and
KNOWN_CASES.md lists each case with its evidence. No third-party server is called."""

import unittest
from pathlib import Path

from docka_check import calls, findings, rules, schema, signin
from docka_check.mcp import Client
from docka_check.net import Session
from testserver import cases, shapes
from tests.test_signin import signin_kw

TABLE = rules.load()
CALLS = {"calls": [{"tool": "get_deal", "arguments": {"deal_id": "1"}}, {"tool": "list_deals", "arguments": {}}]}
LABELS = ("blocker", "likely", "advisory")



def flagged(shape_set, opts, rule):
    srv = shapes.start(shape_set)
    try:
        tier = opts["tier"]
        if tier == "signin":
            res = signin.check_signin(srv.url, headers=opts.get("headers"), register=opts.get("register", False),
                                      interactive=opts.get("interactive", False), **signin_kw())
        else:
            auth = {"Authorization": "Bearer " + srv.mint_token()}
            if tier == "schema":
                c = Client(Session(["127.0.0.1"]), srv.url, auth)
                c.initialize()
                tools, _, _ = c.tools()
                res = schema.check_schema(tools)
            else:
                res = calls.check_calls(srv.url, auth, CALLS)
        hosts = {r["url"].split("/")[2] for r in res.get("requests", [])}
        assert all(h.startswith("127.0.0.1:") for h in hosts), hosts          # nothing but our own server
        ev = findings.evaluate(TABLE, [res])
        return {f["client"] for f in ev["findings"] if f["rule"] == rule and f["label"] in LABELS}
    finally:
        srv.stop()


class KnownCases(unittest.TestCase):
    def test_every_case_flags_exactly_its_clients(self):
        for shape, opts, rule, clients, fixed in cases.SERVER_CASES:
            with self.subTest(shape=shape, rule=rule):
                self.assertEqual(flagged({shape}, opts, rule), clients)

    def test_every_fixed_variant_is_clean(self):
        for shape, opts, rule, clients, fixed in cases.SERVER_CASES:
            # the fixed variant of a key-based server takes the client's one OAuth token: no extra headers
            fixed_opts = {k: v for k, v in opts.items() if k != "headers"}
            with self.subTest(shape=shape, rule=rule):
                self.assertEqual(flagged(set(fixed), fixed_opts, rule), set())

    def test_every_case_rule_is_in_the_table_with_those_clients(self):
        ids = rules.by_id(TABLE)
        for shape, opts, rule, clients, fixed in cases.SERVER_CASES:
            for c in clients:
                self.assertIsNotNone(rules.finding_label(ids[rule], c), (rule, c))

    def test_known_cases_file_is_current(self):
        path = Path(__file__).resolve().parents[1] / "KNOWN_CASES.md"
        self.assertEqual(path.read_text(), cases.markdown(), "run: python3 -m testserver.cases")


if __name__ == "__main__":
    unittest.main()
