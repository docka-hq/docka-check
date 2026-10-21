"""Golden-file tests on the test server's cases, and a test that fails if any output contains PASS, "compatible",
"all green" or a score. Also: no report carries a file path or a credential.

    UPDATE_GOLDEN=1 python3 -m unittest tests.test_report      # rewrite the golden files after a deliberate change
"""

import json
import os
import re
import unittest
from pathlib import Path

from docka_check import calls, findings, report, rules, schema, signin
from testserver import shapes
from tests.test_signin import signin_kw

GOLDEN = Path(__file__).resolve().parent / "golden"
TABLE = rules.load()
# PASS is the verdict token (case-sensitive): evidence lines may say a job "passed" in one of our runs
BANNED = [(r"\bPASS\b", 0), (r"\bcompatible\b", re.I), (r"\ball green\b", re.I), (r"\bscore\b", re.I),
          (r"\bbadge\b", re.I), (r"\b\d{1,3}\s*/\s*100\b", 0), (r"\bgrade [A-F]\b", re.I)]
CALLS_CONFIG = {"calls": [{"tool": "get_deal", "arguments": {"deal_id": "1"}}, {"tool": "list_deals", "arguments": {}}],
                "promised_tools": ["get_deal", "list_deals"]}



def full_run(shape_set):
    """All three tiers on the test server, as `docka-check check --register --interactive` would run them."""
    srv = shapes.start(shape_set)
    try:
        tok = srv.mint_token()
        auth = {"Authorization": "Bearer " + tok}
        results = [signin.check_signin(srv.url, register=True, interactive=True, secrets_=[tok], **signin_kw())]
        from docka_check.mcp import Client
        from docka_check.net import Session
        c = Client(Session(["127.0.0.1"], secrets=[tok]), srv.url, auth)
        c.initialize()
        tools, _, _ = c.tools()
        results.append(schema.check_schema(tools, server_name="shapes"))
        results.append(calls.check_calls(srv.url, auth, CALLS_CONFIG))
        ev = findings.evaluate(TABLE, results)
        r = report.build(TABLE, {"url": srv.url}, results, ev, when="(time)")
        return r, tok, srv
    finally:
        srv.stop()


def normalise(text, srv):
    for base in (srv.world.mcp_base, srv.world.as_base):
        text = text.replace(base, "http://127.0.0.1:PORT")
    return re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:PORT", text)


SCENARIOS = {"clean": (), "failing": ("get403", "schema_copilot", "outschema_mismatch", "latin1")}
# "clean" = every shape off: its report shows only the info line about ChatGPT's redirect URI


class Golden(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runs = {name: full_run(s) for name, s in SCENARIOS.items()}

    def test_golden_markdown(self):
        GOLDEN.mkdir(exist_ok=True)
        for name, (r, tok, srv) in self.runs.items():
            text = normalise(report.markdown(r), srv)
            path = GOLDEN / f"{name}.md"
            if os.environ.get("UPDATE_GOLDEN") or not path.exists():
                path.write_text(text)
            self.assertEqual(text, path.read_text(), f"{name}: the report changed; UPDATE_GOLDEN=1 if on purpose")

    def test_no_verdict_words_in_any_format(self):
        for name, (r, tok, srv) in self.runs.items():
            for fmt, render in report.FORMATS.items():
                text = render(r)
                for pat, flags in BANNED:
                    self.assertIsNone(re.search(pat, text, flags), f"{name}/{fmt}: {pat}")

    def test_the_banned_word_test_bites(self):
        r, tok, srv = self.runs["clean"]
        text = report.markdown(r) + "\nAll checks PASS."
        self.assertTrue(any(re.search(p, text, f) for p, f in BANNED))

    def test_no_file_path_or_credential(self):
        for name, (r, tok, srv) in self.runs.items():
            for fmt, render in report.FORMATS.items():
                text = render(r).lower()
                self.assertIsNone(re.search(r"[\w./-]+\.(md|jsonl?)\b", text), f"{name}/{fmt} carries a file path")
                self.assertNotIn(tok.lower(), text)

    def test_first_line_counts_come_from_the_table(self):
        r, tok, srv = self.runs["clean"]
        self.assertEqual(r["counts"]["known_failures"], len(rules.known_failures(TABLE)))
        self.assertTrue(report.first_line(r).startswith(f"Checked {r['counts']['checked']} of {r['counts']['known_failures']}"))
        self.assertEqual(r["counts"]["found"], 0)

    def test_failing_scenario_finds_its_cases(self):
        r, tok, srv = self.runs["failing"]
        found = {(f["rule"], f["client"]) for f in r["findings"] if f["label"] == "blocker"}
        for case in [("OAUTH-DISC", "copilot-studio"), ("F1-ROW", "copilot-studio"), ("UNTYPED", "copilot-studio"),
                     ("REQ8", "copilot-studio"), ("RESULT-SCHEMA", "claude-api")]:
            self.assertIn(case, found)
        self.assertEqual(r["cells"]["signin/copilot-studio"], "found")
        self.assertEqual(r["cells"]["run-only/copilot-studio"], "not_checked")

    def test_last_agent_run_line(self):
        r, tok, srv = self.runs["clean"]
        self.assertIn("Last agent run: never", report.markdown(r))
        self.assertIn("Docka runs it", report.markdown(r))

    def test_every_rule_shows_somewhere(self):
        """Each rule is a finding, checked and not found, or in the not-checked list: none silently disappears."""
        r, tok, srv = self.runs["clean"]
        listed = {rid for ids in r["not_checked"].values() for rid in ids}
        found = {f["rule"] for f in r["findings"]}
        for rid in rules.by_id(TABLE):
            self.assertTrue(rid in listed or rid in found or rid in r["checked_rules"], rid)


if __name__ == "__main__":
    unittest.main()
