"""diff: what a release changed, from two JSON reports, and the exit code: non-zero only on a new blocker with run
evidence. The two releases come from the test server's tools: monday's create_items as served on 2026-09-23 (row
fields required) and as fixed (no `required` inside the rows)."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from docka_check import diff, findings, report, rules, schema
from testserver.shapes import COPILOT_SHAPES

TABLE = rules.load()
REPO = Path(__file__).resolve().parents[1]
BEFORE = copy.deepcopy([t for t in COPILOT_SHAPES if t["name"] == "create_items"])
AFTER = copy.deepcopy(BEFORE)
del AFTER[0]["inputSchema"]["properties"]["items"]["items"]["required"]


def schema_report(tools):
    res = [schema.check_schema(tools, server_name="shapes")]
    return json.loads(report.as_json(report.build(TABLE, {"tools_file": "tools.json"}, res,
                                                  findings.evaluate(TABLE, res))))


class Release(unittest.TestCase):
    def test_the_fix_shows_as_a_blocker_removed(self):
        d = diff.compare(schema_report(BEFORE), schema_report(AFTER))
        gone = {(f["rule"], f["client"], f["tool"]) for f in d["removed"] if f["label"] == "blocker"}
        self.assertIn(("F1-ROW", "copilot-studio", "create_items"), gone)
        self.assertEqual(d["new_run_blockers"], [])
        text = "\n".join(diff.lines(d, report.CLIENT_NAMES))
        self.assertIn("Gone blocker: F1-ROW on `create_items` for Copilot Studio", text)

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = {}
            for k, tools in (("before", BEFORE), ("after", AFTER)):
                src = Path(tmp) / f"{k}.tools.json"
                src.write_text(json.dumps({"tools": tools}))
                out[k] = Path(tmp) / f"{k}.json"
                subprocess.run([sys.executable, "-m", "docka_check", "schema", "--tools-file", str(src),
                                "--server-name", "shapes", "--format", "json", "--out", str(out[k])],
                               cwd=REPO, check=True, capture_output=True)
            fixed = subprocess.run([sys.executable, "-m", "docka_check", "diff", str(out["before"]), str(out["after"])],
                                   cwd=REPO, capture_output=True, text=True)
            self.assertEqual(fixed.returncode, 0, fixed.stdout)
            regress = subprocess.run([sys.executable, "-m", "docka_check", "diff", str(out["after"]), str(out["before"])],
                                     cwd=REPO, capture_output=True, text=True)
            self.assertEqual(regress.returncode, 1)                 # the required row fields come back
            self.assertIn("New blocker: F1-ROW on `create_items` for Copilot Studio", regress.stdout)


class ExitRule(unittest.TestCase):
    def finding(self, label, evidence):
        return {"rule": "X", "client": "copilot-studio", "label": label, "evidence": evidence,
                "hits": [{"tool": "t"}], "says": None}

    def test_only_a_new_run_blocker_fails(self):
        for label, evidence, fails in (("blocker", "run", True), ("likely", "docs", False),
                                       ("advisory", "run", False), ("info", "docs", False)):
            d = diff.compare({"findings": []}, {"findings": [self.finding(label, evidence)]})
            self.assertEqual(bool(d["new_run_blockers"]), fails, label)


if __name__ == "__main__":
    unittest.main()
