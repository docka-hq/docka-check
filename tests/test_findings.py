"""The coverage map's own rules: a skip outranks an empty hit list, a skip can be per client (and names the client),
and the first line's Found counts only known failures with a blocker, likely or advisory finding."""

import unittest

from docka_check import findings, rules

TABLE = rules.load()
HIT = [{"tool": None, "detail": "d"}]


def coverage(tier_result, rule, table=TABLE):
    return findings.evaluate(table, [tier_result])["coverage"][rule]


class Coverage(unittest.TestCase):
    def test_a_skip_outranks_an_empty_hit_list(self):
        cov = coverage({"tier": "signin", "hits": {"DCR-REDIRECT": []},
                        "skipped": {"DCR-REDIRECT": "needs --register"}}, "DCR-REDIRECT")
        self.assertEqual((cov["status"], cov["reason"]), ("not_checked", "needs --register"))
        self.assertEqual(set(cov["clients"].values()) - {"n/a"}, {"not_checked"})

    def test_an_empty_hit_list_alone_is_not_found(self):
        cov = coverage({"tier": "signin", "hits": {"DCR-REDIRECT": []}}, "DCR-REDIRECT")
        self.assertEqual(cov["status"], "not_found")

    def test_one_client_skipped(self):
        cov = coverage({"tier": "signin", "hits": {"DCR-REDIRECT": []}, "skipped_clients": {
            "DCR-REDIRECT": {"copilot-studio": "registration got no answer (HTTP 503)"}}}, "DCR-REDIRECT")
        self.assertEqual(cov["clients"]["copilot-studio"], "not_checked")
        self.assertEqual(cov["clients"]["claude-ai"], "not_found")
        self.assertEqual(cov["status"], "not_found")

    def test_every_client_skipped_is_not_checked_and_named(self):
        skip = {c: "no answer" for c in ("copilot-studio", "claude-ai", "chatgpt", "claude-code")}
        cov = coverage({"tier": "signin", "hits": {"DCR-REDIRECT": []}, "skipped_clients": {"DCR-REDIRECT": skip}},
                       "DCR-REDIRECT")
        self.assertEqual(cov["status"], "not_checked")
        self.assertEqual(cov["reason"], "Copilot Studio, claude.ai, Claude Code, ChatGPT: no answer")

    def test_a_hit_for_no_client_it_applies_to_is_not_found(self):
        cov = coverage({"tier": "signin", "hits": {"AS-FIRST": [{"tool": None, "clients": ["chatgpt"],
                                                                 "detail": "d"}]}}, "AS-FIRST")
        self.assertEqual(cov["status"], "not_found")


class FirstLine(unittest.TestCase):
    def test_found_counts_only_what_the_report_lists_as_findings(self):
        entry = lambda label: {"chatgpt": {"effect": "fails", "evidence": "run", "label": label,
                                           "behaviour_date": "2026-10-01"}}
        table = {"table_version": "t", "sources": {}, "rules": [
            {"id": "X-INFO", "tier": "signin", "known_failure": True, "title": "t", "fix": "f",
             "per_client": entry("info")},
            {"id": "X-BLOCKER", "tier": "signin", "known_failure": True, "title": "t", "fix": "f",
             "per_client": entry("blocker")}]}
        ev = findings.evaluate(table, [{"tier": "signin", "hits": {"X-INFO": HIT, "X-BLOCKER": HIT}}], ("chatgpt",))
        c = findings.counts(table, ev["coverage"])
        self.assertEqual((c["checked"], c["found"], c["found_rules_by_worst_label"]["blocker"]), (2, 1, 1))


if __name__ == "__main__":
    unittest.main()
