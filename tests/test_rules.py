"""The rule table: every check on our list and every documented client limit has a row, every run case has its date,
record ref and report text, and a blocker row without a run case fails."""

import copy
import unittest

from docka_check import rules

# the checks on our list (2026-10-17)
T1_CHECKS = ["HDR2", "OAUTH-DISC", "F1-ROW", "UNTYPED", "REQ8", "CUT70", "ROWKEYS", "FREEFORM", "OUTSCHEMA",
             "F1-ROW-OTHER", "UNTYPED-OTHER", "DELETE-NOHINT", "SIZE", "SSE-ONLY", "TEMPLATED", "OAUTH-DISC-PARTIAL",
             "NO-DCR", "MS-DROP", "MS-CRASH", "MS-TRUNC", "MS-ENUM", "MS-COUNT"]

# each client's documented limits, as read on 2026-10-18: (client, the limit, the rule that carries it)
RESEARCH_S3 = [
    ("claude-api", "beta header, at most 20 servers, tools only, caller runs OAuth", "CLIENT-CONFIG"),
    ("claude-api", "one authorization_token, no headers", "HDR2"),
    ("claude-api", "streamable HTTP or SSE", "SSE-ONLY"),
    ("claude-api", "rejects anyOf/oneOf/allOf at the schema root", "ROOT-COMBINATOR"),
    ("claude-api", "JSON Schema draft 2020-12", "SCHEMA-DIALECT"),
    ("claude-ai", "OAuth via DCR or CIMD", "NO-DCR"),
    ("claude-ai", "redirect URI claude.ai/api/mcp/auth_callback", "DCR-REDIRECT"),
    ("claude-ai", "only the first authorization_servers entry", "AS-FIRST"),
    ("claude-ai", "up to four headers, custom names approved", "HDR2"),
    ("claude-ai", "streamable HTTP plus legacy SSE", "SSE-ONLY"),
    ("claude-ai", "results capped at about 150,000 characters", "RESULT-SIZE"),
    ("claude-ai", "240 s per tool call", "CALL-TIME"),
    ("claude-ai", "tool-count cap unverified", "CLIENT-CONFIG"),
    ("claude-ai", "#673 outputSchema tools rejected", "OUTSCHEMA-DECLARED"),
    ("claude-ai", "Desktop rejects draft-07", "SCHEMA-DIALECT"),
    ("claude-code", "stdio, HTTP, SSE; any headers plus headersHelper", "CLIENT-CONFIG"),
    ("claude-code", "OAuth via DCR, CIMD or pre-registered client", "NO-DCR"),
    ("claude-code", "redirect URI localhost:PORT/callback", "DCR-REDIRECT"),
    ("claude-code", "warns above 10,000 tokens, caps at 25,000", "RESULT-SIZE"),
    ("claude-code", "drops tools whose full name is over 128 characters", "NAME-128"),
    ("claude-code", "validates outputSchema", "RESULT-SCHEMA"),
    ("claude-code", "#88882 draft-07 rejected", "SCHEMA-DIALECT"),
    ("claude-code", "#95504 root allOf dropped", "ROOT-COMBINATOR"),
    ("openai-api", "one token plus a headers map, no OAuth", "HDR2"),
    ("openai-api", "streamable HTTP or SSE", "SSE-ONLY"),
    ("openai-api", "tool-count, output and strict-mode limits unverified", "CLIENT-CONFIG"),
    ("chatgpt", "SSE and streaming HTTP", "SSE-ONLY"),
    ("chatgpt", "OAuth or no auth only, no custom API keys", "API-KEY-ONLY"),
    ("chatgpt", "CIMD, DCR or a predefined client", "NO-DCR"),
    ("chatgpt", "PKCE S256", "PKCE-S256"),
    ("chatgpt", "redirect URI, or the callback form without RFC 9207 iss", "ISS-9207"),
    ("chatgpt", "tries every authorization_servers entry", "AS-FIRST"),
    ("chatgpt", "tools without readOnlyHint treated as writes", "NO-READONLYHINT"),
    ("chatgpt", "structuredContent must match outputSchema, enforcement unverified", "RESULT-SCHEMA"),
    ("copilot-studio", "streamable HTTP only, SSE dropped after August 2025", "SSE-ONLY"),
    ("copilot-studio", "none, one API key (header or query) or OAuth 2.0", "HDR2"),
    ("copilot-studio", "$ref inputs filtered out", "MS-DROP"),
    ("copilot-studio", "multi-type arrays truncated", "MS-TRUNC"),
    ("copilot-studio", "enums read as strings", "MS-ENUM"),
    ("copilot-studio", "integer exclusiveMinimum crashes", "MS-CRASH"),
]


class Table(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = rules.load()
        cls.ids = rules.by_id(cls.table)

    def test_table_holds_its_own_rules(self):
        self.assertEqual(rules.problems(self.table), [])

    def test_a_blocker_without_a_run_case_fails(self):
        t = copy.deepcopy(self.table)
        c = rules.by_id(t)["F1-ROW"]["per_client"]["copilot-studio"]
        c["cases"] = []
        self.assertTrue(any("blocker with no dated run case" in p for p in rules.problems(t)))
        c["evidence"] = "docs"
        self.assertTrue(any("blocker without run evidence" in p for p in rules.problems(t)))

    def test_every_t1_check_has_a_row(self):
        covered = set(self.ids)
        for r in self.table["rules"]:
            covered |= {x.strip() for x in (r.get("covers") or "").split(",")}
        self.assertEqual([c for c in T1_CHECKS if c not in covered], [])

    def test_every_research_limit_has_a_row_for_its_client(self):
        missing = [(cl, what, rid) for cl, what, rid in RESEARCH_S3
                   if rid not in self.ids or cl not in self.ids[rid]["per_client"]]
        self.assertEqual(missing, [])

    def test_the_known_failure_count_comes_from_the_table(self):
        n = len(rules.known_failures(self.table))
        self.assertGreater(n, 20)
        tiers = {r["tier"] for r in rules.known_failures(self.table)}
        self.assertIn("run-only", tiers)

    def test_disagreeing_sources_are_both_kept(self):
        note = self.ids["CUT70"]["per_client"]["copilot-studio"]["note"]
        self.assertIn("128", note)
        self.assertIn("282", " ".join(c["report"] for c in self.ids["CUT70"]["per_client"]["copilot-studio"]["cases"]))

    def test_passing_clients_are_never_findings(self):
        self.assertIsNone(rules.finding_label(self.ids["RESULT-SCHEMA"], "openai-api"))
        self.assertEqual(rules.finding_label(self.ids["RESULT-SCHEMA"], "claude-api"), "blocker")
        self.assertEqual(rules.finding_label(self.ids["RESULT-SCHEMA"], "claude-code"), "likely")
        self.assertIsNone(rules.finding_label(self.ids["RESULT-SCHEMA"], "chatgpt"))     # unconfirmed


if __name__ == "__main__":
    unittest.main()
