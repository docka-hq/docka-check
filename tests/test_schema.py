"""The schema tier: each per-client rule on a minimal schema, through the entry point the CLI uses. The Copilot
shapes themselves (F1-ROW, UNTYPED, REQ8) run on the test server in tests/test_known_cases.py."""

import unittest

from docka_check import findings, rules, schema

TABLE = rules.load()


def found(tools, client="copilot-studio", server="server"):
    """{(rule, label): set of tools} for one client, through the new entry point."""
    ev = findings.evaluate(TABLE, [schema.check_schema(tools, server_name=server)])
    out = {}
    for f in ev["findings"]:
        if f["client"] == client:
            out.setdefault((f["rule"], f["label"]), set()).update(h["tool"] for h in f["hits"] if h["tool"])
    return out


def blocker_tools(tools, client="copilot-studio"):
    return {t for (rule, label), ts in found(tools, client).items() if label == "blocker" for t in ts}


def tool(name="t", props=None, required=None, **extra):
    s = {"type": "object", "properties": props or {}}
    if required:
        s["required"] = required
    return {"name": name, "inputSchema": s, **extra}


class NewClientRules(unittest.TestCase):
    """One minimal schema per rule beyond the Copilot shape checks in docka_check/t5/."""

    def labels(self, tools, server="server"):
        ev = findings.evaluate(TABLE, [schema.check_schema(tools, server_name=server)])
        return {(f["rule"], f["client"], f["label"]) for f in ev["findings"]}

    def test_root_combinator(self):
        t = {"name": "pick", "inputSchema": {"anyOf": [{"type": "object"}, {"type": "object"}]},
             "annotations": {"readOnlyHint": True}}
        got = self.labels([t])
        self.assertIn(("ROOT-COMBINATOR", "claude-api", "likely"), got)
        self.assertNotIn(("ROOT-COMBINATOR", "claude-code", "likely"), got)     # Claude Code's issue: allOf only
        t2 = {"name": "both", "inputSchema": {"allOf": [{"type": "object"}]}, "annotations": {"readOnlyHint": True}}
        self.assertIn(("ROOT-COMBINATOR", "claude-code", "likely"), self.labels([t2]))

    def test_schema_dialect(self):
        t = tool(annotations={"readOnlyHint": True})
        t["inputSchema"]["$schema"] = "http://json-schema.org/draft-07/schema#"
        got = self.labels([t])
        self.assertIn(("SCHEMA-DIALECT", "claude-code", "likely"), got)
        self.assertIn(("SCHEMA-DIALECT", "claude-ai", "likely"), got)
        self.assertFalse([g for g in got if g[0] == "SCHEMA-DIALECT" and g[1] == "claude-api"])
        t["inputSchema"]["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        self.assertFalse([g for g in self.labels([t]) if g[0] == "SCHEMA-DIALECT"])

    def test_name_128(self):
        long = tool(name="x" * 120, annotations={"readOnlyHint": True})
        self.assertIn(("NAME-128", "claude-code", "likely"), self.labels([long], server="acme"))
        short = tool(name="get_deal", annotations={"readOnlyHint": True})
        self.assertFalse([g for g in self.labels([short], server="acme") if g[0] == "NAME-128"])

    def test_outschema_declared(self):
        t = tool(annotations={"readOnlyHint": True}, outputSchema={"type": "object"})
        got = self.labels([t])
        self.assertIn(("OUTSCHEMA-DECLARED", "claude-ai", "likely"), got)
        self.assertIn(("OUTSCHEMA-DECLARED", "claude-api", "advisory"), got)
        self.assertFalse([g for g in got if g[0] == "OUTSCHEMA-DECLARED" and g[1] in ("openai-api", "copilot-studio")])

    def test_no_readonlyhint(self):
        self.assertIn(("NO-READONLYHINT", "chatgpt", "advisory"), self.labels([tool()]))
        self.assertFalse([g for g in self.labels([tool(annotations={"readOnlyHint": True})])
                          if g[0] == "NO-READONLYHINT"])

    def test_size(self):
        big = [tool(name=f"t{i}", props={"p": {"type": "string", "description": "x" * 2100}},
                    annotations={"readOnlyHint": True}) for i in range(100)]
        got = self.labels(big)
        self.assertIn(("SIZE", "claude-api", "advisory"), got)
        self.assertIn(("SIZE", "openai-api", "advisory"), got)
        res = schema.check_schema(big)
        self.assertEqual(res["views"]["claude-api"]["size"]["dated_case"]["per_job"]["claude-api"], "$0.94")


if __name__ == "__main__":
    unittest.main()
