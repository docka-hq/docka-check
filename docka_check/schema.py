"""`schema` — the Copilot shape checks plus each client's documented schema rules, on one server's tools/list.

    rule hits  = check_schema(tools, server_name="docka")      # {rule id: [hit, ...]} for every schema-tier rule
    per client = findings.for_clients(table, hits)             # labels from the rule table

The checks in docka_check/t5/ find the Copilot shapes; this file adds the rules other clients
document, and the "how each client will see your tools" view. Nothing here calls a server.
"""

import json
import re

from .t5 import schema_checks as t5

# the t5 check names → the rule table's ids
T5_RULE = {"F1-ROW": "F1-ROW", "UNTYPED": "UNTYPED", "REQ8": "REQ8", "CUT70": "CUT70", "ROWKEYS": "ROWKEYS",
           "FREEFORM": "FREEFORM", "OUTSCHEMA": "OUTSCHEMA-DECLARED", "F1-ROW-OTHER": "F1-ROW-OTHER",
           "UNTYPED-OTHER": "F1-ROW-OTHER", "DELETE-NOHINT": "DELETE-NOHINT", "SIZE": "SIZE", "MS-DROP": "MS-DROP",
           "MS-CRASH": "MS-CRASH", "MS-TRUNC": "MS-TRUNC", "MS-ENUM": "MS-ENUM", "MS-COUNT": "MS-COUNT"}
SCHEMA_RULES = sorted(set(T5_RULE.values()) | {"ROOT-COMBINATOR", "SCHEMA-DIALECT", "NAME-128", "NO-READONLYHINT"})
OLD_DRAFT = re.compile(r"draft-0[3467]|draft/0[3467]", re.I)
NAME_LIMIT = 128
# The dated cost case behind SIZE (owner3 report 2026-10-12; the vendor is not named in reports)
COST_CASE = {"date": "2026-10-12", "server": "a server with 282 tools (~131K tokens of definitions)",
             "per_job": {"claude-api": "$0.94", "openai-api": "$0.02"}}


def _schemas(tool):
    for key in ("inputSchema", "input_schema", "outputSchema", "output_schema"):
        s = tool.get(key)
        if isinstance(s, dict):
            yield key, s


def check_schema(tools, server_name="server"):
    """Every schema-tier rule's hits on this tools/list: {rule id: [{"tool", "detail"}]}, plus size and views."""
    hits = {r: [] for r in SCHEMA_RULES}
    res = t5.check_tools(tools)
    for row in res["tools"]:
        for check, details in row["flags"].items():
            rule = T5_RULE.get(check)
            if rule:
                hits[rule].append({"tool": row["name"], "detail": "; ".join(str(d) for d in details)[:300]})
    for check in ("SIZE", "MS-COUNT"):                 # server-level, not per tool
        for detail in res["advisory"].get(check, []):
            hits[T5_RULE[check]].append({"tool": None, "detail": detail})

    for t in tools:
        name = t.get("name") or "?"
        ins = t.get("inputSchema") or t.get("input_schema") or {}
        combos = [k for k in ("anyOf", "oneOf", "allOf") if k in ins]
        if combos:
            hits["ROOT-COMBINATOR"].append({"tool": name, "detail": "root " + "/".join(combos), "combinators": combos})
        for key, s in _schemas(t):
            if OLD_DRAFT.search(str(s.get("$schema") or "")):
                hits["SCHEMA-DIALECT"].append({"tool": name, "detail": f"{key} $schema {s['$schema']}"})
        full = f"mcp__{server_name}__{name}"
        if len(full) > NAME_LIMIT:
            hits["NAME-128"].append({"tool": name, "detail": f"{full[:40]}… is {len(full)} characters"})
        if (t.get("annotations") or {}).get("readOnlyHint") is None:
            hits["NO-READONLYHINT"].append({"tool": name, "detail": "no readOnlyHint"})
    return {"tier": "schema", "n_tools": len(tools), "est_tokens": res["est_tokens"], "hits": hits,
            "views": views(tools, hits, res)}


def _old_output(h):
    """A draft-07 outputSchema: what the Claude Desktop and Claude Code issues are about (#94351, #88882)."""
    return h["detail"].startswith(("outputSchema", "output_schema")) and "draft-07" in h["detail"]


def views(tools, hits, res):
    """How each client will see the tools: what it drops, what it asks the user, what needs a confirmation."""
    names = lambda rule, pred=lambda h: True: sorted({h["tool"] for h in hits[rule] if h["tool"] and pred(h)})
    past70 = [r["name"] for r in res["tools"] if r["pos"] > 70]
    size = {"est_tokens": res["est_tokens"], "dated_case": COST_CASE}
    return {
        "copilot-studio": {
            "asks_user": {"required row fields": names("F1-ROW"), "8+ required inputs": names("REQ8")},
            "fails_before_call": {"untyped array items (SystemError)": names("UNTYPED")},
            "may_drop": {"past position 70, on agents that cut": past70, "$ref inputs": names("MS-DROP")},
            "rows_may_lose_keys": names("ROWKEYS"),
        },
        "claude-api": {"rejects": {"root anyOf/oneOf/allOf": names("ROOT-COMBINATOR")},
                       "validates_results_of": names("OUTSCHEMA-DECLARED"), "size": size},
        "claude-ai": {"rejects": {"declares outputSchema (claude-ai-mcp#673)": names("OUTSCHEMA-DECLARED"),
                                  "draft-07 outputSchema (Desktop, open issue)": names("SCHEMA-DIALECT", _old_output)}},
        "claude-code": {"drops": {"full name over 128 characters": names("NAME-128"),
                                  "root allOf (open issue)": names("ROOT-COMBINATOR",
                                                                   lambda h: "allOf" in h.get("combinators", []))},
                        "fails_when_called": {"draft-07 outputSchema (open issue)": names("SCHEMA-DIALECT", _old_output)},
                        "validates_results_of": names("OUTSCHEMA-DECLARED")},
        "openai-api": {"size": size},
        "chatgpt": {"asks_confirmation": {"no readOnlyHint, treated as a write": names("NO-READONLYHINT")}},
    }


def client_hits(rule_id, client, h):
    """The hits on one rule that count for this client. Claude Code's root-combinator issue is about allOf only; the
    Claude Desktop and Claude Code dialect issues are about a draft-07 outputSchema (draft-07 in an inputSchema alone
    was listed and called without an error in our 2026-10-21 run)."""
    if rule_id == "SCHEMA-DIALECT" and client in ("claude-ai", "claude-code"):
        return [x for x in h if _old_output(x)]
    if rule_id == "ROOT-COMBINATOR" and client == "claude-code":
        return [x for x in h if "allOf" in x.get("combinators", [])]
    return h


def load_tools(path):
    from pathlib import Path
    d = json.loads(Path(path).read_text())
    if isinstance(d, dict):
        d = d.get("tools", d.get("result", {}).get("tools", []))
    return d
