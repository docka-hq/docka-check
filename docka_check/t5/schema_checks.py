#!/usr/bin/env python3
"""
The schema checks behind docka-check's schema tier, run on one server's tools/list. No requests, no model.

  python3 schema_checks.py <tools.json> [--json]

Blockers. A real run confirmed the failure, and the shape alone predicts it:
  F1-ROW    a required top-level array whose object rows have `required` fields. Copilot Studio says the row fields
            are missing although the model filled them, asks the user, and never calls the tool (monday
            create_items 0/24; a work-management vendor's create-task tool 0/3).
  UNTYPED   a required top-level array whose items have no type. Copilot Studio types it as a list of plain values
            and stops with SystemError when the model passes objects (Lucid lucid_create_org_chart 0/6).
  REQ8      eight or more required inputs on one tool. Copilot Studio asks the user for a required input the model
            left out, instead of returning the error to the model (monday search: GPT in Copilot 0/3 with 8 required,
            3/3 with 1).

Advisory. The shape was seen in a failure but does not predict it alone, or nothing confirmed it:
  CUT70, ROWKEYS, FREEFORM, OUTSCHEMA, F1-ROW-OTHER, UNTYPED-OTHER, DELETE-NOHINT, SIZE, and Microsoft's documented
  known issues read by schema_lint.py: MS-DROP, MS-CRASH, MS-TRUNC, MS-ENUM, MS-COUNT.

The walk over each schema is owner2_shapes.walk; this file only narrows its F1-ROW and UNTYPED flags to the shapes
the runs confirmed and adds the remaining checks.
"""

import argparse, json, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import owner2_shapes  # noqa: E402
import schema_lint  # noqa: E402

BLOCKERS = ("F1-ROW", "UNTYPED", "REQ8")
ADVISORY = ("CUT70", "ROWKEYS", "FREEFORM", "OUTSCHEMA", "F1-ROW-OTHER", "UNTYPED-OTHER", "DELETE-NOHINT", "SIZE",
            "MS-DROP", "MS-CRASH", "MS-TRUNC", "MS-ENUM", "MS-COUNT")
CUT, REQ_MANY, SIZE_TOKENS = 70, 8, 50_000
DELETE_VERB = re.compile(r"(^|[_\-.\s])(delete|remove|destroy|purge|erase)", re.I)


def top_level(at):
    """'items[]' -> 'items'; nested paths ('a.b[]', 'a[].b[]') -> None."""
    if not at.endswith("[]"):
        return None
    head = at[:-2]
    return None if ("." in head or "[]" in head or not head) else head


def tool_flags(t, pos):
    """Every check that fires on one tool, as {check: [details]}."""
    schema = t.get("inputSchema") or t.get("input_schema") or {}
    root = owner2_shapes.resolve(schema, schema)
    required = set((root.get("required") or []) if isinstance(root, dict) else [])
    raw = []
    owner2_shapes.walk(schema, schema, "", raw)
    out = {}

    def add(check, what):
        out.setdefault(check, [])
        if what not in out[check]:
            out[check].append(what)

    for kind, at, what in raw:
        name = top_level(at)
        if kind == "F1-ROW":
            add("F1-ROW" if name and name in required else "F1-ROW-OTHER",
                f"{at} {what}" + ("" if name else " (nested)") + ("" if not name or name in required else " (optional)"))
        elif kind == "UNTYPED":
            add("UNTYPED" if name and name in required else "UNTYPED-OTHER",
                at + ("" if name else " (nested)") + ("" if not name or name in required else " (optional)"))
        elif kind in ("ROWKEYS", "FREEFORM"):
            add(kind, f"{at} {what}")
    if len(required) >= REQ_MANY:
        add("REQ8", f"{len(required)} required: {', '.join(sorted(required))}")
    if pos > CUT:
        add("CUT70", f"position {pos}")
    if t.get("outputSchema") or t.get("output_schema"):
        add("OUTSCHEMA", "outputSchema declared")
    ann = t.get("annotations") or {}
    if DELETE_VERB.search(t.get("name") or "") and ann.get("destructiveHint") is not True:
        why = ("readOnlyHint true" if ann.get("readOnlyHint") is True else
               "destructiveHint false" if ann.get("destructiveHint") is False else "no destructiveHint")
        add("DELETE-NOHINT", why)
    return out


def check_tools(tools):
    """One server's tools/list → {n_tools, est_tokens, blockers, advisory, tools}. Checks map to the tools they hit."""
    per_tool, blockers, advisory = [], {}, {}
    lint = {p["tool"]: p for p in schema_lint.lint(tools)["per_tool"]}
    for pos, t in enumerate(tools, 1):
        flags = tool_flags(t, pos)
        for f in (lint.get(t.get("name")) or {}).get("findings", []):
            if f["kind"] in ("DROP", "CRASH", "TRUNC", "ENUM"):
                flags.setdefault("MS-" + f["kind"], []).append(f["at"])
        per_tool.append({"pos": pos, "name": t.get("name"), "flags": flags})
        for check in flags:
            (blockers if check in BLOCKERS else advisory).setdefault(check, []).append(t.get("name"))
    chars = sum(len(json.dumps(t, ensure_ascii=False)) for t in tools)
    est_tokens = chars // 4
    if est_tokens >= SIZE_TOKENS:
        advisory["SIZE"] = [f"~{est_tokens:,} tokens of tool definitions"]
    if len(tools) > schema_lint.TOOL_CAP:
        advisory["MS-COUNT"] = [f"{len(tools)} tools, over Copilot Studio's documented cap of {schema_lint.TOOL_CAP}"]
    return {"n_tools": len(tools), "est_tokens": est_tokens, "blockers": blockers, "advisory": advisory,
            "tools": per_tool}


def load_tools(path):
    d = json.loads(Path(path).read_text())
    if isinstance(d, dict):
        d = d.get("tools", d.get("result", {}).get("tools", []))
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file", type=Path)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = check_tools(load_tools(a.file))
    if a.json:
        print(json.dumps(res, indent=1))
        return
    print(f"== {a.file.name}: {res['n_tools']} tools, ~{res['est_tokens']:,} tokens of definitions")
    for label, group in (("BLOCKER", res["blockers"]), ("advisory", res["advisory"])):
        for check, names in sorted(group.items()):
            shown = ", ".join(str(n) for n in names[:8]) + (f" … +{len(names) - 8}" if len(names) > 8 else "")
            print(f"   {label:<8} {check:<14} {len(names):>3}  {shown}")


if __name__ == "__main__":
    main()
