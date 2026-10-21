#!/usr/bin/env python3
"""Copilot Studio MCP schema lint: does a server's tools/list survive Microsoft's documented known issues?

    python3 schema_lint.py <tools.json> [<tools.json> ...] [--json]
    python3 schema_lint.py --self-test

Input: what a server returns for `tools/list`, either {"tools": [...]} or a bare list of tools. Both
`inputSchema` and the MCP SDK v2 spelling `input_schema` are read.

Checks. Source: Microsoft's "Troubleshooting MCP integration" page for Copilot Studio
(learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-troubleshooting), updated 2026-08-19, plus the
Copilot Studio tool limits (add-tools-custom-agent):

  DROP   a `$ref` in the input or output schema. Documented: "Tools with reference type inputs in the
         schema are filtered from the list of available tools … Reference type inputs and outputs aren't
         supported."
  CRASH  `exclusiveMinimum` given as a number rather than a boolean. Documented: "A System.FormatException
         is thrown".
  TRUNC  a `type` that is an array of types. Documented: the input schema "is truncated".
  ENUM   an enum input. Documented: "interpreted as string instead of enum", so the model loses the list of
         allowed values.
  COUNT  more than 128 tools (the hard cap) or more than 30 (Microsoft's recommendation).

Marked SUSPECT, not documented: a numeric `exclusiveMaximum`, the mirror image of CRASH.
Marked INFO, not documented as a Copilot Studio issue: `anyOf`/`oneOf`/`allOf`. Microsoft 365 API plugins
do not support these; for MCP in Copilot Studio it is unknown.

⚠️ This is a static reading of Microsoft's documentation, not a run. A finding states what Copilot Studio
is documented to do with the schema, not what it did. Confirm it live before quoting it to anyone.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL_CAP, TOOL_RECOMMENDED = 128, 30

DOCUMENTED = ("DROP", "CRASH", "TRUNC", "ENUM")
SEVERITY = {"DROP": "tool filtered out", "CRASH": "exception on schema parse", "TRUNC": "schema truncated",
            "ENUM": "enum read as string", "SUSPECT": "undocumented, likely like CRASH",
            "INFO": "combinator, behaviour unknown"}


def walk(node, path, out, where):
    """Collect findings in one JSON Schema node, recursively. `where` is 'input' or 'output'."""
    if isinstance(node, list):
        for i, x in enumerate(node):
            walk(x, f"{path}[{i}]", out, where)
        return
    if not isinstance(node, dict):
        return
    if "$ref" in node:
        out.append(("DROP", f"{path}.$ref", f"{where} schema uses a reference ({node['$ref']})"))
    em = node.get("exclusiveMinimum")
    if em is not None and not isinstance(em, bool) and where == "input":
        out.append(("CRASH", f"{path}.exclusiveMinimum", f"numeric exclusiveMinimum={em}"))
    ex = node.get("exclusiveMaximum")
    if ex is not None and not isinstance(ex, bool) and where == "input":
        out.append(("SUSPECT", f"{path}.exclusiveMaximum", f"numeric exclusiveMaximum={ex}"))
    t = node.get("type")
    if isinstance(t, list) and len(t) > 1 and where == "input":
        out.append(("TRUNC", f"{path}.type", f"type is an array {t}"))
    if "enum" in node and where == "input":
        out.append(("ENUM", f"{path}.enum", f"enum of {len(node['enum'])} values"))
    for comb in ("anyOf", "oneOf", "allOf"):
        if comb in node and where == "input":
            out.append(("INFO", f"{path}.{comb}", f"{comb} with {len(node[comb])} branches"))
    for key, val in node.items():
        if key in ("enum", "const", "default", "examples", "description", "title", "$ref"):
            continue
        if isinstance(val, (dict, list)):
            walk(val, f"{path}.{key}", out, where)


def load_tools(path: Path) -> tuple[str, list[dict]]:
    data = json.loads(path.read_text())
    source = ""
    if isinstance(data, dict):
        source = data.get("_source", "")
        data = data.get("tools", data.get("result", {}).get("tools", []))
    return source, data


def lint(tools: list[dict]) -> dict:
    per_tool = []
    for t in tools:
        findings: list[tuple[str, str, str]] = []
        ins = t.get("inputSchema") or t.get("input_schema") or {}
        outs = t.get("outputSchema") or t.get("output_schema")
        walk(ins, "input", findings, "input")
        if outs:
            walk(outs, "output", findings, "output")
        kinds = {f[0] for f in findings}
        if "DROP" in kinds:
            verdict = "DROPPED"
        elif "CRASH" in kinds:
            verdict = "CRASH"
        elif "TRUNC" in kinds:
            verdict = "TRUNCATED"
        elif "ENUM" in kinds:
            verdict = "DEGRADED"
        else:
            verdict = "CLEAN"
        per_tool.append({"tool": t.get("name", "?"), "verdict": verdict,
                         "findings": [{"kind": k, "at": a, "what": w} for k, a, w in findings]})
    n = len(tools)
    counts = {v: sum(1 for p in per_tool if p["verdict"] == v)
              for v in ("DROPPED", "CRASH", "TRUNCATED", "DEGRADED", "CLEAN")}
    count_flag = ("over the hard cap" if n > TOOL_CAP else
                  "over Microsoft's recommendation" if n > TOOL_RECOMMENDED else "ok")
    return {"tools": n, "count_check": count_flag, "verdicts": counts, "per_tool": per_tool}


def headline(res: dict) -> str:
    v = res["verdicts"]
    line = (f"{res['tools']} tools: {v['DROPPED']} dropped, {v['CRASH']} crash on parse, "
            f"{v['TRUNCATED']} truncated, {v['DEGRADED']} lose enum values, {v['CLEAN']} clean "
            f"(tool count {res['count_check']})")
    if v["CRASH"]:
        # Vendor evidence, not Microsoft's docs: monday.com hit this twice, and its own PR says one numeric
        # exclusiveMinimum "can reject the entire tools/list response" (mondaycom/mcp #334 2026-05-06,
        # #495 2026-09-23). A single CRASH tool therefore puts every tool on the server at risk.
        line += "\n   ⚠️ SERVER AT RISK: one CRASH can make Copilot Studio reject the whole tools/list"
    return line


def report(path: Path, as_json: bool) -> dict:
    source, tools = load_tools(path)
    res = lint(tools)
    res["file"], res["source"] = str(path), source
    if not as_json:
        print(f"== {path.name}" + (f"  [{source}]" if source else ""))
        print("   " + headline(res))
        for p in res["per_tool"]:
            if p["verdict"] == "CLEAN" and not p["findings"]:
                continue
            kinds = sorted({f["kind"] for f in p["findings"]})
            print(f"   {p['verdict']:<9} {p['tool']}: " + ", ".join(
                f"{k} ({SEVERITY[k]})" for k in kinds))
    return res


def self_test() -> None:
    """The four SDK fixtures carry one tool each: a positive number, an enum, an optional string and an
    optional nested object, written the way each SDK's docs teach it. Expected verdicts were
    established by hand on 2026-09-23."""
    expect = {
        "sdk_python_v1.json": ("DROPPED", {"DROP", "CRASH", "ENUM", "INFO"}),
        "sdk_python_v2.json": ("DROPPED", {"DROP", "CRASH", "ENUM", "INFO"}),
        "fastmcp_4.json": ("CRASH", {"CRASH", "ENUM", "INFO"}),
        "sdk_typescript.json": ("CRASH", {"CRASH", "TRUNC", "ENUM"}),
    }
    ok = True
    for name, (verdict, kinds) in expect.items():
        _, tools = load_tools(HERE / "fixtures" / name)
        p = lint(tools)["per_tool"][0]
        got = {f["kind"] for f in p["findings"]}
        good = p["verdict"] == verdict and got == kinds
        ok &= good
        print(f"{'PASS' if good else 'FAIL'}  {name}: verdict {p['verdict']} (want {verdict}), "
              f"kinds {sorted(got)} (want {sorted(kinds)})")
    sys.exit(0 if ok else 1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        self_test()
    if not a.files:
        ap.error("give at least one tools.json, or --self-test")
    results = [report(f, a.json) for f in a.files]
    if a.json:
        print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
