#!/usr/bin/env python3
"""The known risky shapes in a dumped tools/list, as found in our live runs. The checks are static, so a flag is a
prediction until a run confirms it.

    owner2_shapes.py <tools.json> [--write-only] [--json]

Checks, each tied to a live finding:
  CUT70      position > 70 in raw tools/list: invisible on Copilot's URL path (monday, re-checked 10-05).
  F1-ROW     array of objects whose rows have `required` fields: Copilot asks the user instead of calling
             (monday create_items, a work-management vendor's create-task tool; fix = drop the row `required`).
  UNTYPED    array whose items have no type/properties: Copilot types it as one-column Table{Value} and fails with
             SystemError before calling (Lucid lucid_create_org_chart.nodes).
  ROWKEYS    array of objects with optional properties: Copilot sends every row with the FIRST row's keys only
             (Lucid v2 and two other vendors' rows); harmless only if every row carries the same keys.
  FREEFORM   object with no declared properties (a free map): Copilot typed a CRM's `properties` as an empty
             Record and a row reached the CRM without its keys.
  OUTSCHEMA  outputSchema present: Anthropic's client validates results against it and rejects a mismatch
             (a CRM's deals read, custom_fields: null).
  plus schema_lint.py (Microsoft's documented issues): DROP ($ref), CRASH (numeric exclusiveMinimum), TRUNC (type
  array), ENUM, INFO (anyOf/oneOf/allOf).
Write tools: readOnlyHint false, or no hint and a write verb in the name.
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema_lint  # noqa: E402

WRITE_VERB = re.compile(r"(^|[_\-.])(create|update|delete|remove|add|set|post|put|patch|cancel|send|buy|purchase|"
                        r"release|save|hide|move|assign|apply|upload|archive|disqualify|replace|merge|bulk)", re.I)


def resolve(s, root, depth=0):
    while isinstance(s, dict) and "$ref" in s and depth < 10:
        ref = s["$ref"]
        if not ref.startswith("#/"):
            return s
        node = root
        for part in ref[2:].split("/"):
            node = node[int(part)] if isinstance(node, list) else node.get(part, {})
        s, depth = node, depth + 1
    return s


def merge_allof(v, root):
    """Fold `allOf` object branches into one row view (update actions shaped allOf[{action required}, …])."""
    if not isinstance(v, dict) or "allOf" not in v:
        return v
    props, req, free = dict(v.get("properties") or {}), list(v.get("required") or []), False
    for b in v["allOf"]:
        b = resolve(b, root)
        if not isinstance(b, dict):
            continue
        props.update(b.get("properties") or {})
        req += b.get("required") or []
        for alt in b.get("anyOf") or b.get("oneOf") or []:
            alt = resolve(alt, root)
            if isinstance(alt, dict) and alt.get("type") == "object" and not alt.get("properties"):
                free = True
    out = {"type": "object", "properties": props, "required": sorted(set(req))}
    if free:
        out["x-free-extra-keys"] = True
    return out


def is_untyped(items):
    if items in (None, True, {}):
        return True
    if not isinstance(items, dict):
        return False
    keys = set(items) - {"description", "title", "default", "examples"}
    return not keys


def walk(s, root, path, out, seen=0):
    s = resolve(s, root)
    if not isinstance(s, dict) or seen > 12:
        return
    for comb in ("anyOf", "oneOf", "allOf"):
        for sub in s.get(comb) or []:
            walk(sub, root, path, out, seen + 1)
    t = s.get("type")
    types = t if isinstance(t, list) else [t]
    if "array" in types:
        items = s.get("items")
        if is_untyped(items):
            out.append(("UNTYPED", path + "[]", "items untyped"))
        else:
            it = resolve(items, root)
            variants = [merge_allof(resolve(v, root), root)
                        for v in (it.get("anyOf") or it.get("oneOf") or [it])] if isinstance(it, dict) else []
            for v in variants:
                if isinstance(v, dict) and (v.get("type") == "object" or "properties" in v):
                    req = v.get("required") or []
                    props = sorted((v.get("properties") or {}).keys())
                    if req:
                        out.append(("F1-ROW", path + "[]", f"row requires {req}"))
                    if len(props) > len(req):
                        out.append(("ROWKEYS", path + "[]", f"{len(props) - len(req)} optional row keys"))
                    if v.get("x-free-extra-keys"):
                        out.append(("ROWKEYS", path + "[]", "row takes free extra keys (allOf + open object)"))
                    if not props and v.get("additionalProperties", True) is not False:
                        out.append(("FREEFORM", path + "[]", "row is a free map"))
                    walk(v, root, path + "[]", out, seen + 1)
    if ("object" in types or "properties" in s) and not s.get("properties") and path:
        if s.get("additionalProperties", True) is not False:
            out.append(("FREEFORM", path, "object with no declared properties"))
    for name, sub in (s.get("properties") or {}).items():
        walk(sub, root, f"{path}.{name}" if path else name, out, seen + 1)


def scan(tools):
    lint = {p["tool"]: p for p in schema_lint.lint(tools)["per_tool"]}
    rows = []
    for i, t in enumerate(tools, 1):
        schema = t.get("inputSchema") or {}
        flags = []
        walk(schema, schema, "", flags)
        ann = t.get("annotations") or {}
        ro = ann.get("readOnlyHint")
        write = (ro is False) or (ro is None and bool(WRITE_VERB.search(t["name"])))
        kinds = sorted({k for k, _, _ in flags})
        lk = sorted({f["kind"] for f in lint[t["name"]]["findings"]}) if t["name"] in lint else []
        rows.append({
            "pos": i, "name": t["name"], "title": t.get("title") or ann.get("title"), "write": write,
            "readOnlyHint": ro, "destructiveHint": ann.get("destructiveHint"),
            "cut70": i > 70, "outputSchema": bool(t.get("outputSchema")),
            "shapes": [{"kind": k, "at": a, "what": w} for k, a, w in flags], "shape_kinds": kinds,
            "lint_kinds": lk, "chars": len(json.dumps(t, ensure_ascii=False)),
            "desc_chars": len(t.get("description") or ""),
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", type=Path)
    ap.add_argument("--write-only", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    d = json.loads(a.file.read_text())
    tools = d["tools"] if isinstance(d, dict) else d
    rows = scan(tools)
    if a.json:
        print(json.dumps(rows, indent=1))
        return
    n = len(rows)
    agg = lambda k: sum(1 for r in rows if k in r["shape_kinds"] or k in r["lint_kinds"])
    print(f"== {a.file.name}: {n} tools, {sum(r['chars'] for r in rows):,} chars of definitions; "
          f"writes {sum(r['write'] for r in rows)}; untitled {sum(1 for r in rows if not r['title'])}; "
          f"past Copilot's 70: {sum(r['cut70'] for r in rows)}; outputSchema {sum(r['outputSchema'] for r in rows)}")
    print("   tools with: " + ", ".join(f"{k} {agg(k)}" for k in
          ("F1-ROW", "UNTYPED", "ROWKEYS", "FREEFORM", "DROP", "CRASH", "TRUNC", "ENUM", "INFO")))
    for r in rows:
        if a.write_only and not r["write"]:
            continue
        kinds = r["shape_kinds"] + [k for k in r["lint_kinds"] if k not in ("ENUM", "INFO")]
        mark = ("W" if r["write"] else "R") + ("  CUT70" if r["cut70"] else "")
        detail = "; ".join(f"{s['kind']} {s['at']} ({s['what']})" for s in r["shapes"][:6])
        print(f"   #{r['pos']:<3} {mark:<8} {r['name']:<45} {','.join(kinds) or '-'}" + (f"  | {detail}" if detail else ""))


if __name__ == "__main__":
    main()
