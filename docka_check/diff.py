"""What a release changed, from two JSON reports. A build fails only on a new blocker with run evidence:
docs-class and advisory findings never fail it."""


def _keys(report):
    out = {}
    for f in report.get("findings", []):
        tools = [h.get("tool") for h in f.get("hits", []) if h.get("tool")] or [None]
        for t in tools:
            out[(f["rule"], f["client"], t)] = f
    return out


def compare(old, new):
    a, b = _keys(old), _keys(new)
    added = [b[k] | {"tool": k[2]} for k in sorted(set(b) - set(a), key=str)]
    removed = [a[k] | {"tool": k[2]} for k in sorted(set(a) - set(b), key=str)]
    fails = [f for f in added if f["label"] == "blocker" and f["evidence"] == "run"]
    return {"added": added, "removed": removed, "new_run_blockers": fails}


def lines(d, names):
    out = []
    for verb, group in (("New", d["added"]), ("Gone", d["removed"])):
        for f in group:
            where = f"`{f['tool']}`" if f.get("tool") else "the server"
            says = f" — {f['says']}" if f.get("says") else ""
            out.append(f"- {verb} {f['label']}: {f['rule']} on {where} for {names[f['client']]}{says}")
    if not out:
        out.append("- No finding changed since the baseline.")
    return out
