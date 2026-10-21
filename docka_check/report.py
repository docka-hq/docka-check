"""The report — a coverage map, never a verdict. Terminal, Markdown (PR comments, job summaries) and JSON.

Its first line counts from the rule table: checked, found, what only an agent run shows. Then client × tier, each
cell one of: found / not found in our checks / not checked here. Then each finding with its evidence class, the
date of the client behaviour, the case and the fix. It never prints PASS, a score or a badge.
"""

import json

from . import __version__
from .findings import CLIENT_NAMES, CLIENTS, counts

TIER_ROWS = (("signin", "sign-in"), ("schema", "schema"), ("calls", "calls"), ("run-only", "agent run"))
CELL = {"found": "found", "not_found": "not found in our checks", "not_checked": "not checked here"}
ORDER = {"blocker": 0, "likely": 1, "advisory": 2, "info": 3}


def build(table, target, tier_results, ev, clients=CLIENTS, when=None):
    """Everything a format needs, as plain data (this is also the JSON output and the baseline for --baseline)."""
    cov = ev["coverage"]
    cells = {}
    info_only = {(f["rule"], f["client"]) for f in ev["findings"] if f["label"] == "info"}
    for tier, _ in TIER_ROWS:
        for client in clients:
            states = [("not_found" if (r["id"], client) in info_only else cov[r["id"]]["clients"].get(client))
                      for r in table["rules"] if r["tier"] == tier]
            states = [s for s in states if s and s != "n/a"]
            if tier == "run-only" or not states:
                cells[f"{tier}/{client}"] = "not_checked"
            elif "found" in states:
                cells[f"{tier}/{client}"] = "found"
            elif "not_found" in states:
                cells[f"{tier}/{client}"] = "not_found"
            else:
                cells[f"{tier}/{client}"] = "not_checked"
    not_checked = {}
    for rid, c in cov.items():
        if c["status"] == "not_checked":
            not_checked.setdefault(c["reason"], []).append(rid)
    unconfirmed = sorted(f"{r['id']} for {CLIENT_NAMES[cl]}" for r in table["rules"] for cl, v in r["per_client"].items()
                         if v.get("label") == "unconfirmed" and cl in clients)
    views = next((tr.get("views") for tr in tier_results if tr.get("views")), None)
    return {
        "tool": f"docka-check {__version__}", "table_version": table["table_version"], "target": target,
        "when": when, "tiers_run": [tr["tier"] for tr in tier_results], "clients": list(clients),
        "counts": counts(table, cov), "cells": cells,
        "findings": sorted(ev["findings"], key=lambda f: (ORDER.get(f["label"], 9), f["rule"], f["client"])),
        "views": views, "not_checked": not_checked, "unconfirmed": unconfirmed,
        "checked_rules": sorted(rid for rid, c in cov.items() if c["status"] in ("found", "not_found")),
        "notes": [n for tr in tier_results for n in tr.get("notes", [])],
        "last_agent_run": "never",
    }


def first_line(r):
    """Counts rules (known failures); the sections below list each client's findings."""
    c = r["counts"]
    return (f"Checked {c['checked']} of {c['known_failures']} known failures. Found: {c['found']}. "
            f"Only an agent run shows: {c['agent_run_only']}. Needs write calls (v1): {c['needs_writes']}. "
            f"Not checked in this run: {c['not_checked_here']}.")


def findings_line(r):
    """The per-client count under the first line: the sections below add up to it (the first line counts rules)."""
    n = {k: sum(1 for f in r["findings"] if f["label"] == k) for k in ("blocker", "likely", "advisory")}
    if not sum(n.values()):
        return None
    return (f"Listed below, client by client: {sum(n.values())} findings ({n['blocker']} blocker, {n['likely']} likely, "
            f"{n['advisory']} advisory).")


def _evidence(f):
    """One line per case (our runs, dated, with the public link where there is one), then the documentation."""
    out = []
    for case in f["cases"][:4]:
        link = f" ({case['public']})" if case.get("public") else ""
        out.append(f"Seen in our run, {case.get('date')}: {case.get('what')}{link}")
    src = f.get("source")
    if src:
        out.append(f"Documented: {src.get('url')} (read {src.get('read')})")
    return out or ["no case recorded"]


def _hits(f):
    names = [h["tool"] for h in f["hits"] if h.get("tool")]
    if names:
        shown = ", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else "")
        return shown
    return "; ".join(h["detail"] for h in f["hits"][:2])


def markdown(r):
    out = [f"## docka-check: what each AI client sees on `{r['target'].get('url') or r['target'].get('tools_file')}`",
           "", f"**{first_line(r)}**", ""]
    if findings_line(r):
        out += [findings_line(r), ""]
    out += [
           f"<sub>{r['tool']} · rule table {r['table_version']} · tiers run: {', '.join(r['tiers_run']) or 'none'}"
           + (f" · {r['when']}" if r.get("when") else "") + "</sub>", ""]
    if r.get("mode"):
        out += [r["mode"], ""]
    out += ["| | " + " | ".join(CLIENT_NAMES[c] for c in r["clients"]) + " |",
            "|---|" + "---|" * len(r["clients"])]
    for tier, label in TIER_ROWS:
        out.append(f"| {label} | " + " | ".join(CELL[r["cells"][f"{tier}/{c}"]] for c in r["clients"]) + " |")
    out.append("")
    groups = [("Blockers: our own run confirmed the failure", "blocker"),
              ("Likely: the platform documents it", "likely"),
              ("Advisory: seen in our runs but not a failure by itself, or friction", "advisory"),
              ("Info", "info")]
    for title, label in groups:
        fs = [f for f in r["findings"] if f["label"] == label]
        if not fs:
            continue
        out += [f"### {title} ({len(fs)})", ""]
        for f in fs:
            out.append(f"- **{f['rule']}** · {CLIENT_NAMES[f['client']]} · client behaviour of {f['behaviour_date']}: "
                       f"{f['title']}. Where: {_hits(f)}.")
            if f.get("says"):
                out.append(f"  - {f['says']}")
            out += [f"  - {line}." for line in _evidence(f)]
            if f.get("note"):
                out.append(f"  - Note: {f['note']}")
            out.append(f"  - Fix: {f['fix']}" + (f" Guide: {f['guide']}" if f.get("guide") else ""))
        out.append("")
    if r.get("views"):
        out += ["### How each client will see your tools", ""]
        for client, v in r["views"].items():
            if client not in r["clients"]:
                continue
            parts = []
            for k, val in v.items():
                if isinstance(val, dict) and "est_tokens" in val:
                    case = val["dated_case"]
                    parts.append(f"~{val['est_tokens']:,} tokens of tool definitions on every turn "
                                 f"(dated case: {case['server']} cost {case['per_job'].get(client, 'n/a')} a job, "
                                 f"{case['date']})")
                elif isinstance(val, dict):
                    parts += [f"{what}: {', '.join(names[:6])}" + (f" +{len(names) - 6}" if len(names) > 6 else "")
                              for what, names in val.items() if names]
                elif val:
                    parts.append(f"{k.replace('_', ' ')}: {', '.join(val[:6])}")
            out.append(f"- **{CLIENT_NAMES[client]}**: " + ("; ".join(parts) if parts else "no notes from the tool definitions"))
        out.append("")
    out += ["### Not checked here", ""]
    for reason, ids in sorted(r["not_checked"].items()):
        out.append(f"- {reason}: {', '.join(sorted(ids))}")
    if r["unconfirmed"]:
        out.append(f"- unconfirmed, never shown as findings: {', '.join(r['unconfirmed'])}")
    out += [f"- {note}" for note in r.get("notes") or []]
    out += ["", f"Last agent run: {r['last_agent_run']}. Copilot Studio needs a Microsoft tenant: Docka runs it "
                "(https://docka.ai).", ""]
    return "\n".join(out)


def terminal(r):
    md = markdown(r)
    lines = []
    for line in md.splitlines():
        line = line.replace("**", "").replace("<sub>", "").replace("</sub>", "").replace("`", "")
        if line.startswith("## "):
            line = line[3:]
        elif line.startswith("### "):
            line = "\n" + line[4:].upper()
        lines.append(line)
    return "\n".join(lines)


def as_json(r):
    return json.dumps(r, indent=1, ensure_ascii=False, default=str)


FORMATS = {"md": markdown, "terminal": terminal, "json": as_json}
