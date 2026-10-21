"""Turn each tier's rule hits into findings per client, labelled from the rule table, plus the coverage map.

A finding exists only for a client whose row in the table says the shape hurts it (`fails`) with evidence: run →
blocker or advisory, docs → likely. A `passes` row or an `unconfirmed` row never yields a finding. Every rule the
tool did not evaluate is "not checked here", with the reason.
"""

from . import rules as R
from .schema import client_hits

CLIENTS = ("copilot-studio", "claude-api", "claude-ai", "claude-code", "openai-api", "chatgpt")
CLIENT_NAMES = {"copilot-studio": "Copilot Studio", "claude-api": "Claude API", "claude-ai": "claude.ai",
                "claude-code": "Claude Code", "openai-api": "OpenAI API", "chatgpt": "ChatGPT"}
WHY_NOT = {"run-only": "only an agent run shows it", "calls-write": "needs write calls (--allow-writes, v1)",
           "registry": "a registry property; the owner gives the real URL", "client-config": "a client setting"}


def evaluate(table, tier_results, clients=CLIENTS):
    """tier_results: [{"tier", "hits": {rule: [hit]}, "skipped": {rule: reason},
    "skipped_clients": {rule: {client: reason}}}] → findings and coverage.

    A skip outranks an empty hit list: a rule the tier did not evaluate is "not checked", never "not found". A rule is
    "found" only when some client has a finding, and "not checked" when every client it applies to was skipped."""
    ran = {tr["tier"] for tr in tier_results}
    hits = {rid: h for tr in tier_results for rid, h in tr["hits"].items()}
    skipped = {rid: why for tr in tier_results for rid, why in tr.get("skipped", {}).items()}
    by_client = {}
    for tr in tier_results:
        for rid, m in (tr.get("skipped_clients") or {}).items():
            by_client.setdefault(rid, {}).update(m)
    findings, coverage = [], {}
    for rule in table["rules"]:
        rid, tier = rule["id"], rule["tier"]
        cskip = by_client.get(rid, {})
        if hits.get(rid):
            status, reason = "found", None
        elif rid in skipped:
            status, reason = "not_checked", skipped[rid]
        elif rid in hits:
            status, reason = "not_found", None
        elif tier in ran:
            status, reason = "not_checked", "not evaluated in this run"
        else:
            status, reason = "not_checked", WHY_NOT.get(tier, f"the {tier} tier did not run")
        per_client = {}
        for client in clients:
            label = R.finding_label(rule, client)
            if label is None:
                per_client[client] = "n/a"
                continue
            if status == "not_checked":
                per_client[client] = "not_checked"
                continue
            mine = [h for h in hits.get(rid) or [] if "clients" not in h or client in h["clients"]]
            if tier == "schema":
                mine = client_hits(rid, client, mine)
            per_client[client] = "found" if mine else ("not_checked" if client in cskip else "not_found")
            if mine:
                c = rule["per_client"][client]
                findings.append({
                    "rule": rid, "client": client, "label": label, "tier": tier, "title": rule["title"],
                    "evidence": c["evidence"], "behaviour_date": c["behaviour_date"],
                    "cases": public_cases(c), "source": table["sources"].get(c.get("source"), None),
                    "says": c.get("says"), "note": c.get("note"), "fix": rule["fix"], "guide": rule.get("guide"),
                    "hits": mine})
        states = [v for v in per_client.values() if v != "n/a"]
        if status == "found" and "found" not in states:
            status = "not_found"
        if status == "not_found" and states and all(v == "not_checked" for v in states):
            groups = {}
            for c in clients:
                if per_client.get(c) == "not_checked":
                    groups.setdefault(cskip[c], []).append(CLIENT_NAMES.get(c, c))
            status, reason = "not_checked", "; ".join(f"{', '.join(n)}: {why}" for why, n in groups.items())
        coverage[rid] = {"tier": tier, "status": status, "reason": reason,
                         "known_failure": bool(rule.get("known_failure")), "clients": per_client}
    return {"findings": findings, "coverage": coverage}


def public_cases(entry):
    """What a report shows of a case: its date, its report text (which names only vendors our public pages name) and
    its public link."""
    out = []
    for case in entry.get("cases", []):
        text = case.get("report") or "one of our runs (vendor not named)"
        out.append({"date": case.get("date"), "what": text, **({"public": case["public"]} if case.get("public") else {})})
    return out


def counts(table, coverage):
    """The report's first line, from the table: never hard-coded."""
    known = [r for r in table["rules"] if r.get("known_failure")]
    st = lambda r: coverage[r["id"]]["status"]
    rank = {"blocker": 0, "likely": 1, "advisory": 2, "info": 3}

    def worst(r):
        labels = [R.finding_label(r, c) for c, v in coverage[r["id"]]["clients"].items() if v == "found"]
        return min((x for x in labels if x), key=lambda x: rank.get(x, 9), default=None)
    # Found = known failures with a blocker, likely or advisory finding; a rule whose worst finding is info is checked
    found = [w for w in (worst(r) for r in known if st(r) == "found") if w in ("blocker", "likely", "advisory")]
    return {
        "known_failures": len(known),
        "checked": sum(st(r) in ("found", "not_found") for r in known),
        "found": len(found),
        "found_rules_by_worst_label": {k: found.count(k) for k in ("blocker", "likely", "advisory")},
        "agent_run_only": sum(r["tier"] == "run-only" for r in known),
        "needs_writes": sum(r["tier"] == "calls-write" for r in known),
        "not_checked_here": sum(st(r) == "not_checked" and r["tier"] not in ("run-only", "calls-write") for r in known),
    }
