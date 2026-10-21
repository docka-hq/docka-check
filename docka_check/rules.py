"""The rule table: load it, check it, and answer what the report needs to count.

The table is `rules.json` next to this file. Labels and evidence follow one rule: a finding is a **blocker** only when
our own run confirmed it (a dated case, with a ref to its run record); a platform's documentation makes it **likely**;
anything unconfirmed is never shown as a finding, only in the not-checked list. The run records are Docka's and are not
published: a case carries the text a report shows, its date and a public link where one exists.
"""

import json
from pathlib import Path

TABLE = Path(__file__).resolve().parent / "rules.json"
TIERS = ("signin", "schema", "calls", "calls-write", "run-only", "registry", "client-config")
CHECKED_TIERS = ("signin", "schema", "calls")          # what v0 can check at all
EFFECTS = ("fails", "friction", "passes", "unknown")
EVIDENCE = ("run", "docs", "unconfirmed")
LABELS = ("blocker", "likely", "advisory", "info", "unconfirmed")


def load(path=TABLE):
    return json.loads(Path(path).read_text())


def problems(table):
    """Everything wrong with the table, as a list of strings. Empty means it holds the rules above."""
    out, seen = [], set()
    clients, sources = table["clients"], table["sources"]
    for r in table["rules"]:
        rid = r.get("id", "?")
        if rid in seen:
            out.append(f"{rid}: duplicate id")
        seen.add(rid)
        if r.get("tier") not in TIERS:
            out.append(f"{rid}: tier {r.get('tier')!r}")
        for key in ("title", "detects", "fix"):
            if not r.get(key):
                out.append(f"{rid}: no {key}")
        for client, c in r.get("per_client", {}).items():
            where = f"{rid}/{client}"
            if client not in clients:
                out.append(f"{where}: unknown client")
            if c.get("effect") not in EFFECTS:
                out.append(f"{where}: effect {c.get('effect')!r}")
            if c.get("evidence") not in EVIDENCE:
                out.append(f"{where}: evidence {c.get('evidence')!r}")
            if not c.get("behaviour_date"):
                out.append(f"{where}: no behaviour_date")
            label = c.get("label")
            if c.get("effect") != "passes" and label not in LABELS:
                out.append(f"{where}: label {label!r}")
            if label == "blocker":
                if c.get("evidence") != "run":
                    out.append(f"{where}: a blocker without run evidence")
                if not any(case.get("ref") and case.get("date") for case in c.get("cases", [])):
                    out.append(f"{where}: a blocker with no dated run case and record")
            if label == "likely" and c.get("evidence") == "unconfirmed":
                out.append(f"{where}: 'likely' needs run or docs evidence")
            if c.get("evidence") == "run" and not c.get("cases") and label != "unconfirmed":
                out.append(f"{where}: run evidence with no case")
            if c.get("evidence") == "docs" and c.get("source") not in sources:
                out.append(f"{where}: docs evidence with no known source")
            for case in c.get("cases", []):
                if not case.get("ref") or not case.get("date") or not case.get("report"):
                    out.append(f"{where}: a case without date, record ref or report text")
    return out


def known_failures(table):
    """The failures our runs have seen: the denominator of 'checked N of M known failures'."""
    return [r for r in table["rules"] if r.get("known_failure")]


def finding_label(rule, client):
    """How a hit on this rule shows for this client: blocker / likely / advisory / info, or None (not shown)."""
    c = rule.get("per_client", {}).get(client)
    if not c or c.get("effect") == "passes" or c.get("label") == "unconfirmed":
        return None
    return c.get("label")


def by_id(table):
    return {r["id"]: r for r in table["rules"]}
