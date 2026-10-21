"""docka-check: what each AI client sees on your MCP server. No model calls; never a verdict.

    docka-check verify --url https://mcp.example.com/mcp --email you@example.com      (once per server)
    docka-check check  --url https://mcp.example.com/mcp --token-env MCP_TOKEN [--calls-config calls.json]
    docka-check schema --tools-file tools.json            (or --url with your token)
    docka-check signin --url URL [--register] [--interactive]
    docka-check calls  --url URL --token-env MCP_TOKEN --calls-config calls.json [--auto-read]
    docka-check diff   old.json new.json
    docka-check key    --url URL                          (a verified server's key, for a CI secret)

Credentials only from environment variables (--token-env, --header NAME=ENV_VAR), never on the command line; they
never appear in a report, log or CI output. A key written into --url itself is used for the requests and shown as
[credential].

A full run needs a server verified as yours (docka-check verify, or its key in DOCKA_CHECK_KEY in CI) or one on this
machine. A verified server's full run sends its JSON report to Docka. Any other server gets an outside check: at most
5 requests per server, no client registration, no tool calls, and nothing is sent to Docka.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, unquote_plus, urlparse, urlsplit, urlunsplit

from . import calls as calls_tier
from . import diff as diff_mod
from . import findings, owner, report, rules, schema, signin
from .mcp import Client
from .net import OUTSIDE_PER_SERVER, Budget, OutOfBudget, Session, scrub_deep

CLIENT_CHOICES = ("all",) + findings.CLIENTS
OWNER_ONLY = ("register", "interactive", "client_id", "calls_config", "auto_read")
OUTSIDE_MODE = ("Outside mode: this server is not verified as yours ({why}), so this run kept to what any outside "
                f"check may do: at most {OUTSIDE_PER_SERVER} requests per server, no client registration, no tool "
                "calls. Nothing was sent to Docka. For a full run on your own server, verify it once: docka-check "
                "verify --url <your MCP URL> --email <your email>.")
VERIFIED_MODE = "Full run: this server is verified as yours, so this report is also sent to Docka."
CRED_PARAM = re.compile(r"(?i)key|token|secret|auth|sig|pass|pwd|session|cred|code|bearer|jwt|tracker")


def _randomish(s):
    """A long run of letters and digits, as keys are: never a word, a date or a version."""
    return len(s) >= 16 and re.search(r"[A-Za-z]", s) is not None and re.search(r"\d", s) is not None


def url_parts(url):
    """(the URL as reports show it, the credentials written into it). Requests go to the URL as given. user:pass@, a
    credential-like query value, a long random path segment or host label and the fragment show as [credential], and
    every output is scrubbed of them. A query value under 8 characters is hidden only where it stands (scrubbing it
    from every text would cut words, so the same string elsewhere, even as a path segment, stays); an echo of the whole
    query string is scrubbed as one."""
    u = urlsplit(url)
    found = []
    userinfo, at, hostport = u.netloc.rpartition("@")
    if at:
        found += [userinfo] + [unquote(p) for p in userinfo.split(":", 1) if len(unquote(p)) >= 8]
    host, colon, port = hostport.rpartition(":") if hostport.count(":") == 1 else (hostport, "", "")
    found += [label for label in host.split(".") if _randomish(label)]
    segs = []
    for s in u.path.split("/"):
        hide = _randomish(unquote(s))
        found += [s, unquote(s)] if hide else []
        segs.append("[credential]" if hide else s)
    raw, pairs = [p for p in u.query.split("&") if p], []
    for pair in raw:
        k, _, v = pair.partition("=")
        hide = bool(v) and (CRED_PARAM.search(unquote_plus(k)) is not None or _randomish(unquote_plus(v)))
        found += [x for x in (v, unquote_plus(v)) if hide and len(x) >= 8]
        pairs.append(f"{k}=[credential]" if hide else pair)
    if pairs != raw:
        found.append(u.query)
    if len(u.fragment) >= 8:
        found.append(u.fragment)
    labels = ["[credential]" if _randomish(label) else label for label in host.split(".")]
    shown = urlunsplit((u.scheme, ("[credential]@" if at else "") + ".".join(labels) + colon + port, "/".join(segs),
                        "&".join(pairs), ""))
    return shown, [f for f in dict.fromkeys(found) if f]


def credentials(a):
    headers, secrets = {}, []
    if getattr(a, "token_env", None):
        tok = (os.environ.get(a.token_env) or "").strip()
        if not tok:
            sys.exit(f"docka-check: ${a.token_env} is empty")
        headers["Authorization"] = "Bearer " + tok
        secrets.append(tok)
    for spec in getattr(a, "header", None) or []:
        name, _, env = spec.partition("=")
        val = (os.environ.get(env) or "").strip()
        if not name or not val:
            sys.exit(f"docka-check: --header {spec}: give NAME=ENV_VAR with ${env} set")
        headers[name] = val
        secrets.append(val)
    return headers, secrets


def fetch_tools(url, headers, secrets, budget=None):
    s = Session([urlparse(url).hostname], budget=budget, secrets=secrets)
    c = Client(s, url, headers)
    try:
        r, msg = c.initialize()
        if not msg or "result" not in msg:
            return None, c.error
        tools, r, msg = c.tools()
    except OutOfBudget as e:
        return None, e.why()
    return tools, c.error


def run_tiers(a, tiers):
    headers, secrets = credentials(a)
    shown = None
    if getattr(a, "url", None):
        shown, in_url = url_parts(a.url)
        secrets = secrets + in_url
    secrets += [k for k in dict.fromkeys(((os.environ.get("DOCKA_CHECK_KEY") or "").strip(), a.key)) if k]
    results = []
    budget = Budget(per_host=OUTSIDE_PER_SERVER) if a.mode == "outside" else Budget()
    target = {"url": shown, "tools_file": getattr(a, "tools_file", None)}
    server = a.server_name or (urlparse(a.url).hostname.split(".")[0] if getattr(a, "url", None) else "server")
    if "signin" in tiers and a.url:
        cred_headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
        results.append(signin.check_signin(a.url, headers=cred_headers or None, secrets_=secrets,
                                           register=a.register, client_id=a.client_id, interactive=a.interactive,
                                           ask=signin.ask_tty, budget=budget, token="Authorization" in headers))
    if "schema" in tiers:
        if getattr(a, "tools_file", None):
            tools, err = schema.load_tools(a.tools_file), None
        elif a.url:
            tools, err = fetch_tools(a.url, headers, secrets, budget)
        else:
            tools, err = None, "give --tools-file or --url"
        if tools is None:
            results.append({"tier": "schema", "hits": {}, "skipped": {r: err for r in schema.SCHEMA_RULES}})
        else:
            results.append(schema.check_schema(tools, server_name=server))
    if "calls" in tiers and a.url:
        cfg = json.loads(Path(a.calls_config).read_text()) if a.calls_config else {}
        if a.mode == "outside":
            results.append({"tier": "calls", "hits": {}, "skipped": {r: "outside mode: tool calls run only on a server "
                                                                     "verified as yours" for r in calls_tier.CALLS_RULES}})
        elif not cfg and not a.auto_read:
            results.append({"tier": "calls", "hits": {}, "skipped": {r: "give --calls-config or --auto-read"
                                                                     for r in calls_tier.CALLS_RULES}})
        else:
            results.append(calls_tier.check_calls(a.url, headers, cfg, auto_read=a.auto_read, budget=budget))
    # a server can echo a credential into anything it returns (a tool name, a detail): scrub every tier's result
    return target, scrub_deep(results, secrets), secrets


def emit(a, target, results, secrets=()):
    table = rules.load()
    clients = findings.CLIENTS if a.client == "all" else (a.client,)
    ev = findings.evaluate(table, results, clients)
    r = report.build(table, target, results, ev, clients,
                     when=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    if a.mode == "outside" and not getattr(a, "tools_file", None):
        r["mode"] = OUTSIDE_MODE.format(why=a.why)
    elif a.mode == "verified":
        r["mode"] = VERIFIED_MODE
    text = report.FORMATS[a.format](r)
    code = 0
    if a.baseline:
        d = diff_mod.compare(json.loads(Path(a.baseline).read_text()), r)
        r["diff"] = d
        extra = ["", "### Since the baseline", ""] + diff_mod.lines(d, report.CLIENT_NAMES)
        text = report.FORMATS[a.format](r) if a.format == "json" else text + "\n".join(extra) + "\n"
        code = 1 if d["new_run_blockers"] else 0
    # last, after the baseline's text is in: nothing below writes or prints anything unscrubbed
    r, text = scrub_deep(r, secrets), scrub_deep(text, secrets)
    if a.out:
        Path(a.out).write_text(text)
        if a.json_out:
            Path(a.json_out).write_text(report.as_json(r))
    else:
        print(text)
        if a.json_out:
            Path(a.json_out).write_text(report.as_json(r))
    if a.mode == "verified":          # after the report is written: a failed upload never costs the owner the report
        print(scrub_deep(owner.upload(a.url, a.key, json.loads(report.as_json(r))), secrets), file=sys.stderr)
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(prog="docka-check", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, url_required=True):
        p.add_argument("--url", required=url_required, help="your MCP server's URL")
        p.add_argument("--token-env", help="env var holding your bearer token")
        p.add_argument("--header", action="append", help="NAME=ENV_VAR for a credential header (repeatable)")
        p.add_argument("--server-name", help="the name clients give your server (for Claude Code's 128-char rule)")
        p.add_argument("--client", default="all", choices=CLIENT_CHOICES)
        p.add_argument("--format", default="terminal", choices=sorted(report.FORMATS))
        p.add_argument("--out", help="write the report here")
        p.add_argument("--json-out", help="also write the JSON report here (the next run's --baseline)")
        p.add_argument("--baseline", help="a previous JSON report: show what changed; exit 1 on a new run-confirmed blocker")
        p.add_argument("--register", action="store_true",
                       help="register each client's redirect URI (a verified server only; clients deleted afterwards)")
        p.add_argument("--interactive", action="store_true", help="sign in in your browser to check the token")
        p.add_argument("--client-id", help="an existing OAuth client id, to check the authorization request")
        p.add_argument("--calls-config", help="JSON: {calls: [{tool, arguments}], promised_tools: [...]}")
        p.add_argument("--auto-read", action="store_true",
                       help="also call tools marked readOnlyHint: true that take no required input")
        p.add_argument("--tools-file", help="a saved tools/list instead of --url (schema only)")

    for name in ("check", "signin", "calls"):
        common(sub.add_parser(name))
    common(sub.add_parser("schema"), url_required=False)
    dp = sub.add_parser("diff")
    dp.add_argument("old")
    dp.add_argument("new")
    vp = sub.add_parser("verify", help="prove a server is yours, once; its full runs then send their report to Docka")
    vp.add_argument("--url", required=True, help="your MCP server's URL (only its origin is sent)")
    vp.add_argument("--email", help="first run: where Docka can reach you about this server")
    vp.add_argument("--wait", type=int, default=0, help="keep checking for the file this many seconds")
    kp = sub.add_parser("key", help="print a verified server's key, to pipe into a CI secret")
    kp.add_argument("--url", required=True)
    a = ap.parse_args(argv)

    if a.cmd == "verify":
        if owner.loopback(a.url):
            print("This server is on this machine: its full runs need no verification and send nothing to Docka.")
            return 0
        return owner.verify(a.url, a.email, wait=a.wait)
    if a.cmd == "key":
        key = owner.stored_key(a.url)
        if not key:
            sys.exit("docka-check key: this server is not verified on this machine: run docka-check verify first")
        print(key)
        return 0
    if a.cmd == "diff":
        d = diff_mod.compare(json.loads(Path(a.old).read_text()), json.loads(Path(a.new).read_text()))
        print("\n".join(diff_mod.lines(d, report.CLIENT_NAMES)))
        return 1 if d["new_run_blockers"] else 0
    tiers = {"check": ("signin", "schema", "calls"), "signin": ("signin",), "schema": ("schema",),
             "calls": ("calls",)}[a.cmd]
    if a.cmd == "schema" and not (a.url or a.tools_file):
        ap.error("schema needs --url or --tools-file")
    a.mode, a.key, a.why = owner.mode(a.url) if a.url else ("file", None, "")
    asked = ["--" + f.replace("_", "-") for f in OWNER_ONLY if getattr(a, f, None) not in (None, False)]
    if a.mode == "outside" and asked:
        hide = url_parts(a.url)[1] + [k for k in ((os.environ.get("DOCKA_CHECK_KEY") or "").strip(),) if k]
        ap.exit(2, scrub_deep(f"docka-check: {', '.join(asked)} {'needs' if len(asked) == 1 else 'need'} a server "
                              f"verified as yours ({a.why}). Verify it once: docka-check verify --url <your MCP URL> "
                              "--email <your email>\n", hide))
    target, results, secrets = run_tiers(a, tiers)
    return emit(a, target, results, secrets)


if __name__ == "__main__":
    sys.exit(main())
