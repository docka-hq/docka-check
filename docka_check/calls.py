"""`calls` (read-only) — call the read tools the owner lists and hold each result against its own schema and each
client's documented limits. Nothing is called on the strength of its name: only the owner's list, plus, with
--auto-read, tools marked readOnlyHint: true that take no required input.

    config = {"calls": [{"tool": "get_deal", "arguments": {"deal_id": "42"}}],
              "promised_tools": ["update_deal"]}                       # optional: tools your docs promise

A call that got no result (a transport error, a 5xx, a 429, a JSON-RPC error) concludes nothing about its result:
when no call returned one, the result rules are "not checked" with the reason. A call still unanswered past
claude.ai's limit is a CALL-TIME finding, so each call waits CALL_MARGIN_S beyond it.
"""

import json
import time
from urllib.parse import urlparse

from .jsonschema_lite import errors as schema_errors
from .mcp import Client, rpc_messages
from .net import OutOfBudget, Session, scrub_deep

CALLS_RULES = ("RESULT-SCHEMA", "RESULT-SIZE", "CALL-TIME", "RESULT-UTF8", "PROTOCOL-OPENING", "MISSING-PROMISED-TOOL")
RESULT_RULES = ("RESULT-SCHEMA", "RESULT-SIZE", "RESULT-UTF8")
CLAUDE_CODE_CUT_TOKENS, CLAUDE_CODE_WARN_TOKENS = 25_000, 10_000      # MAX_MCP_OUTPUT_TOKENS default (docs)
CLAUDE_AI_CHARS, CLAUDE_AI_SECONDS = 150_000, 240                      # claude.ai connector limits (docs)
CALL_MARGIN_S = 60
# OpenAI's MCP client's opening, as our proxy logged it on 2026-10-16 (owner4 fix proofs): MCP 2026-07-28
OPENAI_OPENING = {"jsonrpc": "2.0", "id": "openai-mcp-discover", "method": "server/discover", "params": {"_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "docka-check (replaying openai-mcp)", "version": "0.1"}}}}


def plan(tools, config, auto_read=False):
    """Exactly what will be called, decided before any call: the owner's list, plus --auto-read's rule."""
    out = [{"tool": c["tool"], "arguments": c.get("arguments") or {}, "why": "listed by the owner"}
           for c in config.get("calls", [])]
    if auto_read:
        listed = {c["tool"] for c in out}
        for t in tools:
            ann, req = t.get("annotations") or {}, (t.get("inputSchema") or {}).get("required") or []
            if ann.get("readOnlyHint") is True and not req and t.get("name") not in listed:
                out.append({"tool": t["name"], "arguments": {}, "why": "readOnlyHint: true, no required input"})
    return out


def _result_text(result):
    parts = [c.get("text", "") for c in (result or {}).get("content", []) if isinstance(c, dict)]
    if (result or {}).get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    return "".join(parts)


def check_calls(url, headers=None, config=None, auto_read=False, opening=True, budget=None):
    config = config or {}
    s = Session([urlparse(url).hostname], budget=budget, secrets=list((headers or {}).values()))
    c = Client(s, url, headers)
    hits = {r: [] for r in CALLS_RULES}

    def none_checked(why):
        return scrub_deep({"tier": "calls", "hits": {}, "skipped": {r: why for r in CALLS_RULES}, "calls": [],
                           "requests": s.log}, s.secrets)
    try:
        r, msg = c.initialize()
        if not msg or "result" not in msg:
            return none_checked(f"initialize failed ({c.error})")
        tools, r, msg = c.tools()
    except OutOfBudget as e:
        return none_checked(e.why())
    if tools is None:
        return none_checked(c.error)
    by_name = {t["name"]: t for t in tools}
    todo = plan(tools, config, auto_read)
    allowed = {p["tool"] for p in todo}
    records, stopped = [], None
    with_result, failed = 0, []
    schema_tools, schema_checked = 0, 0
    for p in todo:
        name = p["tool"]
        if name not in by_name:
            records.append({"tool": name, "called": False, "why": "not served by tools/list"})
            continue
        if stopped:
            records.append({"tool": name, "called": False, "why": stopped})
            continue
        assert name in allowed
        out_schema = by_name[name].get("outputSchema")
        schema_tools += bool(out_schema)
        t0 = time.monotonic()
        try:
            resp, m = c.call(name, p["arguments"], timeout=CLAUDE_AI_SECONDS + CALL_MARGIN_S)
        except OutOfBudget as e:
            stopped = e.why()
            records.append({"tool": name, "called": False, "why": stopped})
            continue
        secs = time.monotonic() - t0
        rec = {"tool": name, "called": True, "status": resp.status, "seconds": round(secs, 2), "bytes": len(resp.raw)}
        if secs > CLAUDE_AI_SECONDS:
            hits["CALL-TIME"].append({"tool": name, "detail": (f"{secs:.0f} s" if resp.status is not None else
                                                               f"no answer within {secs:.0f} s")
                                      + f"; claude.ai allows {CLAUDE_AI_SECONDS} s"})
        if not resp.answered:
            rec["error"] = resp.why()
            failed.append(f"{name}: {resp.why()}")
            records.append(rec)
            continue
        try:
            resp.raw.decode("utf-8")
            rec["utf8"] = True
        except UnicodeDecodeError as e:
            rec["utf8"] = False
            hits["RESULT-UTF8"].append({"tool": name, "detail": f"byte 0x{resp.raw[e.start]:02x} at {e.start} is not UTF-8"})
            m = next((x for x in rpc_messages(resp.raw.decode("latin-1").encode(), resp.header("content-type"))
                      if x.get("id") == c.n), m)
        result = (m or {}).get("result")
        if result is None:
            err = (m or {}).get("error")
            rec["error"] = s.scrub(f"error {err.get('code')}: {str(err.get('message'))[:100]}") if err else \
                f"HTTP {resp.status}, no JSON-RPC result"
            failed.append(f"{name}: {rec['error']}")
            records.append(rec)
            continue
        with_result += 1
        text = _result_text(result)
        rec["chars"], rec["est_tokens"] = len(text), len(text) // 4
        if rec["est_tokens"] > CLAUDE_CODE_CUT_TOKENS:
            hits["RESULT-SIZE"].append({"tool": name, "clients": ["claude-code"],
                                        "detail": f"~{rec['est_tokens']:,} tokens; Claude Code cuts at {CLAUDE_CODE_CUT_TOKENS:,}"})
        elif rec["est_tokens"] > CLAUDE_CODE_WARN_TOKENS:
            rec["note"] = f"~{rec['est_tokens']:,} tokens: Claude Code warns above {CLAUDE_CODE_WARN_TOKENS:,}"
        if rec["chars"] > CLAUDE_AI_CHARS:
            hits["RESULT-SIZE"].append({"tool": name, "clients": ["claude-ai"],
                                        "detail": f"{rec['chars']:,} characters; claude.ai caps at about {CLAUDE_AI_CHARS:,}"})
        if out_schema and not result.get("isError"):
            schema_checked += 1
            sc = result.get("structuredContent")
            errs = [("$", "outputSchema declared, no structuredContent returned")] if sc is None else \
                schema_errors(sc, out_schema)
            if errs:
                rec["schema_errors"] = [f"{p}: {e}" for p, e in errs[:5]]
                hits["RESULT-SCHEMA"].append({"tool": name, "detail": "; ".join(rec["schema_errors"][:3])})
        records.append(rec)
    # the result rules (and the time a call takes) are concluded only from calls that returned a result
    skipped, notes = {}, []
    called = [x for x in records if x.get("called")]
    if not with_result:
        if called:
            why = "no call returned a result: " + "; ".join(failed[:3])
        elif stopped:
            why = stopped
        elif todo:
            why = "none of the listed tools is served by tools/list"
        else:
            why = "no call was planned"
        skipped.update({r: why for r in RESULT_RULES + ("CALL-TIME",) if not hits[r]})
    elif schema_tools and not schema_checked and not hits["RESULT-SCHEMA"]:
        skipped["RESULT-SCHEMA"] = "every call to a tool with an outputSchema failed or returned isError"
    if stopped:
        not_made = sum(1 for x in records if not x.get("called") and x.get("why") == stopped)
        notes.append(f"calls: {not_made} of {len(todo)} planned calls were not made ({stopped})")
    if failed and with_result:
        notes.append(f"calls: {len(failed)} returned no result, so only the others were checked ({'; '.join(failed[:3])})")
    for name in config.get("promised_tools") or []:
        if name not in by_name:
            hits["MISSING-PROMISED-TOOL"].append({"tool": name, "detail": "promised by your docs, not in tools/list"})
    if not config.get("promised_tools"):
        skipped["MISSING-PROMISED-TOOL"] = "list the tools your docs promise in the config (promised_tools)"
    if not opening:
        skipped["PROTOCOL-OPENING"] = "skipped (--no-opening)"
    elif stopped:
        skipped["PROTOCOL-OPENING"] = stopped
    else:
        try:
            resp = s.request("POST", url, OPENAI_OPENING, {"Accept": "application/json, text/event-stream",
                                                           "MCP-Protocol-Version": "2026-07-28",
                                                           "Mcp-Method": "server/discover", **(headers or {})})
        except OutOfBudget as e:
            resp = None
            skipped["PROTOCOL-OPENING"] = e.why()
        if resp is not None and not resp.answered:
            skipped["PROTOCOL-OPENING"] = f"the 2026-07-28 opening got no answer ({resp.why()})"
        elif resp is not None:
            m = next(iter(rpc_messages(resp.raw, resp.header("content-type"))), None) or {}
            err = m.get("error") or {}
            rec = {"tool": None, "opening": "server/discover (MCP 2026-07-28)", "status": resp.status,
                   "error_code": err.get("code"), "error": s.scrub(str(err.get("message")))[:120] if err else None}
            if err.get("code") == -32020 or "mcp-method" in str(err.get("message", "")).lower():
                hits["PROTOCOL-OPENING"].append({"tool": None, "detail": f"{resp.status}, {err.get('code')}: {rec['error']}"})
            records.append(rec)
    return scrub_deep({"tier": "calls", "hits": hits, "skipped": skipped, "notes": notes, "calls": records,
                       "plan": todo, "requests": s.log}, s.secrets)
