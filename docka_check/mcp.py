"""A minimal MCP client over Streamable HTTP: initialize, tools/list (all pages), tools/call. No model, no writes
unless the caller asks for a tool by name. Credentials come in as headers and never leave this process."""

import json
import re

PROTOCOL = "2025-06-18"
CLIENT_INFO = {"name": "docka-check", "version": "0.1"}


def rpc_messages(raw, ctype):
    """JSON-RPC messages in a JSON or an SSE body."""
    if not raw:
        return []
    texts = [raw]
    if "text/event-stream" in (ctype or "") or raw.lstrip().startswith((b"event:", b"data:", b":")):
        texts, cur = [], []
        for line in raw.splitlines():
            if line.startswith(b"data:"):
                cur.append(line[5:].strip())
            elif not line.strip() and cur:
                texts.append(b"\n".join(cur))
                cur = []
        if cur:
            texts.append(b"\n".join(cur))
    out = []
    for t in texts:
        try:
            m = json.loads(t)
        except ValueError:
            continue
        out.extend(m if isinstance(m, list) else [m])
    return [m for m in out if isinstance(m, dict) and m.get("jsonrpc") == "2.0"]


def challenge(www):
    """WWW-Authenticate → {"scheme": "bearer", "resource_metadata": …, …} or None."""
    if not www:
        return None
    scheme = www.strip().split(" ", 1)[0].lower()
    params = {k.lower(): v for k, v in re.findall(r'([A-Za-z_]+)="([^"]*)"', www)}
    return {"scheme": scheme, **params}


class Client:
    def __init__(self, session, url, headers=None):
        self.s, self.url, self.headers = session, url, dict(headers or {})
        self.sid, self.version, self.n = None, PROTOCOL, 0
        self.error = None                 # why the last initialize or tools/list gave nothing

    def _post(self, method, params=None, notify=False, extra=None, timeout=None):
        self.n += 1
        body = {"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})}
        if not notify:
            body["id"] = self.n
        h = {"Accept": "application/json, text/event-stream", **self.headers, **(extra or {})}
        if method != "initialize":
            h["MCP-Protocol-Version"] = self.version
            if self.sid:
                h["Mcp-Session-Id"] = self.sid
        r = self.s.request("POST", self.url, body, h, **({"timeout": timeout} if timeout else {}))
        msg = None if notify else next((m for m in rpc_messages(r.raw, r.header("content-type")) if m.get("id") == self.n), None)
        return r, msg

    def _why(self, method, r, msg):
        err = (msg or {}).get("error")
        if err:
            return self.s.scrub(f"{method} answered error {err.get('code')}: {str(err.get('message'))[:100]}")
        return f"{method} answered {r.why()}"

    def initialize(self):
        r, msg = self._post("initialize", {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": CLIENT_INFO})
        if msg and "result" in msg:
            self.sid = r.header("mcp-session-id")
            self.version = msg["result"].get("protocolVersion") or PROTOCOL
            self._post("notifications/initialized", notify=True)
        else:
            self.error = self._why("initialize", r, msg)
        return r, msg

    def tools(self, max_pages=20):
        """Every page of tools/list, or None with self.error saying why: a partial list is never returned."""
        tools, cursor = [], None
        for _ in range(max_pages):
            r, msg = self._post("tools/list", {"cursor": cursor} if cursor else {})
            if not msg or "result" not in msg:
                self.error = self._why("tools/list", r, msg)
                return None, r, msg
            tools += msg["result"].get("tools") or []
            cursor = msg["result"].get("nextCursor")
            if not cursor:
                return tools, r, msg
        self.error = f"tools/list has more than {max_pages} pages"
        return None, r, msg

    def call(self, name, arguments, timeout=None):
        return self._post("tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout)
