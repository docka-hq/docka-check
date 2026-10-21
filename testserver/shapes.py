#!/usr/bin/env python3
"""
Our test server: an MCP host and an OAuth host of our own, switchable into each failure shape one of our runs or a
client's documentation shows. Each shape off is its fixed variant. Nothing here is a vendor's server, and the suite
calls nothing else.

  python3 testserver/shapes.py --port 8941 --as-port 8942 [--shape get403 --shape latin1 …]   # stand-alone
  from testserver.shapes import start; s = start({"get403"})                                     # in tests

Shapes (the rule each one reproduces, and the evidence for it, are in SHAPES):
  signin  get403, dcr_allowlist, scope_required, audience, consent_broken, headers3, api_key_only
  schema  schema_copilot (the F1-ROW, UNTYPED and REQ8 shapes in tools/list)
  calls   outschema_mismatch, latin1, big_result, drop_mcp_headers
The OAuth host approves at once, as a browser sign-in would after a click; `consent_broken` replaces that with a page
that never redirects back. Tokens are random, in memory, never logged.

FAULTS are not failures of a server's design but ways of getting no answer (a 503, a 429, a slow or failing call):
the tool must report each as "not checked", never as "not found" and never as a finding.
"""

import argparse, base64, hashlib, json, secrets, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

SHAPES = {
    "get403": ("OAUTH-DISC", "a tokenless GET answers 403 with no challenge; the path-form document is not served",
               "our run, 2026-10-08 (lab.docka.ai/guides/copilot-studio-mcp/, section 7)"),
    "dcr_allowlist": ("DCR-REDIRECT", "registration accepts Claude, ChatGPT and localhost, refuses Microsoft's redirect",
                      "our run, 2026-09-23 (lab.docka.ai/guides/copilot-studio-mcp/, section 6)"),
    "scope_required": ("SCOPE-DEFAULT", "an authorization request without scope is refused with access_denied",
                       "our run, 2026-10-16"),
    "audience": ("TOKEN-AUDIENCE", "a token requested without resource gets 401 at the MCP host",
                 "our run, 2026-10-08 (lab.docka.ai/guides/copilot-studio-mcp/, section 8)"),
    "consent_broken": ("CONSENT-PAGE", "the consent page never redirects back to the client",
                       "our run, 2026-09-24"),
    "headers3": ("HDR2", "three required credential headers, no OAuth",
                 "our run, 2026-10-13 (lab.docka.ai/guides/apideck-mcp/)"),
    "api_key_only": ("API-KEY-ONLY", "one API key header, no OAuth", "docs: ChatGPT cannot present custom API keys"),
    "schema_copilot": ("F1-ROW, UNTYPED, REQ8", "tools with the monday, Lucid and monday-search shapes",
                       "our runs, 2026-09-25 to 2026-10-05 (github.com/mondaycom/mcp/issues/499)"),
    "outschema_mismatch": ("RESULT-SCHEMA", "get_deal declares custom_fields an object and returns null",
                           "our run, 2026-09-24"),
    "outschema_ok": ("RESULT-SCHEMA", "the fixed variant: get_deal declares outputSchema and returns what it says",
                     "our run, 2026-09-24"),
    "latin1": ("RESULT-UTF8", "list_deals returns Latin-1 bytes in a body declared UTF-8",
               "our run, 2026-10-16"),
    "big_result": ("RESULT-SIZE", "list_deals returns about 130,000 characters (over Claude Code's 25,000 tokens)",
                   "docs: code.claude.com/docs/en/mcp"),
    "drop_mcp_headers": ("PROTOCOL-OPENING", "the 2026-07-28 opening is answered -32020, as when a gateway drops Mcp-Method",
                         "our run, 2026-10-16"),
}
FAULTS = {
    "wellknown_503": "every /.well-known/ path on the MCP host answers 503",
    "wellknown_429": "every /.well-known/ path on the MCP host answers 429",
    "call_slow": "get_deal answers after SLOW_S seconds",
    "call_error": "every tools/call answers a JSON-RPC error",
    "tools_endless": "every tools/list page carries a nextCursor",
    "echo_token": "tools/list adds a tool whose name carries the caller's bearer token",
    "endpoints_elsewhere": "the OAuth host's metadata names its endpoints on localhost, not 127.0.0.1",
    "as_8414_503": "the OAuth host answers 503 at oauth-authorization-server, 200 at openid-configuration",
}
SLOW_S = 3
MICROSOFT_REDIRECT = "global.consent.azure-apim.net"
LOCK = threading.Lock()
API_KEY, HEADER_KEYS = "test-key-not-a-secret", {"x-acme-key": "k1", "x-acme-app-id": "a1", "x-acme-consumer-id": "c1"}

DEAL_OUT = {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"},
                                             "custom_fields": {"type": "object"}},
            "required": ["id", "name", "custom_fields"]}
BASE_TOOLS = [
    {"name": "get_deal", "title": "Get a deal", "description": "Read one deal by id.",
     "inputSchema": {"type": "object", "properties": {"deal_id": {"type": "string"}}, "required": ["deal_id"]},
     "annotations": {"readOnlyHint": True}},
    {"name": "list_deals", "title": "List deals", "description": "List open deals.",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
     "annotations": {"readOnlyHint": True}}
]
COPILOT_SHAPES = [
    {"name": "create_items", "title": "Create items", "description": "monday's create_items shape (2026-09-23).",
     "inputSchema": {"type": "object", "required": ["boardId", "items"], "properties": {
         "boardId": {"type": "number"}, "items": {"type": "array", "items": {"type": "object", "required": ["name"],
                                                                         "properties": {"name": {"type": "string"},
                                                                                        "columnValues": {"type": "string"}}}}}},
     "annotations": {"readOnlyHint": False}},
    {"name": "create_org_chart", "title": "Create an org chart", "description": "Lucid's shape (2026-10-01).",
     "inputSchema": {"type": "object", "required": ["title", "nodes"], "properties": {
         "title": {"type": "string"}, "nodes": {"type": "array", "items": {}}}},
     "annotations": {"readOnlyHint": False}},
    {"name": "search", "title": "Search", "description": "monday's search with 8 required inputs (2026-10-05).",
     "inputSchema": {"type": "object", "required": ["searchType", "limit", "strategy", "workspaceIds", "boardIds",
                                                     "creatorIds", "docIds", "itemIds"],
                     "properties": {k: {"type": "string"} for k in ("searchType", "searchTerm", "limit", "strategy",
                                                                    "workspaceIds", "boardIds", "creatorIds", "docIds",
                                                                    "itemIds")}},
     "annotations": {"readOnlyHint": True}},
]


class World:
    """The shared state of one test setup: the shapes, both hosts' base URLs, clients, codes and tokens."""

    def __init__(self, shapes):
        self.shapes = set(shapes)
        unknown = self.shapes - set(SHAPES) - set(FAULTS)
        if unknown:
            raise ValueError(f"unknown shapes {sorted(unknown)}")
        self.mcp_base = self.as_base = None
        self.clients, self.codes, self.tokens, self.log, self.calls = {}, {}, {}, [], []
        self.static_token = None
        self.verify_token = None      # served at /.well-known/docka-verify.txt (ownership tests)
        self.verify_token_file = None # or read from this file on each request (an end-to-end test behind a tunnel)

    def on(self, shape):
        return shape in self.shapes


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60
    world = None
    role = None                   # "mcp" or "as"

    def log_message(self, *a):
        pass

    def send(self, status, body=b"", ctype="application/json", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(status)
        if body:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)
        u = urlparse(self.path)
        with LOCK:
            self.world.log.append({"role": self.role, "method": self.command, "path": u.path, "status": status,
                                   "query_keys": sorted(parse_qs(u.query)),
                                   "bearer": (self.headers.get("Authorization") or "").startswith("Bearer ")})

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        return self.as_get() if self.role == "as" else self.mcp_get()

    def do_POST(self):
        return self.as_post() if self.role == "as" else self.mcp_post()

    def do_DELETE(self):
        if self.role == "as" and urlparse(self.path).path.startswith("/register/"):
            return self.unregister()
        return self.send(204)

    # ---------------------------------------------------------------- MCP host
    def auth_ok(self):
        w = self.world
        if w.on("headers3"):
            return all(self.headers.get(k) == v for k, v in HEADER_KEYS.items())
        if w.on("api_key_only"):
            return self.headers.get("x-api-key") == API_KEY
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            return False
        if w.static_token and auth[7:] == w.static_token:       # demos and CI: a token set by the job
            return not w.on("audience")
        with LOCK:
            t = w.tokens.get(auth[7:])
        if not t or t["expires"] < time.time():
            return False
        if w.on("audience") and not t.get("resource"):
            return False
        return True

    def challenge(self):
        w = self.world
        if w.on("headers3") or w.on("api_key_only"):
            return {}
        return {"WWW-Authenticate": f'Bearer resource_metadata="{w.mcp_base}/.well-known/oauth-protected-resource/mcp"'}

    def mcp_get(self):
        w, path = self.world, urlparse(self.path).path
        if path.startswith("/.well-known/") and w.on("wellknown_503"):
            return self.send(503, {"error": "unavailable"})
        if path.startswith("/.well-known/") and w.on("wellknown_429"):
            return self.send(429, {"error": "slow down"}, headers={"Retry-After": "60"})
        if path == "/.well-known/docka-verify.txt" and (w.verify_token or w.verify_token_file):
            token = w.verify_token
            if not token:
                try:
                    token = Path(w.verify_token_file).read_text().strip()
                except OSError:
                    return self.send(404, {"error": "no token yet"})
            return self.send(200, token.encode(), ctype="text/plain")
        if path == "/.well-known/oauth-protected-resource/mcp":
            if w.on("get403") or w.on("headers3") or w.on("api_key_only"):
                return self.send(403 if w.on("get403") else 404, {"error": "not here"})
            return self.send(200, {"resource": w.mcp_base + "/mcp", "authorization_servers": [w.as_base],
                                   "bearer_methods_supported": ["header"]})
        if path == "/.well-known/oauth-protected-resource" and w.on("get403"):
            return self.send(200, {"resource": w.mcp_base + "/mcp", "authorization_servers": [w.as_base]})
        if path.startswith("/.well-known/"):
            return self.send(403 if w.on("get403") else 404, {"error": "not here"})
        if path == "/mcp":
            if not self.auth_ok():
                if w.on("get403"):
                    return self.send(403, {"message": "Forbidden"})
                return self.send(401, {"error": "invalid_token"}, headers=self.challenge())
            return self.send(405, {"error": "no SSE stream"}, headers={"Allow": "POST, DELETE"})
        return self.send(404, {"error": "not found"})

    def mcp_post(self):
        w, path, raw = self.world, urlparse(self.path).path, self.body()
        if path != "/mcp":
            return self.send(404, {"error": "not found"})
        if not self.auth_ok():
            if w.on("get403"):        # as on the server we recorded: only POST got the 401 naming the root-form document
                return self.send(401, {"error": "invalid_token"}, headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{w.mcp_base}/.well-known/oauth-protected-resource"'})
            return self.send(401, {"error": "invalid_token"}, headers=self.challenge())
        try:
            msg = json.loads(raw or b"{}")
        except ValueError:
            return self.send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
        if not isinstance(msg, dict):
            return self.send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "no batches"}})
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:
            return self.send(202)
        header_method = self.headers.get("Mcp-Method")
        if self.headers.get("MCP-Protocol-Version") == "2026-07-28" and header_method != method:
            # a vendor server's answer in our run when our proxy dropped the header (2026-10-16), as a gateway would
            return self.send(400, {"jsonrpc": "2.0", "id": mid, "error": {
                "code": -32020, "message": "mcp-method header does not match the request body's method"}})
        if method == "server/discover":
            if w.on("drop_mcp_headers"):
                return self.send(400, {"jsonrpc": "2.0", "id": mid, "error": {
                    "code": -32020, "message": "mcp-method header does not match the request body's method"}})
            return self.send(200, {"jsonrpc": "2.0", "id": mid, "result": {
                "supportedVersions": ["2025-06-18", "2026-07-28"], "capabilities": {"tools": {}},
                "serverInfo": {"name": "docka-shapes", "version": "1"}}})
        if method == "initialize":
            asked = (msg.get("params") or {}).get("protocolVersion") or "2025-06-18"
            return self.send(200, {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": asked, "capabilities": {"tools": {}},
                "serverInfo": {"name": "docka-shapes", "version": "1"}}}, headers={"Mcp-Session-Id": "s1"})
        if method == "tools/list":
            tools = [dict(t) for t in BASE_TOOLS] + (COPILOT_SHAPES if w.on("schema_copilot") else [])
            if w.on("outschema_mismatch") or w.on("outschema_ok"):
                tools[0]["outputSchema"] = DEAL_OUT
            if w.on("echo_token"):
                tokn = (self.headers.get("Authorization") or "")[7:]
                tools.append({"name": "echo_" + tokn, "title": "Echo", "description": "A tool named after the caller.",
                              "inputSchema": {"type": "object", "required": ["rows"],
                                              "properties": {"rows": {"type": "array", "items": {}}}}})
            page = {"tools": tools, **({"nextCursor": f"p{mid}"} if w.on("tools_endless") else {})}
            return self.send(200, {"jsonrpc": "2.0", "id": mid, "result": page})
        if method == "tools/call":
            return self.call(mid, msg.get("params") or {})
        if method == "ping":
            return self.send(200, {"jsonrpc": "2.0", "id": mid, "result": {}})
        return self.send(200, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"no {method}"}})

    def call(self, mid, params):
        w, name = self.world, params.get("name")
        with LOCK:
            w.calls.append({"tool": name})
        if w.on("call_error"):
            return self.send(200, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": "internal error"}})
        if name == "get_deal" and w.on("call_slow"):
            time.sleep(SLOW_S)
        if name == "get_deal":
            deal = {"id": (params.get("arguments") or {}).get("deal_id", "1"), "name": "Northwind annual",
                    "custom_fields": None if w.on("outschema_mismatch") else {}}
            res = {"content": [{"type": "text", "text": json.dumps(deal)}], "structuredContent": deal, "isError": False}
            return self.send(200, {"jsonrpc": "2.0", "id": mid, "result": res})
        if name == "list_deals":
            n = 1100 if w.on("big_result") else 3          # ~126,000 characters: over 25,000 tokens, under 150,000 characters
            rows = [{"id": str(i), "name": f"Deal {i}", "stage": "Négociation" if w.on("latin1") else "Negotiation",
                     "note": "x" * 60} for i in range(n)]
            text = json.dumps(rows, ensure_ascii=False)
            body = json.dumps({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": text}], "isError": False}}, ensure_ascii=False)
            data = body.encode("latin-1") if w.on("latin1") else body.encode("utf-8")
            return self.send(200, data, ctype="application/json; charset=utf-8")
        return self.send(200, {"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": f"{name} is not called by the read-only suite"}], "isError": True}})

    # ---------------------------------------------------------------- OAuth host
    def as_metadata(self):
        b = self.world.as_base
        e = b.replace("127.0.0.1", "localhost") if self.world.on("endpoints_elsewhere") else b
        return {"issuer": b, "authorization_endpoint": e + "/authorize", "token_endpoint": e + "/token",
                "registration_endpoint": e + "/register", "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"], "scopes_supported": ["mcp"],
                "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"]}

    def as_get(self):
        u = urlparse(self.path)
        if u.path == "/.well-known/oauth-authorization-server" and self.world.on("as_8414_503"):
            return self.send(503, {"error": "unavailable"})
        if u.path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            return self.send(200, self.as_metadata())
        if u.path == "/authorize":
            return self.authorize({k: v[0] for k, v in parse_qs(u.query).items()})
        return self.send(404, {"error": "not found"})

    def as_post(self):
        path = urlparse(self.path).path
        if path == "/register":
            return self.register()
        if path == "/token":
            return self.token()
        return self.send(404, {"error": "not found"})

    def register(self):
        try:
            req = json.loads(self.body() or b"{}")
        except ValueError:
            return self.send(400, {"error": "invalid_client_metadata"})
        uris = req.get("redirect_uris") or []
        if self.world.on("dcr_allowlist") and any(MICROSOFT_REDIRECT in u for u in uris):
            return self.send(400, {"error": "invalid_redirect_uri", "error_description": "Invalid redirect URI"})
        cid = "c_" + secrets.token_hex(6)
        rec = {"client_id": cid, "redirect_uris": uris,
               "token_endpoint_auth_method": req.get("token_endpoint_auth_method") or "none",
               "registration_client_uri": f"{self.world.as_base}/register/{cid}"}
        with LOCK:
            self.world.clients[cid] = rec
        return self.send(201, rec)

    def unregister(self):
        cid = urlparse(self.path).path.rsplit("/", 1)[-1]
        with LOCK:
            gone = self.world.clients.pop(cid, None)
        return self.send(204 if gone else 404)

    def authorize(self, q):
        w = self.world
        with LOCK:
            client = w.clients.get(q.get("client_id"))
        ruri = q.get("redirect_uri") or (client or {}).get("redirect_uris", [None])[0]
        if not client or ruri not in client["redirect_uris"]:
            return self.send(400, b"unknown client or redirect", ctype="text/plain")
        if w.on("scope_required") and not q.get("scope"):
            return self.send(302, headers={"Location": ruri + "?" + urlencode(
                {"error": "access_denied", "state": q.get("state", ""), "iss": w.as_base})})
        if w.on("consent_broken"):
            return self.send(200, b"<html><body><button onclick='createConsent()'>Allow</button></body></html>",
                             ctype="text/html")
        code = secrets.token_urlsafe(16)
        with LOCK:
            w.codes[code] = {"client_id": client["client_id"], "redirect_uri": ruri, "resource": q.get("resource"),
                             "challenge": q.get("code_challenge"), "expires": time.time() + 300}
        return self.send(302, headers={"Location": ruri + ("&" if "?" in ruri else "?") + urlencode(
            {"code": code, "state": q.get("state", ""), "iss": w.as_base})})

    def token(self):
        w = self.world
        form = {k: v[0] for k, v in parse_qs(self.body().decode()).items()}
        with LOCK:
            c = w.codes.pop(form.get("code", ""), None)
        if form.get("grant_type") != "authorization_code" or not c or c["expires"] < time.time():
            return self.send(400, {"error": "invalid_grant"})
        if c["challenge"]:
            v = form.get("code_verifier", "")
            calc = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
            if calc != c["challenge"]:
                return self.send(400, {"error": "invalid_grant", "error_description": "PKCE"})
        tok = secrets.token_urlsafe(24)
        with LOCK:
            w.tokens[tok] = {"client_id": c["client_id"], "resource": c["resource"] or form.get("resource"),
                             "expires": time.time() + 3600}
        return self.send(200, {"access_token": tok, "token_type": "Bearer", "expires_in": 3600},
                         headers={"Cache-Control": "no-store"})


class Running:
    def __init__(self, world, servers):
        self.world, self.servers = world, servers

    @property
    def url(self):
        return self.world.mcp_base + "/mcp"

    def stop(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()

    def mint_token(self, resource=True):
        """A token as a completed sign-in would leave it (for calls and schema tests that skip sign-in)."""
        tok = secrets.token_urlsafe(24)
        with LOCK:
            self.world.tokens[tok] = {"client_id": "test", "resource": self.url if resource else None,
                                      "expires": time.time() + 3600}
        return tok


def start(shapes=(), port=0, as_port=0, host="127.0.0.1"):
    world = World(shapes)
    servers = []
    for role, p in (("mcp", port), ("as", as_port)):
        h = type(f"H_{role}", (Handler,), {"world": world, "role": role})
        s = ThreadingHTTPServer((host, p), h)
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
        base = f"http://{host}:{s.server_address[1]}"
        if role == "mcp":
            world.mcp_base = base
        else:
            world.as_base = base
    return Running(world, servers)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--port", type=int, default=8941)
    ap.add_argument("--as-port", type=int, default=8942)
    ap.add_argument("--shape", action="append", default=[], choices=sorted(SHAPES) + sorted(FAULTS))
    ap.add_argument("--static-token-env", help="accept the bearer token in this env var (demos and CI only)")
    ap.add_argument("--verify-token-file", help="serve the docka-check verify token in this file (read on each "
                                                "request) at /.well-known/docka-verify.txt")
    a = ap.parse_args()
    r = start(a.shape, a.port, a.as_port)
    r.world.verify_token_file = a.verify_token_file
    if a.static_token_env:
        import os
        r.world.static_token = os.environ.get(a.static_token_env) or None
    print(json.dumps({"mcp": r.url, "as": r.world.as_base, "shapes": sorted(r.world.shapes)}), flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
