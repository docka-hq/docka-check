"""`signin` — replay each client's sign-in on the owner's server, step by step, as recorded or documented.

Copilot Studio's path is the one we recorded on the wire on 2026-10-17 (lab.docka.ai/guides/copilot-studio-mcp/,
section 7): a tokenless GET; the protected-resource document named in its
401, else the path form; then the metadata at the host the document names; only with no document at all, metadata
on the MCP host, at the four URLs our proxy log of 2026-10-08 shows it asking for (guide §7). claude.ai, ChatGPT and
Claude Code follow the MCP spec as their docs describe: the challenge, then the path form, then the root form;
claude.ai reads only the first authorization server, ChatGPT tries every one.

A conclusion needs an answer. A step that got none (a transport error, a 5xx, a 429, the request limit) makes the
rules that depend on it "not checked" with the reason, never "not found" and never a finding.

Requests go only to the MCP host and the authorization servers its documents name. Client registration happens only
with `--register` (your own server only) and is undone afterwards where the server allows it (RFC 7592).
"""

import base64
import hashlib
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from .mcp import CLIENT_INFO, PROTOCOL, challenge, rpc_messages
from .net import HostNotAllowed, OutOfBudget, Session, scrub_deep

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": CLIENT_INFO}}
ACCEPT = "application/json, text/event-stream"
SIGNIN_RULES = ("OAUTH-DISC", "OAUTH-DISC-PARTIAL", "AS-FIRST", "NO-DCR", "PKCE-S256", "ISS-9207", "HDR2",
                "API-KEY-ONLY", "SSE-ONLY", "DCR-REDIRECT", "SCOPE-DEFAULT", "TOKEN-AUDIENCE", "CONSENT-PAGE")
OAUTH_RULES = ("OAUTH-DISC", "OAUTH-DISC-PARTIAL", "AS-FIRST", "NO-DCR", "PKCE-S256", "ISS-9207", "DCR-REDIRECT",
               "SCOPE-DEFAULT", "TOKEN-AUDIENCE", "CONSENT-PAGE")
PER_CLIENT_RULES = ("NO-DCR", "PKCE-S256", "ISS-9207", "DCR-REDIRECT", "SCOPE-DEFAULT", "TOKEN-AUDIENCE", "CONSENT-PAGE")
CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
CHATGPT_REDIRECT_NO_ISS = "https://chatgpt.com/connector/oauth/{callback_id}"       # ChatGPT fills in its own id
CHATGPT_REGISTER_NO_ISS = "https://chatgpt.com/connector/oauth/docka-check-test"    # a stand-in for --register


def redirects(chatgpt_iss=True, port=33418):
    """Each client's redirect URI(s) for registration (Copilot's in the form seen in our runs, the others from their
    docs)."""
    return {
        "copilot-studio": ["https://global.consent.azure-apim.net/redirect",
                           "https://global.consent.azure-apim.net/redirect/cr000-5fdocka-2dcheck-5f0000000000000000"],
        "claude-ai": ["https://claude.ai/api/mcp/auth_callback"],
        "chatgpt": [CHATGPT_REDIRECT if chatgpt_iss else CHATGPT_REGISTER_NO_ISS],
        "claude-code": [f"http://localhost:{port}/callback"],
    }


def _base(url):
    u = urlparse(url)
    return f"{u.scheme}://{u.netloc}", u.path.rstrip("/")


def _doc(resp):
    d = resp.json() if resp.status == 200 else None
    return d if isinstance(d, dict) and (d.get("resource") or d.get("authorization_servers")) else None


def _meta(resp):
    d = resp.json() if resp.status == 200 else None
    return d if isinstance(d, dict) and (d.get("issuer") or d.get("authorization_endpoint")) else None


def as_metadata_urls(issuer):
    """RFC 8414 (path inserted after the well-known prefix), then OpenID Connect discovery."""
    base, path = _base(issuer)
    return [f"{base}/.well-known/oauth-authorization-server{path}", f"{base}/.well-known/openid-configuration{path}"]


def copilot_host_metadata_urls(base, path):
    """Where Copilot looks on the MCP host when it finds no document: the four URLs it asked for in our proxy log of
    2026-10-08."""
    urls = [f"{base}/.well-known/oauth-authorization-server{path}", f"{base}/.well-known/oauth-authorization-server",
            f"{base}/.well-known/openid-configuration{path}", f"{base}{path}/.well-known/openid-configuration"]
    return list(dict.fromkeys(urls))


class Discovery:
    """What one server answers, fetched once and read along each client's path.

    Each fetched document is a dict (found), False (the server answered, and it is not there) or None (no answer;
    `unknown[url]` says why)."""

    def __init__(self, session, url, headers=None):
        self.s, self.url = session, url
        self.base, self.path = _base(url)
        self.docs, self.metas, self.unknown = {}, {}, {}
        get, self.get_why = self.send("GET", url, headers={"Accept": ACCEPT, **(headers or {})})
        post, self.post_why = self.send("POST", url, INIT, {"Accept": ACCEPT, **(headers or {})})
        self.get = {"status": get.status if get else None, "ctype": get.header("content-type") if get else None,
                    "challenge": challenge(get.header("www-authenticate")) if get and not self.get_why else None}
        self.post = {"status": post.status if post else None,
                     "challenge": challenge(post.header("www-authenticate")) if post and not self.post_why else None}
        self.reached = any(x is not None and x.status is not None for x in (get, post))
        msg = None if self.post_why else \
            next((m for m in rpc_messages(post.raw, post.header("content-type")) if m.get("id") == 1), None)
        self.open = bool(msg and "result" in msg)
        self.oauth = any((x["challenge"] or {}).get("scheme") == "bearer" for x in (self.get, self.post)
                         if x["status"] in (401, 403))
        self.decided = self.oauth or self.open or not (self.get_why or self.post_why)
        # a 404 to a tokenless initialize: nothing serves MCP at this URL, or a server that hides from such calls
        self.missing = (not self.post_why and self.post["status"] in (404, 410)
                        and "text/event-stream" not in (self.get["ctype"] or ""))

    def send(self, method, url, body=None, headers=None):
        """(response, None) for an answer; (response or None, why) when there was none."""
        try:
            r = self.s.request(method, url, body, headers)
        except OutOfBudget as e:
            return None, e.why()
        except HostNotAllowed as e:
            return None, f"on another host ({e}), not followed"
        return r, (None if r.answered else r.why())

    def allow_endpoints(self, m):
        """The endpoints an authorization server's own metadata names are that server's, wherever they live."""
        for key in ("registration_endpoint", "authorization_endpoint", "token_endpoint"):
            host = urlparse(m.get(key) or "").hostname
            if host:
                self.s.allow(host)

    def named(self, which):
        x = self.get if which == "get" else self.post
        return (x["challenge"] or {}).get("resource_metadata") if x["status"] == 401 else None

    def path_form(self):
        return f"{self.base}/.well-known/oauth-protected-resource{self.path}"

    def root_form(self):
        return f"{self.base}/.well-known/oauth-protected-resource"

    def _fetch(self, url, parse):
        r, why = self.send("GET", url, headers={"Accept": "application/json"})
        if why:
            self.unknown[url] = why
            return None
        return parse(r) or False

    def doc(self, url):
        if url not in self.docs:
            self.docs[url] = self._fetch(url, _doc)
        return self.docs[url]

    def meta(self, url):
        if url not in self.metas:
            self.metas[url] = self._fetch(url, _meta)
        return self.metas[url]

    def _first(self, urls):
        """(url, metadata, unanswered): metadata at the first URL that has it, else False when every URL answered and
        None when one did not; `unanswered` lists the URLs before that point that got no answer."""
        before = []
        for u in urls:
            m = self.meta(u)
            if m:
                self.allow_endpoints(m)
                return u, m, before
            if m is None:
                before.append(f"{u}: {self.unknown[u]}")
        return None, (None if before else False), before

    def as_meta(self, issuer):
        host = urlparse(issuer).hostname
        if host:
            self.s.allow(host)                # an authorization server the document names
        return self._first(as_metadata_urls(issuer))

    def host_meta(self):
        """Copilot's fallback when it finds no document."""
        return self._first(copilot_host_metadata_urls(self.base, self.path))


def _found(x):
    return True if x else (None if x is None else False)


def client_path(d, client):
    """One client's discovery path: which document it reads, which authorization server, which metadata. A path with
    a step that got no answer is `undetermined` (the reasons), and nothing is concluded from it."""
    out = {"steps": [], "undetermined": []}
    if client == "copilot-studio":
        if d.get_why:
            out["undetermined"].append(f"the tokenless GET: {d.get_why}")
            out["discovered"] = False
            out["authorization_servers"] = []
            return out
        cands = ([("named by the 401 to GET", d.named("get"))] if d.named("get") else []) + \
            [("path form", d.path_form())]
    else:
        if d.post_why:
            out["undetermined"].append(f"the tokenless POST: {d.post_why}")
            out["discovered"] = False
            out["authorization_servers"] = []
            return out
        named = d.named("post") or d.named("get")
        cands = ([("named by the 401", named)] if named else []) + [("path form", d.path_form()),
                                                                  ("root form", d.root_form())]
    for how, url in cands:
        doc = d.doc(url)
        out["steps"].append({"step": f"protected-resource document ({how})", "url": url, "found": _found(doc)})
        if doc:
            out["document"], out["document_how"] = url, how
            break
        if doc is None:
            out["undetermined"].append(f"{url}: {d.unknown[url]}")
    entries = (d.docs.get(out.get("document")) or {}).get("authorization_servers") or []
    out["authorization_servers"] = entries
    tried = entries[:1] if client in ("claude-ai", "copilot-studio") else entries
    for issuer in tried:
        url, m, before = d.as_meta(issuer)
        out["steps"].append({"step": "authorization-server metadata", "issuer": issuer, "url": url, "found": _found(m)})
        out["undetermined"] += before
        if m:
            out["issuer"], out["metadata"] = issuer, m
            break
    if client == "copilot-studio" and "document" not in out:
        url, m, before = d.host_meta()
        out["steps"].append({"step": "metadata on the MCP host (fallback)", "url": url, "found": _found(m)})
        out["undetermined"] += before
        if m:
            out["issuer"], out["metadata"], out["fallback"] = m.get("issuer"), m, True
    out["discovered"] = "metadata" in out
    return out


def usable(p):
    """A path to conclude from: metadata found, and no step before it went unanswered (a client's behaviour on a 5xx
    or a timeout is not recorded, so a later find may not be where the client ends up)."""
    return bool(p) and p["discovered"] and not p["undetermined"]


def check_signin(url, headers=None, secrets_=(), register=False, client_id=None, interactive=False,
                 open_browser=None, callback_port=33418, interactive_wait=180, ask=None, budget=None,
                 clients=("copilot-studio", "claude-ai", "chatgpt", "claude-code"), token=False):
    """The signin tier. `headers` are the owner's credentials for key-based servers (values never recorded); `token`
    says the owner also gave a bearer token. Without either, a server that refuses a tokenless call and offers no OAuth
    leaves the credential rules not checked: how many credentials it needs is unknown."""
    s = Session([urlparse(url).hostname], budget=budget, secrets=list(secrets_) + list((headers or {}).values()))
    d = Discovery(s, url)
    hits = {r: [] for r in SIGNIN_RULES}
    skipped, by_client = {}, {}

    def skip_client(rule, client, why):
        by_client.setdefault(rule, {}).setdefault(client, why)

    def result(**extra):
        # everything the server sent back is in here (challenges, metadata, details): scrub all of it
        return scrub_deep({"tier": "signin", "hits": hits, "skipped": skipped, "skipped_clients": by_client,
                           "open_without_token": d.open, "oauth": d.oauth, "get": d.get, "post": d.post, **extra,
                           "requests": s.log}, s.secrets)

    if not d.reached:
        why = f"the server did not answer ({d.get_why or d.post_why})"
        skipped.update({r: why for r in SIGNIN_RULES})
        return result(paths={}, registered=[])
    if d.missing:
        why = (f"initialize without credentials answered HTTP {d.post['status']}: nothing serves MCP at this URL, or "
               "the server hides from calls without credentials")
        skipped.update({r: why for r in SIGNIN_RULES})
        return result(paths={}, registered=[])

    # the other clients first: under a request limit, Copilot's long fallback is what goes unchecked
    order = [c for c in clients if c != "copilot-studio"] + [c for c in clients if c == "copilot-studio"]
    found_paths = {c: client_path(d, c) for c in order} if d.oauth else {}
    paths = {c: found_paths[c] for c in clients if c in found_paths}

    # transport: SSE only when POST is refused and GET opens an event stream
    if d.post_why:
        skipped["SSE-ONLY"] = f"the tokenless POST got no answer ({d.post_why})"
    elif d.post["status"] in (404, 405):
        if d.get_why:
            skipped["SSE-ONLY"] = f"the tokenless GET got no answer ({d.get_why})"
        elif "text/event-stream" in (d.get["ctype"] or ""):
            hits["SSE-ONLY"].append({"tool": None, "detail": "POST refused, GET opens an SSE stream"})

    if not d.oauth:
        why = "the server does not ask for OAuth" if d.decided else \
            f"cannot tell whether the server asks for OAuth ({d.get_why or d.post_why})"
        skipped.update({r: why for r in OAUTH_RULES})
    else:
        cp = paths.get("copilot-studio")
        if cp and cp["undetermined"]:
            skipped["OAUTH-DISC"] = skipped["OAUTH-DISC-PARTIAL"] = \
                "Copilot's path got no answer: " + "; ".join(cp["undetermined"])
        elif cp and not cp["discovered"]:
            hits["OAUTH-DISC"].append({"tool": None, "clients": ["copilot-studio"],
                                       "detail": "; ".join(f"{x['step']}: not found" for x in cp["steps"])})
        elif cp and not cp.get("fallback"):
            iss_host = urlparse(cp["issuer"] or "").hostname
            if iss_host and iss_host != urlparse(url).hostname:
                hits["OAUTH-DISC-PARTIAL"].append({"tool": None, "detail": f"metadata on {iss_host}, not the MCP host"})
        ca = paths.get("claude-ai")
        if ca and ca["undetermined"]:
            skipped["AS-FIRST"] = "claude.ai's path got no answer: " + "; ".join(ca["undetermined"])
        elif ca and len(ca["authorization_servers"]) > 1 and not ca["discovered"]:
            others = []
            for issuer in ca["authorization_servers"][1:]:
                _, m, before = d.as_meta(issuer)
                others.append(None if before else m)
            if any(others):
                hits["AS-FIRST"].append({"tool": None, "clients": ["claude-ai"],
                                         "detail": f"first entry {ca['authorization_servers'][0]} unreadable"})
            elif any(o is None for o in others):
                skipped["AS-FIRST"] = "the other authorization servers gave no answer"
        for client, p in paths.items():
            if not usable(p):
                why = ("no answer on its sign-in path: " + "; ".join(p["undetermined"])) if p["undetermined"] else \
                    "no authorization-server metadata on its sign-in path"
                for r in PER_CLIENT_RULES:
                    skip_client(r, client, why)
                continue
            m = p["metadata"]
            if not m.get("registration_endpoint") and not m.get("client_id_metadata_document_supported"):
                hits["NO-DCR"].append({"tool": None, "clients": [client], "detail": "no registration_endpoint, no CIMD"})
            if "S256" not in (m.get("code_challenge_methods_supported") or []):
                hits["PKCE-S256"].append({"tool": None, "clients": [client], "detail": "S256 not advertised"})
            if client == "chatgpt":
                iss = bool(m.get("authorization_response_iss_parameter_supported"))
                hits["ISS-9207"].append({"tool": None, "clients": ["chatgpt"], "detail":
                                         f"ChatGPT will use {CHATGPT_REDIRECT if iss else CHATGPT_REDIRECT_NO_ISS}"})

    # credentials without OAuth: how many headers, against what each client can send
    n_headers = len(headers or {})
    refused = not (d.open or d.oauth)              # a tokenless call got no result and no OAuth challenge
    unknown = ("the server refused a call without credentials and offers no OAuth: pass the credentials it needs "
               "(--header NAME=ENV_VAR, --token-env) to check this")
    if n_headers >= 2:
        hits["HDR2"].append({"tool": None, "detail": f"the server needs {n_headers} credential headers"})
    elif refused and not (n_headers or token):
        skipped["HDR2"] = unknown
    if (n_headers or token) and refused:
        if d.decided:
            hits["API-KEY-ONLY"].append({"tool": None, "detail": "credentials by header or a fixed token, no OAuth"})
        else:
            skipped["API-KEY-ONLY"] = f"cannot tell whether the server asks for OAuth ({d.get_why or d.post_why})"
    elif refused:
        skipped["API-KEY-ONLY"] = unknown if d.decided else \
            f"cannot tell whether the server asks for OAuth ({d.get_why or d.post_why})"

    if not d.oauth:
        return result(paths=paths, registered=[])
    registered = []
    if register:
        _register(d, paths, hits, registered, callback_port, skip_client)
    else:
        skipped["DCR-REDIRECT"] = "needs --register (your own server only)"
    cid = client_id or next((r["client_id"] for r in registered if r.get("client") == "copilot-studio"), None)
    cp = paths.get("copilot-studio")
    if not usable(cp):
        pass                              # skipped per client above
    elif cid:
        _authorization_request(d, cp, cid, registered, hits, skipped)
    else:
        skipped["SCOPE-DEFAULT"] = "needs a client id: --register or --client-id"
    if not usable(cp):
        pass
    elif interactive:
        _interactive(d, cp, url, registered, hits, skipped, open_browser, callback_port, interactive_wait, ask)
    else:
        skipped["TOKEN-AUDIENCE"] = skipped["CONSENT-PAGE"] = "needs --interactive (you sign in in a browser)"
    return result(paths=paths, registered=_unregister(d, registered))


def _register(d, paths, hits, registered, port, skip_client):
    for client, uris in redirects(port=port).items():
        p = paths.get(client) or {}
        reg_url = (p.get("metadata") or {}).get("registration_endpoint")
        if not reg_url:
            continue                      # NO-DCR, or the client's path, already says why
        r, why = d.send("POST", reg_url, {"client_name": f"docka-check ({client})", "redirect_uris": uris,
                                          "grant_types": ["authorization_code", "refresh_token"],
                                          "response_types": ["code"], "token_endpoint_auth_method": "none"})
        if why:
            skip_client("DCR-REDIRECT", client, f"registration got no answer ({why})")
            continue
        body = r.json() or {}
        if r.status in (200, 201) and body.get("client_id"):
            registered.append({"client": client, "client_id": body["client_id"],
                               "registration_client_uri": body.get("registration_client_uri"),
                               "token": body.get("registration_access_token"), "redirect_uri": uris[0]})
            if body.get("registration_access_token"):
                d.s.secrets.append(body["registration_access_token"])
        elif 400 <= r.status < 500:
            hits["DCR-REDIRECT"].append({"tool": None, "clients": [client], "detail":
                                         f"registration refused {uris[0]}: {r.status} {str(body.get('error'))[:60]}"})
        else:
            skip_client("DCR-REDIRECT", client, f"registration answered {r.status} without a client id")


def _pkce():
    v = secrets.token_urlsafe(32)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def _authorization_request(d, cp, cid, registered, hits, skipped):
    """The request as Copilot builds it (no scope, no resource, S256), up to the login page only."""
    m = cp["metadata"]
    ruri = next((r["redirect_uri"] for r in registered if r["client_id"] == cid), redirects()["copilot-studio"][0])
    _, chal = _pkce()
    q = {"response_type": "code", "client_id": cid, "redirect_uri": ruri, "state": secrets.token_hex(8),
         "code_challenge": chal, "code_challenge_method": "S256"}
    r, why = d.send("GET", m["authorization_endpoint"] + "?" + urlencode(q), headers={"Accept": "text/html"})
    if why:
        skipped["SCOPE-DEFAULT"] = f"the authorization endpoint gave no answer ({why})"
        return
    loc = r.header("location") or ""
    if r.status in (301, 302, 303, 307, 308) and loc.startswith(ruri):
        err = (parse_qs(urlparse(loc).query).get("error") or [None])[0]
        if err:
            hits["SCOPE-DEFAULT"].append({"tool": None, "clients": ["copilot-studio"],
                                          "detail": f"without scope: error={err} before any login page"})
    elif r.status >= 400:
        skipped["SCOPE-DEFAULT"] = (f"the authorization endpoint answered {r.status} without redirecting back "
                                    "(an unknown client id, or a refusal: check it by hand)")


class _Callback(BaseHTTPRequestHandler):
    got = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).got = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"docka-check: you can close this tab.")


def ask_tty(question):
    """The owner's answer at the terminal; None when nobody is there to answer (CI, a pipe)."""
    if not sys.stdin.isatty():
        return None
    try:
        return input(question)
    except EOFError:
        return None


def _interactive(d, cp, url, registered, hits, skipped, open_browser, port, wait_s, ask):
    """The owner signs in in a browser; the token is requested without resource, as Copilot does."""
    reg = next((r for r in registered if r["client"] == "claude-code"), None)
    if not reg:
        skipped["CONSENT-PAGE"] = skipped["TOKEN-AUDIENCE"] = \
            "no localhost client could be registered, so there is no sign-in to watch"
        return
    m = cp["metadata"]
    cb = type("CB", (_Callback,), {"got": None})
    srv = ThreadingHTTPServer(("127.0.0.1", port), cb)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        verifier, chal = _pkce()
        state = secrets.token_hex(8)
        q = {"response_type": "code", "client_id": reg["client_id"], "redirect_uri": reg["redirect_uri"],
             "state": state, "code_challenge": chal, "code_challenge_method": "S256", "scope": "mcp"}
        auth_url = m["authorization_endpoint"] + "?" + urlencode(q)
        (open_browser or _browser)(auth_url)
        for _ in range(wait_s * 10):
            if cb.got:
                break
            threading.Event().wait(0.1)
        got = cb.got or {}
        if not got.get("code") or got.get("state") != state:
            seen = f"error={got['error']}" if got.get("error") else "nothing came back"
            answer = (ask or ask_tty)(f"No sign-in came back within {wait_s} s ({seen}). "
                                      "Did the consent or sign-in page fail? [y/N] ")
            if (answer or "").strip().lower().startswith("y"):
                hits["CONSENT-PAGE"].append({"tool": None, "detail": f"you saw the consent or sign-in page fail ({seen})"})
            else:
                skipped["CONSENT-PAGE"] = (f"no sign-in came back within {wait_s} s ({seen}); the tool cannot tell a "
                                           "failed page from a sign-in left unfinished")
            skipped["TOKEN-AUDIENCE"] = "no token: the sign-in did not finish"
            return
        tok, why = d.send("POST", m["token_endpoint"], urlencode({
            "grant_type": "authorization_code", "code": got["code"], "redirect_uri": reg["redirect_uri"],
            "client_id": reg["client_id"], "code_verifier": verifier}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"})
        access = None if why else (tok.json() or {}).get("access_token")
        if not access:
            err = why or f"{tok.status} {str((tok.json() or {}).get('error'))[:40]}"
            skipped["TOKEN-AUDIENCE"] = f"the token request failed ({err})"
            return
        d.s.secrets.append(access)
        r, why = d.send("POST", url, {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}},
                        {"Accept": ACCEPT, "Authorization": "Bearer " + access})
        if why:
            skipped["TOKEN-AUDIENCE"] = f"tools/list with the new token got no answer ({why})"
        elif r.status == 401:
            hits["TOKEN-AUDIENCE"].append({"tool": None, "clients": ["copilot-studio"],
                                           "detail": "a token requested without resource got 401 on tools/list"})
    finally:
        srv.shutdown()
        srv.server_close()


def _browser(url):
    import webbrowser
    print(f"Sign in in your browser (your own server only): {url}")
    webbrowser.open(url)


def _unregister(d, registered):
    """RFC 7592: delete what --register created, where the server allows it; otherwise report the ids."""
    out = []
    for r in registered:
        uri, deleted = r.get("registration_client_uri"), False
        if uri:
            h = {"Authorization": "Bearer " + r["token"]} if r.get("token") else {}
            resp, why = d.send("DELETE", uri, headers=h)
            deleted = not why and resp.status in (200, 204)
        out.append({"client": r["client"], "client_id": r["client_id"], "deleted": deleted})
    return out
