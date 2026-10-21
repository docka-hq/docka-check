#!/usr/bin/env python3
"""Docka's side of docka-check's ownership check, as it runs at docka.ai/api/check.

A full check runs only on a server whose owner proved it is theirs: Docka issues a token, the owner serves it at
<origin>/.well-known/docka-verify.txt on the MCP host, Docka fetches that file. A verified owner gets an upload key, and
a verified run sends its report here. Stdlib only; binds 127.0.0.1, Caddy proxies docka.ai/api/check/* to it.

  POST /api/check/verify/start    {"url", "email"}            -> {"token", "claim", "file_url", "expires_in"}
  POST /api/check/verify/confirm  {"url", "token", "claim"}   -> {"key", "origin"}   (the file must hold the token)
  POST /api/check/key             Bearer <key>, {"origin"}    -> {"origin"}          (before a full run)
  POST /api/check/report          Bearer <key>, {"origin", "report"}  -> {"stored"}
  GET  /api/check/health

The token is public (it sits in the file), so confirming also takes the claim, which only the starter got back: a
reader of the file cannot take the key. Only the origin of a URL is kept, never its path or query.

Everything is written to events.jsonl first (tokens and keys only as sha256), reports to reports/<origin hash>/.
The file fetch is the one request this service makes to the outside, so it is guarded: https only, every address of
the host must be public and the connection goes to the address that was checked, no redirects, 5 s, 4 KB.

Environment:
  CHECK_API_PORT          default 8793
  CHECK_API_TG_TOKEN / CHECK_API_TG_CHAT_ID   Telegram notice on a verification and on a report (optional)
  CHECK_API_DRY_RUN=1     print notices instead of sending them (tests)
  CHECK_API_ALLOW_PRIVATE=1  tests only: allow http and loopback servers
  STATE_DIRECTORY         set by systemd (StateDirectory=docka-check-api); default ./check-api-state
"""

import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("CHECK_API_PORT", "8793"))
STATE = os.environ.get("STATE_DIRECTORY") or os.path.join(os.getcwd(), "check-api-state")
DRY = os.environ.get("CHECK_API_DRY_RUN") == "1"
ALLOW_PRIVATE = os.environ.get("CHECK_API_ALLOW_PRIVATE") == "1"
TG_TOKEN = os.environ.get("CHECK_API_TG_TOKEN", "")
TG_CHAT = os.environ.get("CHECK_API_TG_CHAT_ID", "")

BASE = "/api/check"
FILE_PATH = "/.well-known/docka-verify.txt"
TOKEN_TTL = 7 * 24 * 3600
MAX_BODY = 4 * 1024
MAX_REPORT = 1024 * 1024
MAX_FILE = 4 * 1024
EMAIL_RE = re.compile(r"^[^@\s<>,;:\"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
PER_IP = (20, 600)              # verify start/confirm: at most 20 per IP per 10 minutes
PER_KEY = (60, 3600)            # reports: at most 60 per key per hour
KEY_CHECKS = (120, 600)         # key checks before a run: at most 120 per IP per 10 minutes
DEFAULT_PORT = {"https": 443, "http": 80}

TOO_BIG = object()
_lock = threading.Lock()
_hits = {}
_issued = {}                    # token sha256 -> issued record
_keys = {}                      # key sha256 -> verified record


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def now():
    return time.time()


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def append(rec):
    rec = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **rec}
    with _lock:
        os.makedirs(STATE, exist_ok=True)
        with open(os.path.join(STATE, "events.jsonl"), "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def load():
    """Rebuild the token and key indexes from events.jsonl (the only state that matters)."""
    path = os.path.join(STATE, "events.jsonl")
    if not os.path.exists(path):
        return
    for line in open(path):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("type") == "issued":
            _issued[e["token_sha256"]] = e
        elif e.get("type") == "verified":
            _keys[e["key_sha256"]] = e
        elif e.get("type") == "revoked":
            _keys.pop(e.get("key_sha256"), None)


def limited(bucket, who, limit):
    n, window = limit
    t = now()
    with _lock:
        hits = [x for x in _hits.get((bucket, who), []) if t - x < window]
        if len(hits) >= n:
            _hits[(bucket, who)] = hits
            return True
        hits.append(t)
        _hits[(bucket, who)] = hits
    return False


def origin_of(url):
    """scheme://host[:port] of an MCP URL, or None when it is not one we may check."""
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return None
    if u.scheme not in (("https", "http") if ALLOW_PRIVATE else ("https",)) or not u.hostname or u.username or u.password:
        return None
    host = u.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{u.scheme}://{host}" + (f":{port}" if port and port != DEFAULT_PORT[u.scheme] else "")


def public_ip(host, port):
    """The first address of host, if every address it resolves to is public; else None."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return None
    ips = [i[4][0] for i in infos]
    for ip in ips:
        a = ipaddress.ip_address(ip.split("%")[0])
        if not ALLOW_PRIVATE and (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
                                  or a.is_unspecified):
            return None
    return ips[0] if ips else None


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to a vetted address, with the certificate checked against the host name."""

    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def fetch_file(origin):
    """(status, text) of <origin>/.well-known/docka-verify.txt, or (None, why)."""
    u = urllib.parse.urlsplit(origin)
    port = u.port or (443 if u.scheme == "https" else 80)
    ip = public_ip(u.hostname, port)
    if not ip:
        return None, "the host does not resolve to public addresses only"
    conn = (_PinnedHTTPS if u.scheme == "https" else _PinnedHTTP)(u.hostname, ip, port, timeout=5)
    try:
        conn.request("GET", FILE_PATH, headers={"User-Agent": "docka-check-verify/1", "Accept": "text/plain"})
        r = conn.getresponse()
        body = r.read(MAX_FILE + 1)
        return r.status, body[:MAX_FILE].decode("utf-8", "replace")
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        return None, type(e).__name__
    finally:
        conn.close()


def notify(text):
    if DRY or not (TG_TOKEN and TG_CHAT):
        log("notice:", text)
        return
    data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": text, "disable_web_page_preview": "true"}).encode()

    def send():
        try:
            urllib.request.urlopen(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data=data, timeout=10).read()
        except OSError as e:
            log("telegram failed:", type(e).__name__)
    threading.Thread(target=send, daemon=True).start()


def summary(report):
    labels = [f.get("label") for f in report.get("findings") or [] if isinstance(f, dict)]
    return {k: labels.count(k) for k in ("blocker", "likely", "advisory")}


class Handler(BaseHTTPRequestHandler):
    server_version = "docka-check-api/1"
    timeout = 15                    # a client that stops sending is dropped, not waited for

    def log_message(self, *a):
        pass

    def ip(self):
        """The address Caddy saw: the last X-Forwarded-For entry is the one our own proxy wrote."""
        return self.headers.get("X-Forwarded-For", "").split(",")[-1].strip() or self.client_address[0]

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def body(self, limit):
        """The JSON body; None when it is not JSON, TOO_BIG when it is longer than limit (left unread)."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n < 0:
            return None
        if n > limit:
            return TOO_BIG
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return None

    def key_record(self):
        auth = self.headers.get("Authorization") or ""
        return _keys.get(sha(auth[7:].strip())) if auth.lower().startswith("bearer ") else None

    def do_GET(self):
        if self.path == BASE + "/health":
            return self.reply(200, {"ok": True, "telegram": bool(TG_TOKEN and TG_CHAT), "dry_run": DRY})
        return self.reply(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == BASE + "/verify/start":
            return self.start()
        if path == BASE + "/verify/confirm":
            return self.confirm()
        if path == BASE + "/key":
            return self.key()
        if path == BASE + "/report":
            return self.report()
        return self.reply(404, {"error": "not found"})

    def start(self):
        if limited("verify", self.ip(), PER_IP):
            return self.reply(429, {"error": "too many requests, try again in a few minutes"})
        b = self.body(MAX_BODY)
        if not isinstance(b, dict):
            return self.reply(400, {"error": "send JSON: url, email"})
        origin, email = origin_of(str(b.get("url") or "")), str(b.get("email") or "").strip()
        if not origin:
            return self.reply(400, {"error": "url must be your MCP server's https URL"})
        if not EMAIL_RE.match(email):
            return self.reply(400, {"error": "email is required"})
        token, claim = "docka-verify-" + secrets.token_hex(16), secrets.token_urlsafe(32)
        rec = {"type": "issued", "origin": origin, "email": email, "token_sha256": sha(token),
               "claim_sha256": sha(claim), "expires": now() + TOKEN_TTL, "ip": self.ip()}
        append(rec)
        with _lock:
            _issued[rec["token_sha256"]] = rec
        return self.reply(200, {"token": token, "claim": claim, "file_url": origin + FILE_PATH,
                                "expires_in": TOKEN_TTL})

    def confirm(self):
        if limited("verify", self.ip(), PER_IP):
            return self.reply(429, {"error": "too many requests, try again in a few minutes"})
        b = self.body(MAX_BODY)
        if not isinstance(b, dict):
            return self.reply(400, {"error": "send JSON: url, token, claim"})
        origin, token, claim = (origin_of(str(b.get("url") or "")), str(b.get("token") or ""),
                                str(b.get("claim") or ""))
        rec = _issued.get(sha(token))
        if not origin or not rec or rec["origin"] != origin or rec["expires"] < now():
            return self.reply(400, {"error": "unknown or expired token for this server: run verify again"})
        if not secrets.compare_digest(sha(claim), rec.get("claim_sha256", "")):
            return self.reply(403, {"error": "this token was issued to another verify run"})
        status, text = fetch_file(origin)
        if status != 200 or token not in text:
            why = text if status is None else f"{origin}{FILE_PATH} answered HTTP {status}" + (
                "" if status != 200 else " without the token")
            return self.reply(409, {"error": "the file does not hold the token yet", "detail": why})
        key = "dck_" + secrets.token_urlsafe(32)
        v = {"type": "verified", "origin": origin, "email": rec["email"], "key_sha256": sha(key), "ip": self.ip()}
        append(v)
        with _lock:
            _keys[v["key_sha256"]] = v
        notify(f"docka-check: {origin} verified by {rec['email']}")
        return self.reply(200, {"key": key, "origin": origin})

    def key(self):
        if limited("key", self.ip(), KEY_CHECKS):
            return self.reply(429, {"error": "too many requests, try again in a few minutes"})
        v = self.key_record()
        if not v:
            return self.reply(401, {"error": "Docka issued no such key"})
        b = self.body(MAX_BODY)
        if not isinstance(b, dict):
            return self.reply(400, {"error": "send JSON: origin"})
        if origin_of(str(b.get("origin") or "")) != v["origin"]:
            return self.reply(403, {"error": "this key is for another server"})
        return self.reply(200, {"origin": v["origin"]})

    def report(self):
        v = self.key_record()
        if not v:
            return self.reply(401, {"error": "Docka issued no such key"})
        if limited("report", v["key_sha256"], PER_KEY):
            return self.reply(429, {"error": "too many reports this hour"})
        b = self.body(MAX_REPORT)
        if b is TOO_BIG:
            return self.reply(413, {"error": f"the report is over {MAX_REPORT // 1024} KB"})
        if not isinstance(b, dict) or not isinstance(b.get("report"), dict):
            return self.reply(400, {"error": "send JSON: origin, report"})
        if origin_of(str(b.get("origin") or "")) != v["origin"]:
            return self.reply(403, {"error": "this key is for another server"})
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(3)
        folder = os.path.join(STATE, "reports", sha(v["origin"])[:16])
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, stamp + ".json"), "w") as f:
            json.dump({"origin": v["origin"], "email": v["email"], "report": b["report"]}, f, ensure_ascii=False)
        n = summary(b["report"])
        append({"type": "report", "origin": v["origin"], "stored": stamp, "findings": n})
        notify(f"docka-check report: {v['origin']} ({v['email']}): {n['blocker']} blocker, {n['likely']} likely, "
               f"{n['advisory']} advisory")
        return self.reply(201, {"stored": stamp})


def serve(port=PORT):
    load()
    s = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    s.daemon_threads = True
    return s


def main():
    log(f"docka-check-api on 127.0.0.1:{PORT}, state {STATE}, telegram={'on' if TG_TOKEN and TG_CHAT else 'off'}"
        f"{', ALLOW_PRIVATE' if ALLOW_PRIVATE else ''}")
    serve().serve_forever()


if __name__ == "__main__":
    main()
