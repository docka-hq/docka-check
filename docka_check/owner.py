"""Ownership: a full check runs only on a server its owner verified with Docka, or on your own machine.

Verifying: Docka issues a token, you serve it at <origin>/.well-known/docka-verify.txt on the MCP host, Docka fetches
the file and gives this tool an upload key (kept in ~/.config/docka-check/keys.json, mode 600). Before each full run
the key is checked with Docka, and the run's JSON report (the one --json-out writes, scrubbed of credentials) is sent
to Docka afterwards. Docka gets the server's origin only (scheme, host, port), never a path or query.
An unverified server gets an outside check (at most 5 requests, no client registration, no tool calls) and nothing is
sent. A server on your own machine (localhost, 127.0.0.1, ::1) is yours by definition: full run, nothing sent.
Lines this module prints during a check go to CI logs, so they never name the server.
"""

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__

FILE_PATH = "/.well-known/docka-verify.txt"
DEFAULT_PORT = {"https": 443, "http": 80}
MAX_REPORT = 1024 * 1024        # Docka's limit for one upload


def api_base():
    return (os.environ.get("DOCKA_CHECK_API") or "https://docka.ai/api/check").rstrip("/")


def home():
    return Path(os.environ.get("DOCKA_CHECK_HOME") or Path.home() / ".config" / "docka-check")


def origin(url):
    """scheme://host[:port], as Docka's side computes it for the same URL."""
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{u.scheme}://{host}" + (f":{u.port}" if u.port and u.port != DEFAULT_PORT.get(u.scheme) else "")


def loopback(url):
    """A server on this machine; DOCKA_CHECK_TRUST_LOOPBACK=0 turns that off (the tests use it)."""
    if os.environ.get("DOCKA_CHECK_TRUST_LOOPBACK") == "0":
        return False
    host = urlsplit(url).hostname or ""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------- the key store
def _store_file():
    return home() / "keys.json"


def _store():
    try:
        s = json.loads(_store_file().read_text())
    except (OSError, ValueError):
        s = {}
    return {"verified": s.get("verified") or {}, "pending": s.get("pending") or {}}


def _write(s):
    path = _store_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(s, f, indent=1)
    os.chmod(path, 0o600)


def stored_key(url):
    return (_store()["verified"].get(origin(url)) or {}).get("key")


def key_for(url):
    """The upload key for this server: DOCKA_CHECK_KEY (CI) or the one `verify` stored. None when there is none."""
    return (os.environ.get("DOCKA_CHECK_KEY") or "").strip() or stored_key(url)


# ---------------------------------------------------------------- Docka's API
def _post(path, body, key=None, timeout=20):
    req = urllib.request.Request(api_base() + path, json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": f"docka-check/{__version__}",
                                          **({"Authorization": "Bearer " + key} if key else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}
        finally:
            e.close()
    except (OSError, ValueError) as e:
        return None, {"error": f"Docka could not be reached ({type(e).__name__})"}


def mode(url):
    """('local' | 'verified' | 'outside', key or None, why it is outside)."""
    if loopback(url):
        return "local", None, ""
    key = key_for(url)
    if not key:
        return "outside", None, "no key for it"
    status, b = _post("/key", {"origin": origin(url)}, key=key)
    if status == 200:
        return "verified", key, ""
    where = "DOCKA_CHECK_KEY" if os.environ.get("DOCKA_CHECK_KEY", "").strip() else "the stored key"
    return "outside", None, f"{where} was not accepted: {b.get('error') or status}"


def upload(url, key, report):
    """Send a verified run's report. Returns a line for stderr; never raises."""
    body = {"origin": origin(url), "report": report}
    if len(json.dumps(body).encode()) > MAX_REPORT:
        return "docka-check: the report is over 1 MB, so it was not sent to Docka. The run itself is complete."
    status, b = _post("/report", body, key=key)
    if status == 201:
        return "docka-check: report sent to Docka (verified owner)."
    return f"docka-check: the report was not sent to Docka ({b.get('error') or status}). The run itself is complete."


# ---------------------------------------------------------------- docka-check verify
def served(file_url, token, timeout=5):
    req = urllib.request.Request(file_url, headers={"User-Agent": f"docka-check/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status == 200 and token in r.read(4096).decode("utf-8", "replace")
    except (OSError, ValueError):
        return False


def verify(url, email=None, wait=0, every=5, say=print):
    """First run: get a token and say where to serve it. Next run (or the same one, with wait): let Docka check the
    file and store the key. Returns the exit code: 0 verified, 1 not yet."""
    org, s = origin(url), _store()
    file_url = org + FILE_PATH
    p = s["pending"].get(org)
    fresh = not p or p["expires"] < time.time()
    if fresh:
        if not email:
            raise SystemExit("docka-check verify: give --email (Docka keeps it with this server's reports)")
        status, b = _post("/verify/start", {"url": org, "email": email})
        if status != 200:
            raise SystemExit(f"docka-check verify: {b.get('error') or status}")
        p = {"token": b["token"], "claim": b["claim"], "email": email, "expires": time.time() + b["expires_in"]}
        s["pending"][org] = p
        _write(s)
        say(f"To verify that {org} is yours, serve this line as plain text at\n  {file_url}\n\n  {p['token']}\n")
        say("By verifying you agree that each full run of this server sends its report to Docka (credentials "
            "removed).")
    else:
        say(f"Checking {file_url} for the token...")
    deadline = time.time() + wait
    while not served(file_url, p["token"]) and time.time() < deadline:
        time.sleep(every)
    if fresh and not wait:
        say("Then run this command again (or add --wait 600 to keep checking for 10 minutes).")
        return 1
    status, b = _post("/verify/confirm", {"url": org, "token": p["token"], "claim": p["claim"]})
    if status == 400:
        s["pending"].pop(org, None)
        _write(s)
        say(f"Not verified: {b.get('error')}. Run this command again for a new token.")
        return 1
    if status != 200:
        detail = f" ({b['detail']})" if b.get("detail") else ""
        say(f"Not verified yet: {b.get('error') or status}{detail}. Serve this line at {file_url}, then run this "
            f"command again:\n\n  {p['token']}\n")
        return 1
    s["pending"].pop(org, None)
    s["verified"][org] = {"key": b["key"], "email": p["email"],
                          "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _write(s)
    say(f"Verified {org}. Full checks of it now run, and each one sends its report to Docka.")
    say("For CI: docka-check key --url <this URL> | gh secret set DOCKA_CHECK_KEY  (then pass it as verify-key)")
    return 0
