"""HTTP for docka-check: one place for the User-Agent, the host allowlist, the request budget and credential scrubbing.

No automatic redirects: a redirect is returned, so the caller decides (and counts) the next request. A request to a
host outside the allowlist raises before anything is sent: the tool talks only to the MCP host and the authorization
servers its protected-resource document names.

The budget is per server (host:port) and shared by every tier of one run. On a server not verified as yours it is the
outside-check limit, 5 requests per server; a 429 stops every further request to that server in either mode. A response is an answer only
when it is not a transport error, a 429 or a 5xx: anything else concludes nothing.
"""

import http.client
import json
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import __version__

UA = f"docka-check/{__version__} (+https://docka.ai)"
TIMEOUT_S = 30


class HostNotAllowed(Exception):
    pass


OUTSIDE_PER_SERVER = 5         # the outside-check limit, for a server not verified as yours


class OutOfBudget(Exception):
    def __init__(self, server, per_host=None):
        super().__init__(server)
        self.server, self.per_host = server, per_host

    def why(self):
        return f"outside mode: the {self.per_host} requests allowed to {self.server} were used up"


class RateLimited(OutOfBudget):
    def why(self):
        return f"{self.server} answered 429, so nothing more was sent to it"


def server_key(url):
    """host:port with the scheme's default port filled in: one server, one count, however its URL is spelled."""
    u = urlparse(url)
    try:
        port = u.port
    except ValueError:
        port = None
    return f"{(u.hostname or '').lower()}:{port or (443 if u.scheme == 'https' else 80)}"


def _forms(secret):
    """A secret as it can appear in text: as is, escaped by Python's repr (str and bytes), escaped by JSON."""
    forms = {secret, repr(secret)[1:-1], json.dumps(secret)[1:-1]}
    try:
        forms.add(repr(secret.encode())[2:-1])
    except UnicodeEncodeError:
        pass
    return sorted((f for f in forms if f), key=len, reverse=True)


def scrub_deep(obj, secrets):
    """obj with every secret, in any of its forms, replaced in every string inside it (dict keys too)."""
    # longest first: a secret inside another is replaced after it, so no fragment of the longer one is left behind
    forms = sorted({f for s in secrets if s for f in _forms(s)}, key=len, reverse=True)
    if not forms:
        return obj

    def walk(o):
        if isinstance(o, str):
            for f in forms:
                o = o.replace(f, "[credential]")
            return o
        if isinstance(o, dict):
            return {walk(k): walk(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [walk(v) for v in o]
        return o
    return walk(obj)


class Budget:
    """Requests per server, shared by every tier of one run. per_host=None: no cap (the owner's run)."""

    def __init__(self, per_host=None):
        self.per_host, self.used, self.stopped = per_host, {}, set()

    def take(self, server):
        if server in self.stopped:
            raise RateLimited(server)
        if self.per_host is not None and self.used.get(server, 0) >= self.per_host:
            raise OutOfBudget(server, self.per_host)
        self.used[server] = self.used.get(server, 0) + 1

    def saw(self, server, status):
        if status == 429:
            self.stopped.add(server)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


class Session:
    """Every request of one check. `secrets` are values to scrub from anything recorded."""

    def __init__(self, allowed_hosts, budget=None, secrets=()):
        self.allowed = {h.lower() for h in allowed_hosts}
        self.budget = budget if budget is not None else Budget()
        self.secrets = [s for s in secrets if s]
        self.log = []

    def allow(self, host):
        self.allowed.add(host.lower())

    def scrub(self, text):
        return scrub_deep(text, self.secrets)

    def request(self, method, url, body=None, headers=None, cap=8 << 20, timeout=TIMEOUT_S):
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if host not in self.allowed:
            raise HostNotAllowed(host)
        server = server_key(url)
        self.budget.take(server)
        h = {"User-Agent": UA, **(headers or {})}
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        if data is not None and "Content-Type" not in h:
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        rec = {"method": method, "url": self.scrub(url), "sent_headers": sorted(k for k in h if k != "User-Agent")}
        self.log.append(rec)
        t0 = time.monotonic()
        try:
            try:
                resp = _OPENER.open(req, timeout=timeout)
                status = resp.status
            except urllib.error.HTTPError as e:
                resp, status = e, e.code
            raw = resp.read(cap)
            out = Response(status, dict(resp.headers), raw, time.monotonic() - t0)
        except (OSError, ValueError, http.client.HTTPException) as e:
            # scrubbed before it is cut: http.client puts a malformed header value into its message
            out = Response(None, {}, b"", time.monotonic() - t0, error=self.scrub(f"{type(e).__name__}: {e}")[:200])
        rec.update(status=out.status, ms=int(out.seconds * 1000), error=out.error)
        self.budget.saw(server, out.status)
        return out


class Response:
    def __init__(self, status, headers, raw, seconds, error=None):
        self.status, self.raw, self.seconds, self.error = status, raw, seconds, error
        self.headers = {k.lower(): v for k, v in headers.items()}

    def header(self, name):
        return self.headers.get(name.lower())

    @property
    def answered(self):
        """The server's own answer: not a transport error, a 429 or a 5xx."""
        return self.status is not None and self.status != 429 and self.status < 500

    def why(self):
        return self.error or f"HTTP {self.status}"

    def json(self):
        try:
            return json.loads(self.raw)
        except ValueError:
            return None

    @property
    def text(self):
        return self.raw.decode("utf-8", "replace")
