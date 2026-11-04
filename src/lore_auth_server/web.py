"""HTTP(S) listener: the browser login page, sign-in from apps, the JWKS document for loreserver and the admin API."""

from __future__ import annotations

import html
import json
import logging
import ssl
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .admin_api import AdminApi, Response
from .service import Authority

log = logging.getLogger(__name__)

JWKS_PATHS = ("/jwks.json", "/.well-known/jwks.json")
# Apps that show their own sign-in form complete a Lore sign-in session here (JSON).
SIGN_IN_PATH = "/api/sign-in"
MAX_FAILURES = 5          # failed attempts per client address ...
FAILURE_WINDOW = 300      # ... within this many seconds before throttling

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lore sign in</title>
<style>
  :root {{ color-scheme: dark; --frame: #3b3f47; --panel: #454a53; --recessed: #3f434b; --text: #f3f4f6;
          --muted: #a9b0bb; --accent: #ebc35c; --accent-hover: #f1cd70; --ink: #25272c;
          --bad: #fabcbc; --bad-bg: rgba(232, 117, 117, 0.13); }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--frame);
         color: var(--text); font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }}
  main {{ width: min(360px, calc(100vw - 32px)); background: var(--panel); border-radius: 11px; padding: 28px;
         box-sizing: border-box; }}
  h1 {{ font-size: 18px; font-weight: 600; margin: 0 0 4px; }}
  p {{ margin: 0 0 20px; color: var(--muted); font-size: 13px; }}
  p:last-child {{ margin-bottom: 0; }}
  strong {{ color: var(--text); }}
  label {{ display: block; font-size: 13px; color: var(--muted); margin: 14px 0 6px; }}
  input {{ width: 100%; box-sizing: border-box; height: 36px; padding: 0 12px; border: 0; border-radius: 7px;
          background: var(--recessed); color: inherit; font: inherit; outline: none;
          box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.06), inset 0 1px 2px rgba(0, 0, 0, 0.14); }}
  input:focus {{ box-shadow: inset 0 0 0 1.5px var(--accent); }}
  button {{ width: 100%; height: 36px; margin-top: 22px; border: 0; border-radius: 7px; background: var(--accent);
           color: var(--ink); font: inherit; font-weight: 600; cursor: pointer; }}
  button:hover {{ background: var(--accent-hover); }}
  button:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
  .error {{ color: var(--bad); background: var(--bad-bg); border-radius: 7px; padding: 8px 12px; font-size: 13px;
           margin: 14px 0 0; }}
</style></head>
<body><main>{body}</main></body></html>"""

FORM = """<h1>Sign in to Lore</h1>
<p>Use the account your administrator created for you.</p>
<form method="post" action="/login">
  <input type="hidden" name="session" value="{session}">
  <label for="u">User name</label>
  <input id="u" name="username" autocomplete="username" autofocus required>
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
  {error}
</form>"""

DONE = """<h1>Signed in</h1>
<p>You are signed in as <strong>{name}</strong>. You can close this window and return to your Lore client.</p>"""

EXPIRED = """<h1>Link expired</h1>
<p>This sign-in link is no longer valid. Start signing in again from your Lore client.</p>"""


class Throttle:
    def __init__(self, max_failures: int = MAX_FAILURES, window: int = FAILURE_WINDOW):
        self.max_failures = max_failures
        self.window = window
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def blocked(self, address: str) -> bool:
        with self._lock:
            recent = [t for t in self._failures[address] if t > time.time() - self.window]
            self._failures[address] = recent
            return len(recent) >= self.max_failures

    def fail(self, address: str) -> None:
        with self._lock:
            self._failures[address].append(time.time())


def make_handler(authority: Authority):
    throttle = Throttle()
    jwks_body = json.dumps(authority.issuer.jwks).encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = "lore-auth-server"
        sys_version = ""
        # Separate from the login page throttle, so that one cannot lock users out of the other.
        admin_api = AdminApi(authority, Throttle())

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.client_address[0], fmt % args)

        def _send(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            if status != 204:
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def _page(self, status: int, body: str) -> None:
            self._send(status, PAGE.format(body=body).encode(), "text/html; charset=utf-8")

        def _json(self, status: int, body: dict) -> None:
            self._send(status, json.dumps(body).encode(), "application/json", {"X-Content-Type-Options": "nosniff"})

        def _error(self, status: int, code: str, message: str) -> None:
            self._json(status, {"error": {"code": code, "message": message}})

        def _sign_in(self) -> None:
            """The login form without the browser: an app sends the session from the
            sign-in link with the user name and password. Same checks and throttle as the page."""
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._error(415, "unsupported_media_type", "send application/json")
                return
            length = int(self.headers.get("Content-Length", 0))
            if length > 8192:
                self._error(413, "too_large", "request too large")
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                session, username, password = str(body["session"]), str(body["username"]).strip(), str(body["password"])
            except (ValueError, KeyError, TypeError):
                self._error(400, "bad_request", "expected session, username and password")
                return
            address = self.client_address[0]
            if not authority.sessions.exists(session):
                self._error(410, "session_expired", "This sign-in session is no longer valid. Start signing in again.")
                return
            if throttle.blocked(address):
                self._error(429, "too_many_attempts", "Too many failed attempts. Try again in a few minutes.")
                return
            user = authority.store.check_password(username, password)
            if user is None:
                throttle.fail(address)
                log.warning("failed sign-in for %r from %s (app)", username, address)
                self._error(401, "wrong_credentials", "Wrong user name or password.")
                return
            if not authority.sessions.complete(session, user):
                self._error(410, "session_expired", "This sign-in session is no longer valid. Start signing in again.")
                return
            self._json(200, {"user": user.name, "displayName": user.display_name})

        def _admin(self, method: str) -> bool:
            """Serve an admin API request; False when the path is not part of the (enabled) API."""
            if not self.admin_api.handles(urlparse(self.path).path):
                return False
            response: Response = self.admin_api.handle(
                method, self.path, self.headers, self.rfile, self.client_address[0]
            )
            body = b"" if response.body is None else json.dumps(response.body).encode()
            headers = {"X-Content-Type-Options": "nosniff", **response.headers}
            self._send(response.status, body, "application/json", headers)
            return True

        def do_GET(self):
            if self._admin("GET"):
                return
            url = urlparse(self.path)
            if url.path in JWKS_PATHS:
                self._send(200, jwks_body, "application/json")
            elif url.path == SIGN_IN_PATH:
                # Lets an app check, before showing its form, that this service takes it.
                self._json(200, {"passwordSignIn": True})
            elif url.path == "/health":
                self._send(200, b"ok", "text/plain")
            elif url.path == "/login":
                session = parse_qs(url.query).get("session", [""])[0]
                if not authority.sessions.exists(session):
                    self._page(410, EXPIRED)
                else:
                    self._page(200, FORM.format(session=html.escape(session), error=""))
            else:
                self._send(404, b"not found", "text/plain")

        def do_PUT(self):
            if not self._admin("PUT"):
                self._send(404, b"not found", "text/plain")

        def do_PATCH(self):
            if not self._admin("PATCH"):
                self._send(404, b"not found", "text/plain")

        def do_DELETE(self):
            if not self._admin("DELETE"):
                self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if self._admin("POST"):
                return
            if urlparse(self.path).path == SIGN_IN_PATH:
                self._sign_in()
                return
            if urlparse(self.path).path != "/login":
                self._send(404, b"not found", "text/plain")
                return
            length = min(int(self.headers.get("Content-Length", 0)), 8192)
            form = parse_qs(self.rfile.read(length).decode(errors="replace"))
            session = form.get("session", [""])[0]
            username = form.get("username", [""])[0].strip()
            password = form.get("password", [""])[0]
            address = self.client_address[0]

            if not authority.sessions.exists(session):
                self._page(410, EXPIRED)
                return
            if throttle.blocked(address):
                error = '<p class="error">Too many failed attempts. Try again in a few minutes.</p>'
                self._page(429, FORM.format(session=html.escape(session), error=error))
                return
            user = authority.store.check_password(username, password)
            if user is None:
                throttle.fail(address)
                log.warning("failed sign-in for %r from %s", username, address)
                error = '<p class="error">Wrong user name or password.</p>'
                self._page(401, FORM.format(session=html.escape(session), error=error))
                return
            if not authority.sessions.complete(session, user):
                self._page(410, EXPIRED)
                return
            self._page(200, DONE.format(name=html.escape(user.display_name)))

    return Handler


def start_web_server(authority: Authority) -> ThreadingHTTPServer:
    host, port = authority.config.web_listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), make_handler(authority))
    if authority.config.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(authority.config.tls_cert, authority.config.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, name="web", daemon=True).start()
    log.info("web listener on %s (%s)", authority.config.web_listen, "https" if authority.config.tls_cert else "http")
    return server
