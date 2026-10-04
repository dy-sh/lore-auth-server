"""HTTP(S) listener: the browser login page and the JWKS document for loreserver."""

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

from .service import Authority

log = logging.getLogger(__name__)

JWKS_PATHS = ("/jwks.json", "/.well-known/jwks.json")
MAX_FAILURES = 5          # failed sign-ins per client address ...
FAILURE_WINDOW = 300      # ... within this many seconds before throttling

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lore sign in</title>
<style>
  :root {{ color-scheme: light dark; --bg: #f4f4f5; --card: #fff; --text: #18181b; --muted: #71717a;
          --border: #d4d4d8; --accent: #2563eb; --error: #dc2626; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #18181b; --card: #27272a; --text: #f4f4f5; --muted: #a1a1aa; --border: #3f3f46; }}
  }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg);
         color: var(--text); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }}
  main {{ width: min(360px, calc(100vw - 32px)); background: var(--card); border: 1px solid var(--border);
         border-radius: 12px; padding: 28px; box-sizing: border-box; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  p {{ margin: 0 0 20px; color: var(--muted); font-size: 14px; }}
  label {{ display: block; font-size: 14px; margin: 12px 0 4px; }}
  input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid var(--border);
          border-radius: 8px; background: transparent; color: inherit; font: inherit; }}
  button {{ width: 100%; margin-top: 20px; padding: 10px; border: 0; border-radius: 8px;
           background: var(--accent); color: #fff; font: inherit; font-weight: 600; cursor: pointer; }}
  .error {{ color: var(--error); font-size: 14px; margin: 12px 0 0; }}
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


class _Throttle:
    def __init__(self):
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def blocked(self, address: str) -> bool:
        with self._lock:
            recent = [t for t in self._failures[address] if t > time.time() - FAILURE_WINDOW]
            self._failures[address] = recent
            return len(recent) >= MAX_FAILURES

    def fail(self, address: str) -> None:
        with self._lock:
            self._failures[address].append(time.time())


def make_handler(authority: Authority):
    throttle = _Throttle()
    jwks_body = json.dumps(authority.issuer.jwks).encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = "lore-auth-server"
        sys_version = ""

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.client_address[0], fmt % args)

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
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

        def do_GET(self):
            url = urlparse(self.path)
            if url.path in JWKS_PATHS:
                self._send(200, jwks_body, "application/json")
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

        def do_POST(self):
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
