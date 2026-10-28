"""Optional HTTPS JSON admin API: remote management of users, grants and API keys.

The protocol is specified in docs/admin-api.md. It is served on the login page
listener and uses the same store operations as the command line.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import Message
from typing import Any, BinaryIO, Protocol
from urllib.parse import parse_qs, unquote, urlparse

from .service import Authority
from .store import ALL_REPOSITORIES, ApiKey, ConflictError, NotFoundError, User, api_key_id
from .tokens import TokenError, TokenExpired

log = logging.getLogger(__name__)

PROTOCOL = "lore-admin"
VERSION = 1
DISCOVERY_PATH = "/.well-known/lore-admin"
BASE = "/api/v1"
FEATURES = ["users", "grants", "repositories", "api-keys", "servers"]
MAX_BODY_BYTES = 8192
_DRAIN_LIMIT_BYTES = 1 << 20
MAX_TEXT_LENGTH = 128  # display names and API key labels
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class Throttle(Protocol):
    window: int

    def blocked(self, address: str) -> bool: ...

    def fail(self, address: str) -> None: ...


@dataclass
class Response:
    status: int
    body: dict | None = None
    headers: dict[str, str] = field(default_factory=dict)


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


@dataclass(frozen=True)
class _Route:
    method: str
    pattern: tuple[str | None, ...]  # None marks a path parameter
    handler: str
    admin: bool = True
    body: bool = False
    query: frozenset[str] = frozenset()


def _route(method: str, path: str, handler: str, **options) -> _Route:
    pattern = tuple(None if part == "{}" else part for part in path.split("/"))
    if "query" in options:
        options["query"] = frozenset(options["query"])
    return _Route(method, pattern, handler, **options)


ROUTES = [
    _route("GET", "me", "get_me", admin=False),
    _route("GET", "users", "list_users"),
    _route("POST", "users", "create_user", body=True),
    _route("PATCH", "users/{}", "update_user", body=True),
    _route("DELETE", "users/{}", "delete_user"),
    _route("PUT", "users/{}/password", "set_password", body=True),
    _route("GET", "grants", "list_grants", query={"user", "repository"}),
    _route("PUT", "grants", "put_grant", body=True),
    _route("DELETE", "grants", "delete_grant", body=True),
    _route("GET", "repositories", "list_repositories"),
    _route("GET", "api-keys", "list_api_keys", query={"user"}),
    _route("POST", "api-keys", "create_api_key", body=True),
    _route("DELETE", "api-keys/{}", "delete_api_keys"),
    _route("GET", "servers", "list_servers", admin=False),
    _route("PUT", "servers", "put_server", body=True),
    _route("DELETE", "servers", "delete_server", body=True),
]


@dataclass
class _Call:
    user: User
    address: str
    params: list[str]
    query: dict[str, str]
    body: dict[str, Any]


def _unauthenticated(message: str, invalid_token: bool = True) -> ApiError:
    challenge = 'Bearer error="invalid_token"' if invalid_token else "Bearer"
    return ApiError(401, "unauthenticated", message, {"WWW-Authenticate": challenge})


def _bad_request(message: str) -> ApiError:
    return ApiError(400, "invalid_request", message)


def _fields(body: dict[str, Any], required: dict[str, type], optional: dict[str, type] | None = None) -> dict[str, Any]:
    """Check that `body` has exactly the allowed fields with the expected JSON types."""
    allowed = {**required, **(optional or {})}
    for name in body:
        if name not in allowed:
            raise _bad_request(f"unknown field: {name}")
    for name in required:
        if name not in body:
            raise _bad_request(f"{name} is required")
    for name, value in body.items():
        kind = allowed[name]
        if not isinstance(value, kind):
            raise _bad_request(f"{name} must be a {'boolean' if kind is bool else 'string'}")
    return body


def _text(value: str, name: str) -> str:
    value = value.strip()
    if len(value) > MAX_TEXT_LENGTH:
        raise _bad_request(f"{name} must be at most {MAX_TEXT_LENGTH} characters")
    if _CONTROL_CHARS.search(value):
        raise _bad_request(f"{name} must not contain control characters")
    return value


def _not_empty(value: str, name: str) -> str:
    if not value:
        raise _bad_request(f"{name} must not be empty")
    return value


def _timestamp(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repository_id(resource_id: str) -> str:
    """Lore repository ID (as `lore repository list` shows it) or '*' for all repositories."""
    if resource_id == ALL_REPOSITORIES:
        return "*"
    return resource_id.removeprefix("urc-")


def _user_json(user: User) -> dict:
    return {"name": user.name, "displayName": user.display_name, "admin": user.is_admin, "disabled": user.disabled}


def _api_key_json(key: ApiKey) -> dict:
    return {"id": key.id, "user": key.user, "label": key.label, "createdAt": _timestamp(key.created_at)}


class AdminApi:
    def __init__(self, authority: Authority, throttle: Throttle):
        self.a = authority
        self.store = authority.store
        self.throttle = throttle
        self.enabled = authority.config.admin_api

    def handles(self, path: str) -> bool:
        return self.enabled and (path == DISCOVERY_PATH or path == BASE or path.startswith(BASE + "/"))

    def handle(self, method: str, target: str, headers: Message, rfile: BinaryIO, address: str) -> Response:
        try:
            return self._dispatch(method, target, headers, rfile, address)
        except ApiError as e:
            return Response(e.status, {"error": {"code": e.code, "message": e.message}}, e.headers)
        except Exception:
            log.exception("admin API: %s %s failed", method, urlparse(target).path)
            return Response(500, {"error": {"code": "internal", "message": "internal server error"}})

    def discovery(self) -> dict:
        return {"protocol": PROTOCOL, "version": VERSION, "base": BASE, "features": list(FEATURES)}

    def _dispatch(self, method: str, target: str, headers: Message, rfile: BinaryIO, address: str) -> Response:
        url = urlparse(target)
        if url.path == DISCOVERY_PATH:
            if method != "GET":
                raise ApiError(405, "method_not_allowed", "use GET", {"Allow": "GET"})
            return Response(200, self.discovery())

        rest = url.path[len(BASE):].strip("/")
        segments = [unquote(part) for part in rest.split("/")] if rest else []
        candidates = [
            r for r in ROUTES
            if len(r.pattern) == len(segments)
            and all(p is None or p == s for p, s in zip(r.pattern, segments, strict=True))
        ]
        if not candidates:
            raise ApiError(404, "not_found", "no such endpoint")
        route = next((r for r in candidates if r.method == method), None)
        if route is None:
            allowed = ", ".join(sorted({r.method for r in candidates}))
            raise ApiError(405, "method_not_allowed", f"use {allowed}", {"Allow": allowed})

        raw_body = self._read_body(headers, rfile) if route.body else b""
        user = self._authenticate(headers.get("Authorization"), address)
        if route.admin and not user.is_admin:
            raise ApiError(403, "forbidden", "administrator rights required")
        query = self._query(url.query, route.query)
        body = self._parse_body(headers, raw_body)
        params = [s for p, s in zip(route.pattern, segments, strict=True) if p is None]
        call = _Call(user, address, params, query, body)
        try:
            return getattr(self, route.handler)(call)
        except NotFoundError as e:
            raise ApiError(404, "not_found", str(e)) from None
        except (ConflictError, sqlite3.IntegrityError) as e:
            raise ApiError(409, "conflict", str(e)) from None
        except ValueError as e:
            raise _bad_request(str(e)) from None

    def _authenticate(self, header: str | None, address: str) -> User:
        if not header:
            raise _unauthenticated("authorization required", invalid_token=False)
        scheme, _, token = header.strip().partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise _unauthenticated("use Authorization: Bearer <user token>", invalid_token=False)
        try:
            claims = self.a.issuer.verify(token)
        except TokenExpired:
            raise _unauthenticated("token expired, sign in again") from None
        except TokenError as e:
            # Valid tokens are never throttled: only addresses that keep sending
            # forged or foreign tokens are slowed down.
            if self.throttle.blocked(address):
                raise ApiError(
                    429, "too_many_requests", "too many invalid tokens, try again later",
                    {"Retry-After": str(self.throttle.window)},
                ) from None
            self.throttle.fail(address)
            log.warning("admin API: rejected token from %s: %s", address, e)
            raise _unauthenticated("invalid token") from None
        if "resources" in claims:
            raise _unauthenticated("this is a repository access token, use the user token")
        user = self.store.get_user(str(claims.get("sub", "")))
        if user is None:
            raise _unauthenticated("unknown user")
        if user.disabled:
            raise ApiError(403, "user_disabled", "this account is disabled")
        return user

    @staticmethod
    def _query(raw: str, allowed: frozenset[str]) -> dict[str, str]:
        try:
            parsed = parse_qs(raw, keep_blank_values=True, strict_parsing=bool(raw))
        except ValueError:
            raise _bad_request("malformed query string") from None
        query = {}
        for name, values in parsed.items():
            if name not in allowed:
                raise _bad_request(f"unknown query parameter: {name}")
            if len(values) != 1:
                raise _bad_request(f"query parameter {name} must be given once")
            query[name] = _not_empty(values[0], name)
        return query

    @staticmethod
    def _read_body(headers: Message, rfile: BinaryIO) -> bytes:
        if headers.get("Transfer-Encoding"):
            raise _bad_request("send the request body with a Content-Length header")
        try:
            length = int(headers.get("Content-Length") or 0)
        except ValueError:
            raise _bad_request("invalid Content-Length") from None
        if length < 0:
            raise _bad_request("invalid Content-Length")
        if length > MAX_BODY_BYTES:
            # Closing the connection with unread data makes TCP reset it, and the
            # client may lose the response; read moderately sized bodies first.
            if length <= _DRAIN_LIMIT_BYTES:
                rfile.read(length)
            raise ApiError(413, "payload_too_large", f"request body must be at most {MAX_BODY_BYTES} bytes")
        return rfile.read(length) if length else b""

    @staticmethod
    def _parse_body(headers: Message, raw: bytes) -> dict[str, Any]:
        if not raw:
            return {}
        content_type = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise ApiError(415, "unsupported_media_type", "send the request body as application/json")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):
            raise _bad_request("request body is not valid JSON") from None
        if not isinstance(data, dict):
            raise _bad_request("request body must be a JSON object")
        return data

    def _audit(self, call: _Call, message: str, *args) -> None:
        log.info("admin %s from %s: " + message, call.user.name, call.address, *args)

    def _require_user(self, name: str) -> User:
        user = self.store.get_user(name)
        if user is None:
            raise NotFoundError(f"no such user: {name}")
        return user

    def _grant_json(self, user: str, resource_id: str, names: dict[str, str]) -> dict:
        return {"user": user, "repository": _repository_id(resource_id), "repositoryName": names.get(resource_id)}

    def _repository_names(self) -> dict[str, str]:
        return {r.resource_id: r.name for r in self.store.list_repositories()}

    # Endpoints

    def get_me(self, call: _Call) -> Response:
        user = call.user
        return Response(200, {"name": user.name, "displayName": user.display_name, "admin": user.is_admin})

    def list_users(self, call: _Call) -> Response:
        return Response(200, {"users": [_user_json(u) for u in self.store.list_users()]})

    def create_user(self, call: _Call) -> Response:
        body = _fields(call.body, {"name": str, "password": str}, {"displayName": str, "admin": bool})
        name = body["name"]
        display_name = _text(body.get("displayName", ""), "displayName")
        is_admin = body.get("admin", False)
        self.store.add_user(name, body["password"], display_name, is_admin)
        self._audit(call, "created user %s%s", name, " (administrator)" if is_admin else "")
        return Response(201, _user_json(self._require_user(name)))

    def update_user(self, call: _Call) -> Response:
        body = _fields(call.body, {}, {"displayName": str, "admin": bool, "disabled": bool})
        if not body:
            raise _bad_request("nothing to change: send displayName, admin or disabled")
        name = call.params[0]
        display_name = _text(body["displayName"], "displayName") if "displayName" in body else None
        self._require_user(name)
        if name == call.user.name and (body.get("admin") is False or body.get("disabled") is True):
            raise ApiError(409, "conflict", "you cannot remove your own administrator rights or disable yourself")
        if display_name is not None:
            self.store.set_display_name(name, display_name)
        if "admin" in body:
            self.store.set_admin(name, body["admin"])
        if "disabled" in body:
            self.store.set_disabled(name, body["disabled"])
        changes = ", ".join(f"{key}={body[key]!r}" for key in ("displayName", "admin", "disabled") if key in body)
        self._audit(call, "updated user %s: %s", name, changes)
        return Response(200, _user_json(self._require_user(name)))

    def set_password(self, call: _Call) -> Response:
        body = _fields(call.body, {"password": str})
        name = call.params[0]
        self.store.set_password(name, body["password"])
        self._audit(call, "changed the password of user %s", name)
        return Response(204)

    def delete_user(self, call: _Call) -> Response:
        name = call.params[0]
        if name == call.user.name:
            raise ApiError(409, "conflict", "you cannot delete your own account")
        self.store.remove_user(name)
        self._audit(call, "deleted user %s", name)
        return Response(204)

    def list_grants(self, call: _Call) -> Response:
        user = call.query.get("user")
        if user is not None:
            self._require_user(user)
        repository = call.query.get("repository")
        resource_id = self.store.resolve_repository(repository) if repository is not None else None
        names = self._repository_names()
        grants = [self._grant_json(u, rid, names) for u, rid in self.store.list_grants(user, resource_id)]
        return Response(200, {"grants": grants})

    def _grant_target(self, call: _Call) -> tuple[str, str]:
        body = _fields(call.body, {"user": str, "repository": str})
        user = _not_empty(body["user"], "user")
        resource_id = self.store.resolve_repository(_not_empty(body["repository"], "repository"))
        self._require_user(user)
        return user, resource_id

    def put_grant(self, call: _Call) -> Response:
        user, resource_id = self._grant_target(call)
        self.store.grant(user, resource_id)
        self._audit(call, "granted %s access to %s", user, _repository_id(resource_id))
        return Response(200, self._grant_json(user, resource_id, self._repository_names()))

    def delete_grant(self, call: _Call) -> Response:
        user, resource_id = self._grant_target(call)
        self.store.revoke(user, resource_id)
        self._audit(call, "revoked access of %s to %s", user, _repository_id(resource_id))
        return Response(204)

    def list_repositories(self, call: _Call) -> Response:
        repositories = [
            {"id": _repository_id(r.resource_id), "name": r.name, "creator": r.creator or None}
            for r in self.store.list_repositories()
        ]
        return Response(200, {"repositories": repositories})

    def list_api_keys(self, call: _Call) -> Response:
        user = call.query.get("user")
        if user is not None:
            self._require_user(user)
        return Response(200, {"apiKeys": [_api_key_json(k) for k in self.store.api_keys(user)]})

    def create_api_key(self, call: _Call) -> Response:
        body = _fields(call.body, {"user": str}, {"label": str})
        user = body["user"]
        label = _text(body.get("label", ""), "label")
        secret = self.store.create_api_key(user, label)
        key_id = api_key_id(secret)
        key = next(k for k in self.store.api_keys(user) if k.id == key_id)
        self._audit(call, "created API key %s for user %s (label %r)", key_id, user, label)
        return Response(201, {**_api_key_json(key), "key": secret})

    def delete_api_keys(self, call: _Call) -> Response:
        name = call.params[0]
        self._require_user(name)
        revoked = self.store.revoke_api_keys(name)
        self._audit(call, "revoked %d API key(s) of user %s", revoked, name)
        return Response(200, {"revoked": revoked})

    def list_servers(self, call: _Call) -> Response:
        return Response(200, {"servers": [{"url": s.url, "label": s.label} for s in self.store.list_servers()]})

    def put_server(self, call: _Call) -> Response:
        body = _fields(call.body, {"url": str}, {"label": str})
        server = self.store.add_server(_not_empty(body["url"], "url"), _text(body.get("label", ""), "label"))
        self._audit(call, "added server %s", server.url)
        return Response(200, {"url": server.url, "label": server.label})

    def delete_server(self, call: _Call) -> Response:
        body = _fields(call.body, {"url": str})
        self.store.remove_server(_not_empty(body["url"], "url"))
        self._audit(call, "removed server %s", body["url"])
        return Response(204)
