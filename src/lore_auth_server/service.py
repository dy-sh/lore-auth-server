"""gRPC implementation of the Lore auth protocol (epic_urc.UrcAuthApi and ucs.auth.RebacApi)."""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field

import grpc

from .config import Config
from .proto import auth_api_pb2 as pb
from .proto import auth_api_pb2_grpc as pb_grpc
from .proto import rebac_api_pb2 as rebac_pb
from .proto import rebac_api_pb2_grpc as rebac_grpc
from .store import ALL_REPOSITORIES, Store, User
from .tokens import TokenError, TokenIssuer

log = logging.getLogger(__name__)

# Actions understood by loreserver. Being listed for a repository at all grants
# clone/pull/push; the named actions unlock privileged operations.
USER_ACTIONS = ["read", "write"]
ADMIN_ACTIONS = ["read", "write", "admin", "owner", "migrate", "obliterate"]


@dataclass
class LoginSession:
    client_state: str
    created_at: float
    user: User | None = None


@dataclass
class LoginSessions:
    """Browser login sessions, kept in memory. A session lives for a few minutes."""

    ttl_seconds: int
    _sessions: dict[str, LoginSession] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def start(self, client_state: str) -> str:
        code = secrets.token_urlsafe(24)
        with self._lock:
            self._expire()
            self._sessions[code] = LoginSession(client_state, time.time())
        return code

    def exists(self, code: str) -> bool:
        with self._lock:
            self._expire()
            session = self._sessions.get(code)
            return session is not None and session.user is None

    def complete(self, code: str, user: User) -> bool:
        with self._lock:
            self._expire()
            session = self._sessions.get(code)
            if session is None or session.user is not None:
                return False
            session.user = user
            return True

    def take(self, code: str, client_state: str) -> User | None:
        """The signed-in user of a completed session; the session is consumed."""
        with self._lock:
            self._expire()
            session = self._sessions.get(code)
            if session is None or session.client_state != client_state or session.user is None:
                return None
            del self._sessions[code]
            return session.user

    def _expire(self) -> None:
        deadline = time.time() - self.ttl_seconds
        for code in [c for c, s in self._sessions.items() if s.created_at < deadline]:
            del self._sessions[code]


class Authority:
    """Shared state and access rules used by the gRPC services and the login page."""

    def __init__(self, config: Config, store: Store, issuer: TokenIssuer):
        self.config = config
        self.store = store
        self.issuer = issuer
        self.sessions = LoginSessions(config.login_session_ttl_minutes * 60)

    def login_url(self, session_code: str) -> str:
        return f"{self.config.public_web_url}/login?session={session_code}"

    def permissions(self, user: User, resource_id: str) -> list[str] | None:
        """Actions `user` may perform on `resource_id`, or None when it has no access."""
        if user.disabled:
            return None
        if user.is_admin:
            return list(ADMIN_ACTIONS)
        grants = self.store.grants_of(user.name)
        if ALL_REPOSITORIES in grants or resource_id in grants:
            return list(USER_ACTIONS)
        if resource_id != ALL_REPOSITORIES:
            repository = self.store.get_repository(resource_id)
            if repository and repository.creator == user.name:
                return list(USER_ACTIONS)
        return None

    def visible_repositories(self, user: User) -> list[str]:
        known = [r.resource_id for r in self.store.list_repositories()]
        return [rid for rid in known if self.permissions(user, rid) is not None]

    def user_from_context(self, context: grpc.ServicerContext) -> User:
        """The user behind the request's `authorization` header, or abort UNAUTHENTICATED."""
        header = dict(context.invocation_metadata()).get("authorization", "")
        token = header[7:] if header.lower().startswith("bearer ") else header
        if not token:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "authorization header required")
        try:
            claims = self.issuer.verify(token)
        except TokenError as e:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, str(e))
        user = self.store.get_user(claims.get("sub", ""))
        if user is None or user.disabled:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "unknown or disabled user")
        return user

    def user_token_message(self, user: User) -> pb.UserToken:
        token, expires_at = self.issuer.user_token(user)
        return pb.UserToken(user_token=token, expires_at=expires_at, user_id=user.name, user_name=user.display_name)


class UrcAuthApi(pb_grpc.UrcAuthApiServicer):
    def __init__(self, authority: Authority):
        self.a = authority

    def HealthCheck(self, request, context):
        return pb.HealthCheckResponse(status="ok")

    # Interactive (browser) login: the client starts a session, opens the
    # login URL and polls GetAuthSession until the user has signed in.

    def StartAuthSession(self, request, context):
        if not request.client_state:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "client_state required")
        code = self.a.sessions.start(request.client_state)
        return pb.StartAuthSessionResponse(session_code=code, login_url=self.a.login_url(code))

    def GetAuthSession(self, request, context):
        user = self.a.sessions.take(request.session_code, request.client_state)
        if user is None:
            return pb.GetAuthSessionResponse()
        log.info("user %s signed in via browser", user.name)
        return pb.GetAuthSessionResponse(user_token=self.a.user_token_message(user))

    def RefreshAuthSession(self, request, context):
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "sign in again when the token expires")

    # Non-interactive login: `lore auth login --token-type api-key --token <key>`.

    def ExchangeExternalTokenForUserToken(self, request, context):
        if request.token_type not in ("api-key", "api_key", "apikey"):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"unsupported token type {request.token_type!r}")
        return pb.ExchangeExternalTokenForUserTokenResponse(user_token=self._user_for_key(request.external_token, context))

    def ExchangeAPIKeyForUserToken(self, request, context):
        return pb.ExchangeAPIKeyForUserTokenResponse(user_token=self._user_for_key(request.api_key, context))

    def _user_for_key(self, key: str, context) -> pb.UserToken:
        user = self.a.store.user_for_api_key(key)
        if user is None:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid API key")
        log.info("user %s signed in with an API key", user.name)
        return self.a.user_token_message(user)

    # Authorization: the client trades its user token for a short-lived token
    # that lists the repositories it may access; loreserver checks that list.

    def ExchangeUserTokenForMultiresourceToken(self, request, context):
        user = self.a.user_from_context(context)
        resources = []
        for resource_id in request.resource_id:
            actions = self.a.permissions(user, resource_id)
            if actions is not None:
                resources.append({"resource_id": resource_id, "permission": actions})
        if not resources:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "no access to the requested repositories")
        token, expires_at = self.a.issuer.access_token(user, resources)
        return pb.ExchangeUserTokenForMultiresourceTokenResponse(
            token=pb.UserToken(user_token=token, expires_at=expires_at, user_id=user.name, user_name=user.display_name)
        )

    def CheckUserPermission(self, request, context):
        caller = self.a.user_from_context(context)
        user = caller
        if request.HasField("target_user") and request.target_user.user_token:
            try:
                claims = self.a.issuer.verify(request.target_user.user_token)
            except TokenError as e:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, str(e))
            user = self.a.store.get_user(claims.get("sub", "")) or caller
        allowed, denied = [], []
        for resource_id in request.resource_id:
            actions = self.a.permissions(user, resource_id)
            if actions is None:
                denied.append(pb.ResourcePermission(resource_id=resource_id))
            else:
                allowed.append(pb.ResourcePermission(resource_id=resource_id, permission=actions))
        return pb.CheckUserPermissionResponse(allowed_resource_permission=allowed, denied_resource_permission=denied)

    def LookupUserPermissions(self, request, context):
        user = self.a.user_from_context(context)
        prefix = request.resource_filter or ""
        result = [
            pb.ResourcePermission(resource_id=rid, permission=self.a.permissions(user, rid))
            for rid in self.a.visible_repositories(user)
            if rid.startswith(prefix)
        ]
        return pb.LookupUserPermissionsResponse(resource_permission=result)

    # User metadata, used by clients to show display names.

    def VerifyUser(self, request, context):
        self.a.user_from_context(context)
        try:
            claims = self.a.issuer.verify(request.target_user.user_token)
        except TokenError as e:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, str(e))
        user = self.a.store.get_user(claims.get("sub", ""))
        if user is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "unknown user")
        return pb.VerifyUserResponse(user_info=pb.UserInfo(user_id=user.name, display_name=user.display_name))

    def GetUserInfo(self, request, context):
        self.a.user_from_context(context)
        infos = []
        for user_id in request.user_id:
            user = self.a.store.get_user(user_id)
            if user:
                infos.append(pb.UserInfo(user_id=user.name, display_name=user.display_name))
        return pb.GetUserInfoResponse(user_info=infos)

    def GetUserId(self, request, context):
        self.a.user_from_context(context)
        wanted = request.user_display_name
        for user in self.a.store.list_users():
            if wanted in (user.name, user.display_name):
                return pb.GetUserIdResponse(user_info=pb.UserInfo(user_id=user.name, display_name=user.display_name))
        context.abort(grpc.StatusCode.NOT_FOUND, "unknown user")

    def GetProviderUserId(self, request, context):
        self.a.user_from_context(context)
        return pb.GetProviderUserIdResponse(user_id=request.user_id, provider_user_id=request.user_id)


class RebacApi(rebac_grpc.RebacApiServicer):
    """loreserver registers repositories here when they are created or deleted."""

    def __init__(self, authority: Authority):
        self.a = authority

    def CreateResource(self, request, context):
        user = self.a.user_from_context(context)
        existing = self.a.store.get_repository(request.resource_id)
        if existing:
            context.abort(grpc.StatusCode.ALREADY_EXISTS, "repository already registered")
        if self.a.config.repository_create == "admins" and not user.is_admin:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "only administrators may create repositories")
        self.a.store.add_repository(request.resource_id, request.resource_name, creator=user.name)
        log.info("user %s created repository %s (%s)", user.name, request.resource_name, request.resource_id)
        return rebac_pb.CreateResourceResponse()

    def DeleteResource(self, request, context):
        user = self.a.user_from_context(context)
        repository = self.a.store.get_repository(request.resource_id)
        if not user.is_admin and (repository is None or repository.creator != user.name):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "only the creator or an administrator may delete")
        self.a.store.remove_repository(request.resource_id)
        log.info("user %s deleted repository %s", user.name, request.resource_id)
        return rebac_pb.DeleteResourceResponse()
