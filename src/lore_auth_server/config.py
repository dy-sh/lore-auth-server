"""Configuration loading."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/etc/lore-auth-server/config.toml")


@dataclass
class Config:
    # Address advertised to Lore as [environment.endpoint] auth_url. Clients and
    # loreserver connect to it with gRPC. Must be https:// unless it points to a
    # loopback address.
    public_grpc_url: str
    # Base URL of the login page opened in the user's browser.
    public_web_url: str
    # Root domains the issued tokens may be sent to. Must contain the host name
    # (or IP address) of every Lore server that trusts this service.
    audience: list[str]
    issuer: str = "lore-auth-server"

    grpc_listen: str = "0.0.0.0:41342"
    web_listen: str = "0.0.0.0:41343"
    # TLS certificate and key used by both listeners. Leave empty to serve
    # plain text (only for loopback testing or behind a TLS terminating proxy).
    tls_cert: str = ""
    tls_key: str = ""
    # Serve the admin API (docs/admin-api.md) on the web listener.
    admin_api: bool = True

    data_dir: Path = Path("/var/lib/lore-auth-server")
    user_token_ttl_hours: int = 24 * 30
    access_token_ttl_minutes: int = 60
    login_session_ttl_minutes: int = 10

    # Who may create repositories: "everyone" (any signed-in user) or "admins".
    repository_create: str = "everyone"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "auth.db"

    @property
    def signing_key_path(self) -> Path:
        return self.data_dir / "signing-key.pem"


def load_config(path: Path) -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    server = raw.get("server", {})
    tokens = raw.get("tokens", {})
    policy = raw.get("policy", {})

    cfg = Config(
        public_grpc_url=server["public_grpc_url"].rstrip("/"),
        public_web_url=server["public_web_url"].rstrip("/"),
        audience=list(tokens["audience"]),
    )
    for key in ("grpc_listen", "web_listen", "tls_cert", "tls_key", "admin_api"):
        if key in server:
            setattr(cfg, key, server[key])
    if "data_dir" in server:
        cfg.data_dir = Path(server["data_dir"])
    for key in ("issuer", "user_token_ttl_hours", "access_token_ttl_minutes", "login_session_ttl_minutes"):
        if key in tokens:
            setattr(cfg, key, tokens[key])
    if "repository_create" in policy:
        cfg.repository_create = policy["repository_create"]

    if cfg.repository_create not in ("everyone", "admins"):
        raise ValueError("policy.repository_create must be 'everyone' or 'admins'")
    if not isinstance(cfg.admin_api, bool):
        raise ValueError("server.admin_api must be true or false")
    if bool(cfg.tls_cert) != bool(cfg.tls_key):
        raise ValueError("server.tls_cert and server.tls_key must be set together")
    if not cfg.audience:
        raise ValueError("tokens.audience must list at least one domain")
    return cfg
