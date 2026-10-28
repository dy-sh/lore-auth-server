"""Command line: run the server and manage users, repositories and grants."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import signal
import sys
import threading
from concurrent import futures
from pathlib import Path

import grpc

from . import __version__
from .config import DEFAULT_CONFIG_PATH, Config, load_config
from .proto import auth_api_pb2_grpc, rebac_api_pb2_grpc
from .service import Authority, RebacApi, UrcAuthApi
from .store import MIN_PASSWORD_LENGTH, Store
from .tokens import TokenIssuer
from .web import start_web_server

log = logging.getLogger("lore_auth_server")


def _jwks_path(config: Config) -> Path:
    return config.data_dir / "jwks.json"


def serve(config: Config) -> None:
    store = Store(config.db_path)
    issuer = TokenIssuer(config)
    authority = Authority(config, store, issuer)

    # loreserver reads the public key from this file ([server.auth.jwk] endpoint = "file://...").
    jwks = _jwks_path(config)
    jwks.write_text(json.dumps(issuer.jwks))
    os.chmod(jwks, 0o644)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    auth_api_pb2_grpc.add_UrcAuthApiServicer_to_server(UrcAuthApi(authority), server)
    rebac_api_pb2_grpc.add_RebacApiServicer_to_server(RebacApi(authority), server)
    if config.tls_cert:
        credentials = grpc.ssl_server_credentials(
            [(Path(config.tls_key).read_bytes(), Path(config.tls_cert).read_bytes())]
        )
        server.add_secure_port(config.grpc_listen, credentials)
    else:
        server.add_insecure_port(config.grpc_listen)
    server.start()
    log.info("gRPC listener on %s (%s)", config.grpc_listen, "tls" if config.tls_cert else "plain text")
    web = start_web_server(authority)
    log.info("advertised auth_url: %s", config.public_grpc_url)

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()
    log.info("shutting down")
    web.shutdown()
    server.stop(grace=5).wait()


def _read_password(args) -> str:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != password:
            raise SystemExit("passwords do not match")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise SystemExit(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    return password


def lore_config_snippet(config: Config) -> str:
    return f"""# Add to the loreserver config (for example /etc/lore/config/local.toml)
# and restart loreserver. Remove resource_claim if it is present.

[server.auth]
jwt_issuer = "{config.issuer}"
jwt_audience = {json.dumps(config.audience)}

[server.auth.jwk]
endpoint = "file://{_jwks_path(config).as_posix()}"

[environment.endpoint]
auth_url = "{config.public_grpc_url}"
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lore-auth-server", description="Minimal user/password auth service for Lore.")
    p.add_argument("--config", type=Path, default=Path(os.environ.get("LORE_AUTH_CONFIG", DEFAULT_CONFIG_PATH)))
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("serve", help="run the service")
    sub.add_parser("lore-config", help="print the loreserver configuration for this service")

    user = sub.add_parser("user", help="manage users").add_subparsers(dest="action", required=True)
    add = user.add_parser("add", help="create a user")
    add.add_argument("name")
    add.add_argument("--display-name", default="")
    add.add_argument("--admin", action="store_true", help="full access to all repositories")
    add.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    pw = user.add_parser("passwd", help="change a password")
    pw.add_argument("name")
    pw.add_argument("--password-stdin", action="store_true")
    for name, help_text in (("remove", "delete a user"), ("disable", "block sign-in"), ("enable", "allow sign-in"),
                            ("make-admin", "grant administrator rights"), ("drop-admin", "revoke administrator rights")):
        user.add_parser(name, help=help_text).add_argument("name")
    user.add_parser("list", help="list users and their grants")

    grant = sub.add_parser("grant", help="give a user access to a repository")
    grant.add_argument("user")
    grant.add_argument("repository", help="repository name, 32-character ID, or * for all repositories")
    revoke = sub.add_parser("revoke", help="take access away")
    revoke.add_argument("user")
    revoke.add_argument("repository")

    repo = sub.add_parser("repo", help="manage known repositories").add_subparsers(dest="action", required=True)
    repo.add_parser("list", help="list repositories")
    radd = repo.add_parser("add", help="register a repository created before this service was enabled")
    radd.add_argument("id", help="repository ID, as shown by `lore repository list`")
    radd.add_argument("name")
    rrm = repo.add_parser("remove", help="forget a repository")
    rrm.add_argument("repository")

    key = sub.add_parser("apikey", help="API keys for scripts and CI").add_subparsers(dest="action", required=True)
    kc = key.add_parser("create", help="create an API key (printed once)")
    kc.add_argument("user")
    kc.add_argument("--label", default="")
    key.add_parser("list", help="list a user's API keys").add_argument("user")
    key.add_parser("revoke", help="delete all API keys of a user").add_argument("user")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=os.environ.get("LORE_AUTH_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(args.config)

    if args.cmd == "serve":
        serve(config)
        return
    if args.cmd == "lore-config":
        print(lore_config_snippet(config))
        return

    store = Store(config.db_path)
    try:
        _admin_command(args, store)
    except ValueError as e:
        raise SystemExit(f"error: {e}") from None


def _admin_command(args, store: Store) -> None:
    if args.cmd == "user":
        if args.action == "add":
            store.add_user(args.name, _read_password(args), args.display_name, args.admin)
            print(f"user {args.name} created")
        elif args.action == "passwd":
            store.set_password(args.name, _read_password(args))
            print("password changed")
        elif args.action == "remove":
            store.remove_user(args.name)
            print(f"user {args.name} removed")
        elif args.action in ("disable", "enable"):
            store.set_disabled(args.name, args.action == "disable")
            print(f"user {args.name} {args.action}d")
        elif args.action in ("make-admin", "drop-admin"):
            store.set_admin(args.name, args.action == "make-admin")
            print("done")
        elif args.action == "list":
            names = {r.resource_id: r.name for r in store.list_repositories()}
            for u in store.list_users():
                flags = ", ".join(f for f, on in (("admin", u.is_admin), ("disabled", u.disabled)) if on)
                grants = [("all" if g == "urc-*" else names.get(g, g)) for g in store.grants_of(u.name)]
                print(f"{u.name:<20} {flags:<16} {', '.join(grants) or '-'}")
    elif args.cmd in ("grant", "revoke"):
        resource = store.resolve_repository(args.repository)
        (store.grant if args.cmd == "grant" else store.revoke)(args.user, resource)
        print("done")
    elif args.cmd == "repo":
        if args.action == "list":
            for r in store.list_repositories():
                print(f"{r.name:<30} {r.resource_id[4:]}  creator: {r.creator or '-'}")
        elif args.action == "add":
            resource = store.resolve_repository(args.id)
            store.add_repository(resource, args.name)
            print(f"repository {args.name} registered")
        elif args.action == "remove":
            store.remove_repository(store.resolve_repository(args.repository))
            print("done")
    elif args.cmd == "apikey":
        if args.action == "create":
            print(store.create_api_key(args.user, args.label))
        elif args.action == "list":
            for prefix, label, created in store.list_api_keys(args.user):
                print(f"{prefix}...  {label}  created {created}")
        elif args.action == "revoke":
            print(f"{store.revoke_api_keys(args.user)} key(s) revoked")
