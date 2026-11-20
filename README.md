# lore-auth-server

A small, self-hosted **username/password sign-in service for [Lore](https://github.com/EpicGames/lore)**, Epic Games' version control system.

Lore Server has no user accounts of its own. It verifies JWTs and delegates sign-in and permission checks to an external auth service through the `UrcAuthApi` gRPC protocol. Epic does not ship that service, so a self-hosted Lore server is either open to everyone or needs custom token tooling that GUI clients cannot use.

`lore-auth-server` implements that protocol in one Python process:

- **Browser sign-in.** `lore auth login` (and GUI clients built on the Lore client library, such as Anchorpoint for Lore) opens a login page, the user enters a username and password, and the client continues on its own.
- **Per-repository access.** Grant users access to specific repositories or to all of them. Repository creators get access to their own repositories automatically.
- **Administrators.** Admins can access, delete and manage every repository.
- **API keys** for scripts and CI: `lore auth login --token-type api-key --token <key>`.
- **Remote administration (optional).** An HTTPS JSON [admin API](docs/admin-api.md) lets GUI clients manage users, access and API keys. Only administrators can use it.
- **Works with `lore://` (QUIC).** Clients get proper access tokens, so the fast QUIC transport keeps working.
- **One file of state.** Users, grants and keys live in SQLite. Passwords are hashed with scrypt.

Tested with loreserver 0.10.0 to 0.14.0, the Lore CLI 0.10.0 to 0.14.0, and Anchorpoint for Lore (which bundles CLI 0.10.1).

## How it works

```text
  Lore client                       lore-auth-server                       loreserver
  ───────────                       ────────────────                       ──────────
  lore auth login ───────────────▶  StartAuthSession → login URL
  browser: username + password ──▶  login page (HTTPS)
  poll GetAuthSession ◀──────────── user token (JWT)
  ExchangeUserTokenForMultiresourceToken ─▶ access token listing allowed repositories
  clone / push with access token ──────────────────────────────────────▶  verifies JWT signature
                                                                           (public key from JWKS file)
                                    CheckUserPermission / LookupUserPermissions ◀── list / create / delete
                                    CreateResource / DeleteResource ◀──────────── repository create / delete
```

The service signs tokens with its own RSA key and writes the public key to `jwks.json` in its data directory. loreserver reads that file to verify every token. Tokens never leave the hosts listed in `tokens.audience`.

## Requirements

- Python 3.11 or newer.
- A Lore server, version 0.10.0 or newer (tested up to 0.14.0).
- A DNS name for the server, for example `lore.example.com`. Clients use it in `lore://lore.example.com:41337`, and tokens are bound to it.
- **A TLS certificate trusted by the client machines** for the host name in `public_grpc_url`. Lore clients only talk plain HTTP to loopback addresses, and upgrade every other auth URL to HTTPS. A certificate from a public CA, for example Let's Encrypt, avoids installing anything on user machines.
- Two TCP ports reachable by clients: gRPC (default `41342`) and the login page (default `41343`).

## Documentation

| | |
|---|---|
| [Installing on Linux](docs/install-linux.md) | From an open Lore server to one that requires sign-in, step by step |
| [Installing on Windows](docs/install-windows.md) | The same on Windows: Python, win-acme, a Task Scheduler task |
| [Users and access](docs/users-and-access.md) | Users, grants, API keys, access rules, signing in as a Lore user |
| [Configuration and security](docs/configuration.md) | Settings and what to keep private |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and their fixes |
| [Admin API](docs/admin-api.md) | The HTTPS JSON API for GUI clients |
| [Sign-in from apps](docs/app-sign-in.md) | A user name and password form in an app instead of the browser page |

## Admin API

GUI clients can manage users, grants, API keys and the list of Lore servers remotely through an HTTPS JSON API. It is served on the login page listener (port 41343 by default), so it needs no extra port. The protocol is open and specified in [docs/admin-api.md](docs/admin-api.md), so other auth services for Lore can implement it too.

- **Discovery.** Clients look for `GET /.well-known/lore-admin` on the login page's address. A client that gets no valid answer there hides its administration features.
- **Sign-in.** Requests carry the user token the client got when the user signed in (`Authorization: Bearer <token>`). Only administrators can use the API. Any signed-in user can call `GET /api/v1/me` to find out whether they are one, and `GET /api/v1/servers` to find every Lore server.
- **Same rules as the command line.** The endpoints use the same operations and checks as the `lore-auth` commands. In addition, administrators can't revoke their own administrator rights, or disable or delete their own account, through the API.
- **Audit.** Every change is logged with the administrator's name and address. Passwords, tokens and keys are never logged.

The API is **on by default**. To turn it off, set `admin_api = false` under `[server]` and restart the service. Discovery and every endpoint then answer `404`, and clients hide their administration features.

```bash
curl -s https://lore.example.com:41343/.well-known/lore-admin
# {"protocol": "lore-admin", "version": 1, "base": "/api/v1", "features": ["users", "grants", "repositories", "api-keys"]}
```

## Limitations

- Lore clients (0.10 and 0.11) cannot refresh a sign-in. Users sign in again after `user_token_ttl_hours` (30 days by default).
- One instance per database: login sessions are kept in memory.
- No OIDC/SSO. Epic plans to move Lore to standard OIDC; once that ships, an off-the-shelf identity provider may be a better fit.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

The gRPC stubs in `src/lore_auth_server/proto` are generated from Lore's protocol files:

```bash
python -m grpc_tools.protoc -I src --python_out=src --grpc_python_out=src \
  src/lore_auth_server/proto/auth_api.proto src/lore_auth_server/proto/rebac_api.proto
```

## License

MIT, see [LICENSE](LICENSE). The protocol files in `src/lore_auth_server/proto` come from Lore (MIT, Epic Games), see [NOTICE](src/lore_auth_server/proto/NOTICE).
