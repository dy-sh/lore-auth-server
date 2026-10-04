# lore-auth-server

A small, self-hosted **username/password sign-in service for [Lore](https://github.com/EpicGames/lore)**, Epic Games' version control system.

Lore Server has no user accounts of its own. It verifies JWTs and delegates sign-in and permission checks to an external auth service through the `UrcAuthApi` gRPC protocol. Epic does not ship that service, so a self-hosted Lore server is either open to everyone or needs custom token tooling that GUI clients cannot use.

`lore-auth-server` implements that protocol in one Python process:

- **Browser sign-in.** `lore auth login` (and GUI clients built on the Lore client library, such as Anchorpoint for Lore) opens a login page, the user enters a username and password, and the client continues on its own.
- **Per-repository access.** Grant users access to specific repositories or to all of them. Repository creators get access to their own repositories automatically.
- **Administrators.** Admins can access, delete and manage every repository.
- **API keys** for scripts and CI: `lore auth login --token-type api-key --token <key>`.
- **Works with `lore://` (QUIC).** Clients get proper access tokens, so the fast QUIC transport keeps working.
- **One file of state.** Users, grants and keys live in SQLite. Passwords are hashed with scrypt.

Tested with Lore 0.10.0 (server and CLI).

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
- A Lore server with a version compatible with Lore 0.10.0.
- **A TLS certificate trusted by the client machines** for the host name in `public_grpc_url`. Lore clients only talk plain HTTP to loopback addresses, and upgrade every other auth URL to HTTPS. A certificate from a public CA, for example Let's Encrypt, avoids installing anything on user machines.
- Two TCP ports reachable by clients: gRPC (default `41342`) and the login page (default `41343`).

## Installation

The steps below assume Ubuntu/Debian and that the service runs on the same machine as loreserver.

### 1. Install the package

```bash
sudo apt install -y python3-venv
sudo useradd --system --home-dir /var/lib/lore-auth-server --shell /usr/sbin/nologin lore-auth
sudo install -d -o lore-auth -g lore-auth -m 0755 /var/lib/lore-auth-server
sudo python3 -m venv /opt/lore-auth-server/venv
sudo /opt/lore-auth-server/venv/bin/pip install git+https://github.com/dy-sh/lore-auth-server.git
```

### 2. Get a TLS certificate

With a domain name pointing at the server and port 80 free, for example:

```bash
sudo apt install -y certbot
sudo certbot certonly --standalone -d lore.example.com
sudo install -d -o root -g lore-auth -m 0750 /etc/lore-auth-server/tls
sudo cp /etc/letsencrypt/live/lore.example.com/{fullchain,privkey}.pem /etc/lore-auth-server/tls/
sudo chgrp lore-auth /etc/lore-auth-server/tls/*.pem && sudo chmod 0640 /etc/lore-auth-server/tls/*.pem
```

Repeat the copy after each renewal (a certbot `--deploy-hook` can do it and restart the service).

### 3. Configure

```bash
sudo install -d -m 0755 /etc/lore-auth-server
sudo curl -fsSL -o /etc/lore-auth-server/config.toml \
  https://raw.githubusercontent.com/dy-sh/lore-auth-server/main/config.example.toml
sudo nano /etc/lore-auth-server/config.toml
```

Set `public_grpc_url`, `public_web_url`, the certificate paths and `tokens.audience`. The audience must contain the host name clients use in `lore://<host>:41337`.

### 4. Run as a service

```bash
sudo curl -fsSL -o /etc/systemd/system/lore-auth-server.service \
  https://raw.githubusercontent.com/dy-sh/lore-auth-server/main/deploy/lore-auth-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now lore-auth-server
sudo journalctl -u lore-auth-server -n 20 --no-pager
```

For convenience, define an alias for the admin commands:

```bash
alias lore-auth='sudo -u lore-auth /opt/lore-auth-server/venv/bin/lore-auth-server --config /etc/lore-auth-server/config.toml'
```

### 5. Create the first administrator

```bash
lore-auth user add admin --admin
```

### 6. Connect loreserver

Print the matching loreserver configuration and add it to loreserver's config file (for example `/etc/lore/config/local.toml`):

```bash
lore-auth lore-config
```

```toml
[server.auth]
jwt_issuer = "lore-auth-server"
jwt_audience = ["lore.example.com"]

[server.auth.jwk]
endpoint = "file:///var/lib/lore-auth-server/jwks.json"

[environment.endpoint]
auth_url = "https://lore.example.com:41342"
```

Do not set `resource_claim` in `[server.auth]`: together with `auth_url` loreserver refuses to start. Restart loreserver and check the log:

```bash
sudo systemctl restart loreserver
sudo journalctl -u loreserver -n 60 --no-pager -o cat | grep -o "Repository authorizer: [A-Za-z]*"
# Repository authorizer: AuthClientAuthorizer
```

loreserver connects to `auth_url` itself, so the host name must also resolve to a reachable address from the loreserver machine.

### 7. Register existing repositories

Repositories created before the service was enabled are unknown to it. Register them so that they can be granted by name:

```bash
lore repository list lore://lore.example.com:41337     # names and IDs
lore-auth repo add 0198f3c2a1b47c55a0e2d4f6b8c9e012 my-game
```

## Managing users

```bash
lore-auth user add alice                    # asks for a password
lore-auth user add bob --display-name "Bob Smith"
lore-auth user passwd alice
lore-auth user disable alice                # block sign-in, keep grants
lore-auth user make-admin alice
lore-auth user remove alice
lore-auth user list

lore-auth grant alice my-game               # by repository name
lore-auth grant alice 0198f3c2a1b47c55a0e2d4f6b8c9e012   # by ID
lore-auth grant alice '*'                   # every repository, including future ones
lore-auth revoke alice my-game

lore-auth repo list
lore-auth apikey create ci-bot --label "build server"   # printed once
lore-auth apikey revoke ci-bot
```

Changes apply immediately: no token reissue is needed. A user who already has an access token for a repository keeps it until it expires (`access_token_ttl_minutes`, 60 by default).

Use `--password-stdin` with `user add` and `user passwd` to script account creation.

## Access rules

| Who | Access |
|---|---|
| Administrator | every repository, including delete and lock management |
| User with a grant for a repository, or the `*` grant | clone, pull, push |
| Creator of a repository | clone, pull, push on that repository |
| Anyone else | nothing; the repository is hidden from `lore repository list` |

`policy.repository_create` controls whether every signed-in user (`everyone`) or only administrators (`admins`) can create repositories. Only the creator or an administrator can delete a repository.

Lore 0.10.0 has no read-only access level: anyone who can clone can also push.

## Using it as a Lore user

```bash
lore auth login lore://lore.example.com:41337      # opens the browser
lore clone lore://lore.example.com:41337/my-game
lore auth logout --auth-url https://lore.example.com:41342   # or run `lore auth logout` inside a repository
```

GUI clients show the same login page when they need a sign-in.

For CI, create an API key and sign in without a browser:

```bash
lore auth login lore://lore.example.com:41337 --token-type api-key --token "$LORE_API_KEY"
```

## Configuration reference

See [`config.example.toml`](config.example.toml). All keys except `public_grpc_url`, `public_web_url` and `tokens.audience` have defaults. Set `LORE_AUTH_CONFIG` to change the default config path and `LORE_AUTH_LOG_LEVEL=DEBUG` for verbose logs.

Without `tls_cert`/`tls_key` both listeners serve plain text. Use that only for local testing with loopback URLs, or behind a reverse proxy that terminates TLS and supports HTTP/2 (gRPC).

## Security notes

- Keep `data_dir` private: `signing-key.pem` can mint tokens for any user. Back up `auth.db` and `signing-key.pem` together.
- Deleting `signing-key.pem` invalidates every issued token; users simply sign in again.
- Removing or disabling a user stops new sign-ins and token exchanges at once. Access tokens already issued remain valid until they expire.
- Failed password attempts are throttled per client address (5 attempts per 5 minutes).
- The login page is only as safe as its transport: always use HTTPS for remote users.

## Limitations

- Lore 0.10.0 clients cannot refresh a sign-in. Users sign in again after `user_token_ttl_hours` (30 days by default).
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
