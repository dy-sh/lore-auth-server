# Installing on Linux


The steps below assume Ubuntu/Debian and that the service runs on the same machine as loreserver. They take you from an open Lore server to one that requires sign-in. When you're done, the server looks like this:

```text
lore.example.com
  :41337 tcp+udp  loreserver          clone, push, sync
  :41342 tcp      lore-auth-server    gRPC: tokens and permission checks (auth_url)
  :41343 tcp      lore-auth-server    browser login page
```

The order is: install the service, get a certificate, configure and start it, create an administrator, register existing repositories, switch loreserver over, open the ports, verify. loreserver stays open until the switch in step 7.

## 1. Install the package

```bash
sudo apt install -y python3-venv
sudo useradd --system --home-dir /var/lib/lore-auth-server --shell /usr/sbin/nologin lore-auth
sudo install -d -o lore-auth -g lore-auth -m 0755 /var/lib/lore-auth-server
sudo python3 -m venv /opt/lore-auth-server/venv
sudo /opt/lore-auth-server/venv/bin/pip install git+https://github.com/dy-sh/lore-auth-server.git
```

To pin a version, append `@<tag or commit>` to the URL.

The data directory is world-readable (`0755`) on purpose: loreserver runs as a different user and reads `jwks.json` from it. The database and the signing key keep their own restrictive file modes.

## 2. Get a TLS certificate

The certificate must be trusted by the client machines, so use a public CA such as Let's Encrypt. The same certificate is used for loreserver's QUIC endpoint in step 7, so users don't have to install a private CA either.

Point an `A` record for `lore.example.com` at the server first. If your DNS provider offers a proxy (for example Cloudflare's orange cloud), turn it off for this record. Lore needs direct access to UDP 41337 and to the TCP ports above, which such proxies don't forward. For the same reason a proxy-only certificate such as a Cloudflare Origin Certificate won't work.

**Option A: HTTP challenge.** Port 80 must reach the server while the certificate is issued and renewed.

```bash
sudo apt install -y certbot
sudo certbot certonly --standalone -d lore.example.com
```

**Option B: DNS challenge.** Port 80 isn't needed. Here's an example for Cloudflare, using an API token limited to *Zone → DNS → Edit* on your zone:

```bash
sudo apt install -y certbot python3-certbot-dns-cloudflare
sudo install -d -m 0700 /etc/letsencrypt
echo 'dns_cloudflare_api_token = <TOKEN>' | sudo tee /etc/letsencrypt/cloudflare.ini >/dev/null
sudo chmod 0600 /etc/letsencrypt/cloudflare.ini
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 30 -d lore.example.com
```

certbot has plugins for many other DNS providers.

Copy the certificate to where the service reads it:

```bash
sudo install -d -o root -g lore-auth -m 0750 /etc/lore-auth-server/tls
sudo install -m 0640 -o root -g lore-auth /etc/letsencrypt/live/lore.example.com/{fullchain,privkey}.pem /etc/lore-auth-server/tls/
```

certbot renews the certificate automatically (`certbot.timer`), but only under `/etc/letsencrypt/live`. A deploy hook copies each renewed certificate to both services and restarts them. Create `/etc/letsencrypt/renewal-hooks/deploy/lore.sh` and make it executable (`chmod 755`):

```sh
#!/bin/sh
set -e
[ "$RENEWED_LINEAGE" = "/etc/letsencrypt/live/lore.example.com" ] || exit 0
install -m 0640 -o root -g lore-auth "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem" /etc/lore-auth-server/tls/
install -m 0640 -o root -g lore "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem" /etc/lore/certs/letsencrypt/
systemctl restart lore-auth-server
systemctl restart loreserver
```

The hook assumes loreserver runs as user `lore` and reads its certificate from `/etc/lore/certs/letsencrypt/` (step 7). Adjust the names to match your setup. `certbot renew --dry-run` checks renewal, but doesn't run deploy hooks.

## 3. Configure

```bash
sudo install -d -m 0755 /etc/lore-auth-server
sudo curl -fsSL -o /etc/lore-auth-server/config.toml \
  https://raw.githubusercontent.com/dy-sh/lore-auth-server/main/config.example.toml
sudo nano /etc/lore-auth-server/config.toml
```

Set `public_grpc_url`, `public_web_url`, the certificate paths and `tokens.audience`. The audience must contain the host name clients use in `lore://<host>:41337`.

## 4. Run as a service

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

## 5. Create the first administrator

```bash
lore-auth user add admin --admin
```

## 6. Register existing repositories

Repositories created before the service was enabled are unknown to it. Register them so that they can be granted by name. The easiest time is before the switch in step 7, while loreserver still lists everything without sign-in:

```bash
lore repository list lore://lore.example.com:41337     # names and IDs
lore-auth repo add 0198f3c2a1b47c55a0e2d4f6b8c9e012 my-game
lore-auth repo list
```

These repositories have no recorded creator. Administrators and users you grant access to can see them.

## 7. Connect loreserver

Back up loreserver's data and configuration first. The switch only needs a restart, but a copy makes rollback trivial:

```bash
sudo systemctl stop loreserver
sudo tar -C / -cf /var/backups/lore-before-auth.tar var/lib/lore etc/lore    # adjust to your paths
sudo cp -a /etc/lore/config/local.toml /etc/lore/config/local.toml.before-auth
```

Give loreserver the same certificate for its QUIC endpoint:

```bash
sudo install -d -o root -g lore -m 0750 /etc/lore/certs/letsencrypt
sudo install -m 0640 -o root -g lore /etc/letsencrypt/live/lore.example.com/{fullchain,privkey}.pem /etc/lore/certs/letsencrypt/
```

```toml
[server.quic.certificate]
cert_file = "/etc/lore/certs/letsencrypt/fullchain.pem"
pkey_file = "/etc/lore/certs/letsencrypt/privkey.pem"
```

> **Don't add a `[server.grpc.certificate]` block.** For `lore://` URLs the client reads the server's environment configuration over plain gRPC on the same port and moves the data over QUIC with TLS. With TLS on gRPC, every client fails with `Disconnected from server … failed to get environment config`.

Then print the matching auth configuration and add it to loreserver's config file (for example `/etc/lore/config/local.toml`):

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

Do not set `resource_claim` in `[server.auth]`: together with `auth_url` loreserver refuses to start.

loreserver connects to `auth_url` itself, so `lore.example.com` must resolve to a reachable address from the loreserver machine. Behind NAT, the public address usually isn't reachable from inside, because port forwarding only applies to traffic from outside. Point the name at the machine's own address in `/etc/hosts`:

```bash
echo '<server private IP> lore.example.com' | sudo tee -a /etc/hosts
```

Start loreserver and check the log:

```bash
sudo systemctl start loreserver
curl -i http://127.0.0.1:41339/health_check        # HTTP/1.1 200 OK
lore repository list lore://lore.example.com:41337 # [Error] Not authenticated
```

If the list shows repositories without a sign-in, the auth configuration was not picked up and the server is still open. Up to Lore 0.13 the log also says so: `Repository authorizer: AllowAllRepositoryAuthorizer` instead of `AuthClientAuthorizer`; Lore 0.14 no longer logs that line.

## 8. Open the ports

Clients must reach TCP 41342 (gRPC) and 41343 (login page) in addition to loreserver's 41337 (TCP and UDP). If the server is behind NAT, forward these ports and make the rules persistent. On a firewall, allow them.

## 9. Verify

From a client machine:

```bash
lore repository list lore://lore.example.com:41337     # [Error] Not authenticated
lore auth login lore://lore.example.com:41337          # opens the browser; sign in as admin
lore repository list lore://lore.example.com:41337     # lists all repositories
lore clone lore://lore.example.com:41337/my-game
```

In Anchorpoint for Lore, cloning `lore://lore.example.com:41337/<repository>` opens the same login page.

Clients must use the host name from `tokens.audience`. A client connecting by IP address won't send its token there, and the certificate won't match.

## Rollback

To make the server open again, restore the previous loreserver config and restart:

```bash
sudo systemctl stop loreserver
sudo cp /etc/lore/config/local.toml.before-auth /etc/lore/config/local.toml
sudo systemctl start loreserver
```

## Next

- People and access: [users-and-access.md](users-and-access.md)
- Settings and security: [configuration.md](configuration.md)
- When something does not work: [troubleshooting.md](troubleshooting.md)
