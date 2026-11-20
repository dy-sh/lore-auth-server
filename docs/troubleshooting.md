# Troubleshooting


| Symptom | Cause and fix |
|---|---|
| `Disconnected from server … failed to get environment config` | loreserver has `[server.grpc.certificate]`. Remove it and keep the certificate only under `[server.quic.certificate]` |
| Repositories are listed without a sign-in (or, up to Lore 0.13, `Repository authorizer: AllowAllRepositoryAuthorizer` in the loreserver log) | `[server.auth]` is missing from the loaded config. Check the file in the `--config` directory |
| loreserver can't reach the auth service, or sign-in hangs after the password | `lore.example.com` doesn't resolve to a reachable address from the loreserver machine. Add it to `/etc/hosts` |
| Certificate errors on clients | The client connects by IP or by another name, or the certificate expired. Use the name from `tokens.audience`, and check `openssl x509 -in /etc/lore-auth-server/tls/fullchain.pem -noout -enddate` |
| A user still sees repositories after `revoke` | Access tokens already issued remain valid until they expire (`access_token_ttl_minutes`) |
| Commands run as the wrong user | The client reuses a stored sign-in. Run `lore auth logout --auth-url …` and sign in again |
