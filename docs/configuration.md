# Configuration and security

## Configuration reference

See [`config.example.toml`](../config.example.toml). All keys except `public_grpc_url`, `public_web_url` and `tokens.audience` have defaults. Set `LORE_AUTH_CONFIG` to change the default config path and `LORE_AUTH_LOG_LEVEL=DEBUG` for verbose logs.

Without `tls_cert`/`tls_key` both listeners serve plain text. Use that only for local testing with loopback URLs, or behind a reverse proxy that terminates TLS and supports HTTP/2 (gRPC).

`server.admin_api` (default `true`) serves the [admin API](admin-api.md) on the login page listener. Set it to `false` to manage users only with the command line on the server.

## Security notes

- Keep `data_dir` private: `signing-key.pem` can mint tokens for any user. Back up `auth.db` and `signing-key.pem` together.
- Deleting `signing-key.pem` invalidates every issued token; users simply sign in again.
- Removing or disabling a user stops new sign-ins and token exchanges at once. Access tokens already issued remain valid until they expire.
- Failed password attempts are throttled per client address (5 attempts per 5 minutes).
- The login page is only as safe as its transport: always use HTTPS for remote users.
- An administrator's user token controls every account through the admin API, and it stays valid for `user_token_ttl_hours` (30 days by default). If you only manage users on the server, set `admin_api = false`.
