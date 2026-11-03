# Sign-in from apps

Apps that show their own user name and password form can complete a Lore sign-in without opening the browser. Lore itself is unchanged: the app starts the usual interactive sign-in (for example `lore auth login --no-browser`, or the client library with the browser turned off), takes the sign-in link it gets, and sends the credentials here instead of opening the page. Lore keeps waiting for the session as usual and stores the token when it completes.

The endpoint is on the login page listener (`public_web_url`, port `41343` by default), next to `/login`.

## Is it there?

```http
GET /api/sign-in
```

`200` with `{"passwordSignIn": true}`. Any other answer (`404` from an older version or another sign-in service): the app opens the sign-in link in the browser instead.

## Sign in

```http
POST /api/sign-in
Content-Type: application/json

{"session": "<code from the sign-in link>", "username": "alice", "password": "…"}
```

The session is the `session` parameter of the sign-in link (`…/login?session=<code>`).

| Status | `error.code` | Meaning |
|---|---|---|
| `200` | — | Signed in: `{"user": "alice", "displayName": "Alice"}`. The client's sign-in finishes on its next poll. |
| `401` | `wrong_credentials` | Wrong user name or password, or the user is disabled. |
| `410` | `session_expired` | No such session, it has expired or was already used. Start signing in again. |
| `429` | `too_many_attempts` | Too many failed attempts from this address (shared with the login page: 5 in 5 minutes). |
| `400`, `413`, `415` | `bad_request`, `too_large`, `unsupported_media_type` | Malformed request. |

Errors look like the admin API's: `{"error": {"code": "…", "message": "…"}}`.

The password goes only to this service, over the same HTTPS connection the login page uses; the checks, the throttle and the log line (`failed sign-in for 'alice' from <address> (app)`) are the same as for the page.
