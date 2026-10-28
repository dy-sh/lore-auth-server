# Lore admin API, version 1

An open HTTPS JSON protocol for managing the users and repository access of a Lore auth service remotely. [lore-auth-server](../README.md) implements it. Other auth services for Lore may implement it too.

- [Purpose](#purpose)
- [The API is optional](#the-api-is-optional)
- [Conventions](#conventions)
- [Locating the API](#locating-the-api)
- [Discovery](#discovery)
- [Authentication](#authentication)
- [Errors](#errors)
- [Endpoints](#endpoints): [me](#get-me), [users](#users), [grants](#grants), [repositories](#repositories), [API keys](#api-keys), [servers](#servers)
- [Versioning](#versioning)
- [Security considerations](#security-considerations)
- [Notes on lore-auth-server](#notes-on-lore-auth-server)

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## Purpose

Lore servers delegate sign-in and permission checks to an external auth service through the `UrcAuthApi` gRPC protocol. That protocol covers signing in and checking access, but not administration: there is no standard way to create users, reset passwords or give someone access to a repository. Each auth service has its own tools, usually a command line on the server host.

This protocol fills that gap, so that a GUI client can offer the same administration screens for any auth service that implements it. It covers:

- **users**: list, create, change, disable, delete, set passwords;
- **grants**: which user may access which repository;
- **repositories**: the repositories the auth service knows;
- **API keys**: keys for scripts and CI.
- **servers**: the Lore servers that use the auth service, so that a client finds every repository after one sign-in. Teams may run a Lore server per project behind one auth service, and the auth service knows repositories but not where they live.

## The API is optional

- An auth service doesn't have to implement this API, and an administrator may turn it off.
- A client MUST keep working without it. When [discovery](#discovery) fails for any reason (no answer, an HTTP error, a body that isn't the expected JSON, another `protocol`, or a `version` the client doesn't support), the client hides its administration features.
- A server MAY implement only some features. The discovery document lists them, and the client shows only those.

## Conventions

- **Transport.** HTTPS. Plain HTTP is acceptable only for loopback addresses.
- **Bodies.** Request and response bodies are JSON objects encoded as UTF-8, with `Content-Type: application/json`. Field names use camelCase. A request body MUST be sent with `Content-Length`. Servers MAY reject large bodies with `413`.
- **Unknown fields.** Clients MUST ignore response fields they don't know. Servers SHOULD reject request fields and query parameters they don't know with `400 invalid_request`, so that a typo never silently does nothing.
- **Users** are identified by their user name: the `sub` claim of the user token and the `user_id` in `UrcAuthApi`. In paths it is percent-encoded.
- **Repositories** are identified by their Lore repository ID, 32 lowercase hexadecimal characters, as `lore repository list` shows it. `*` means every repository, including future ones. Where a request takes a repository, it accepts a repository ID, `*`, or a repository name, provided the server knows the name and it is unique. Servers MAY also accept the resource form `urc-<ID>`. Responses always use the bare ID or `*`.
- **Timestamps** are ISO 8601 strings in UTC, for example `2026-10-28T09:15:00Z`.
- **Caching.** Responses carry `Cache-Control: no-store`.

## Locating the API

The API lives on an HTTPS origin chosen by the auth service. A server that implements it SHOULD serve it on the origin of its login page: the `login_url` that `UrcAuthApi.StartAuthSession` returns. lore-auth-server does that: the API is on the login page listener (`public_web_url`, for example `https://lore.example.com:41343`).

A client that works with a Lore server therefore tries, in order:

1. the origin (scheme, host and port) of the login URL it saw when the user signed in;
2. an address the user entered.

It then requests the discovery document on that origin.

## Discovery

```http
GET /.well-known/lore-admin
```

No authentication. Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "protocol": "lore-admin",
  "version": 1,
  "base": "/api/v1",
  "features": ["users", "grants", "repositories", "api-keys", "servers"]
}
```

| Field | Meaning |
|---|---|
| `protocol` | Always `lore-admin`. |
| `version` | Major version of the protocol, an integer. This document describes `1`. |
| `base` | Location of the endpoints, resolved against the discovery URL. The paths below are relative to it: `GET /me` means `GET /api/v1/me` here. |
| `features` | The endpoint groups this server offers. Clients ignore names they don't know. |

| Feature | Endpoints |
|---|---|
| — | `GET /me` is always available. |
| `users` | `GET /users`, `POST /users`, `PATCH /users/{name}`, `PUT /users/{name}/password`, `DELETE /users/{name}` |
| `grants` | `GET /grants`, `PUT /grants`, `DELETE /grants` |
| `repositories` | `GET /repositories` |
| `api-keys` | `GET /api-keys`, `POST /api-keys`, `DELETE /api-keys/{name}` |
| `servers` | `GET /servers`, `PUT /servers`, `DELETE /servers` |

A server that has the API turned off answers `404` here, like a server that doesn't implement it.

## Authentication

Every request under `base` carries the user token that the auth service issued when the user signed in:

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

This is the `user_token` from `UrcAuthApi` (`GetAuthSession`, `ExchangeAPIKeyForUserToken` or `ExchangeExternalTokenForUserToken`). Short-lived repository access tokens from `ExchangeUserTokenForMultiresourceToken` are not accepted.

| Status | `code` | When | What the client does |
|---|---|---|---|
| `401` | `unauthenticated` | No token, a malformed, forged, foreign or expired token, a repository access token, or a user that no longer exists. The response has a `WWW-Authenticate: Bearer` header. | Ask the user to sign in again. |
| `403` | `user_disabled` | The account is disabled. | Tell the user; signing in again won't help. |
| `403` | `forbidden` | The user isn't an administrator. Every endpoint except `GET /me` and `GET /servers` requires administrator rights. | Hide the administration features. |
| `429` | `too_many_requests` | Too many failed attempts from this address. The `Retry-After` header gives the wait in seconds. | Wait, then retry. |

The server checks the user's current state on every request. Revoked administrator rights, a disabled account or a deleted user take effect at once, even for tokens issued earlier.

A client calls `GET /me` after discovery to decide whether to show administration features at all.

## Errors

Every error response has this body:

```json
{"error": {"code": "not_found", "message": "no such user: carol"}}
```

`code` is stable and meant for programs. `message` is a short English explanation for people, and it can change. Clients MUST handle a code they don't know by its HTTP status.

| Status | `code` | Meaning |
|---|---|---|
| `400` | `invalid_request` | Malformed JSON, a missing, unknown or mistyped field, an unknown query parameter, or a value the server doesn't accept (for example a password that is too short). `message` says what is wrong. |
| `401` | `unauthenticated` | See [Authentication](#authentication). |
| `403` | `user_disabled`, `forbidden` | See [Authentication](#authentication). |
| `404` | `not_found` | Unknown endpoint, user or repository. |
| `405` | `method_not_allowed` | The endpoint exists, but not with this method. The `Allow` header lists the methods it supports. |
| `409` | `conflict` | The user already exists, a repository name is ambiguous (use its ID), or the change would lock the caller out (see [`PATCH /users/{name}`](#patch-usersname)). |
| `413` | `payload_too_large` | The request body is too large. A server MAY close the connection instead of answering. |
| `415` | `unsupported_media_type` | The request body isn't `application/json`. |
| `429` | `too_many_requests` | See [Authentication](#authentication). |
| `500` | `internal` | A server error. Details are in the server log, not in the response. |

## Endpoints

All examples assume `base` is `/api/v1` and leave out the `Authorization` header.

### GET /me

The signed-in user. Available to every user, not only administrators.

```http
GET /api/v1/me
```

```http
HTTP/1.1 200 OK

{"name": "alice", "displayName": "Alice Smith", "admin": false}
```

| Field | Type | Meaning |
|---|---|---|
| `name` | string | User name. |
| `displayName` | string | Name to show in the interface. |
| `admin` | boolean | Whether the user is an administrator and may use the rest of the API. |

### Users

A user object:

```json
{"name": "alice", "displayName": "Alice Smith", "admin": false, "disabled": false}
```

`disabled` users can't sign in, exchange tokens or use this API. Their grants and API keys are kept.

#### GET /users

```http
GET /api/v1/users
```

```http
HTTP/1.1 200 OK

{
  "users": [
    {"name": "alice", "displayName": "Alice Smith", "admin": false, "disabled": false},
    {"name": "root", "displayName": "root", "admin": true, "disabled": false}
  ]
}
```

#### POST /users

Creates a user.

| Field | Type | |
|---|---|---|
| `name` | string | Required. Can't be changed later. |
| `password` | string | Required. |
| `displayName` | string | Optional. Defaults to `name`. |
| `admin` | boolean | Optional. Defaults to `false`. |

```http
POST /api/v1/users
Content-Type: application/json

{"name": "bob", "password": "correct horse battery", "displayName": "Bob Jones"}
```

```http
HTTP/1.1 201 Created

{"name": "bob", "displayName": "Bob Jones", "admin": false, "disabled": false}
```

Errors: `409 conflict` if the user exists, `400 invalid_request` for a name or password the server doesn't accept.

#### PATCH /users/{name}

Changes a user. Send at least one field; fields you leave out keep their values.

| Field | Type | |
|---|---|---|
| `displayName` | string | An empty string resets it to the user name. |
| `admin` | boolean | Grant or revoke administrator rights. |
| `disabled` | boolean | Block or allow sign-in. |

```http
PATCH /api/v1/users/bob
Content-Type: application/json

{"admin": true}
```

```http
HTTP/1.1 200 OK

{"name": "bob", "displayName": "Bob Jones", "admin": true, "disabled": false}
```

A server SHOULD refuse with `409 conflict` a request that removes the caller's own administrator rights or disables the caller's own account, so that an administrator can't lock themselves out by mistake. Another administrator can still make that change.

Errors: `404 not_found` for an unknown user.

#### PUT /users/{name}/password

Sets a new password. The old one isn't needed: only administrators can call this endpoint.

```http
PUT /api/v1/users/bob/password
Content-Type: application/json

{"password": "new long password"}
```

```http
HTTP/1.1 204 No Content
```

Errors: `404 not_found`, `400 invalid_request` for a password the server doesn't accept.

#### DELETE /users/{name}

Deletes a user together with their grants and API keys.

```http
DELETE /api/v1/users/bob
```

```http
HTTP/1.1 204 No Content
```

A server SHOULD refuse with `409 conflict` to delete the caller's own account. Errors: `404 not_found`.

### Grants

A grant gives one user access to one repository, or to every repository with `*`. A grant object:

```json
{"user": "alice", "repository": "0198f3c2a1b47c55a0e2d4f6b8c9e012", "repositoryName": "my-game"}
```

| Field | Type | Meaning |
|---|---|---|
| `user` | string | User name. |
| `repository` | string | Repository ID, or `*` for every repository. |
| `repositoryName` | string or `null` | The repository's name if the server knows it; `null` for `*` and for unknown repositories. |

Grants are only the explicit ones. Access the server gives in other ways, for example to administrators or to the user who created a repository, isn't listed.

#### GET /grants

Optional query parameters, which can be combined:

| Parameter | Meaning |
|---|---|
| `user` | Only this user's grants. `404` if the user doesn't exist. |
| `repository` | Only grants for exactly this repository (ID, name or `*`). `repository=*` returns the grants for every repository, not all grants. `404` if the repository is unknown. |

```http
GET /api/v1/grants?user=alice
```

```http
HTTP/1.1 200 OK

{
  "grants": [
    {"user": "alice", "repository": "*", "repositoryName": null},
    {"user": "alice", "repository": "0198f3c2a1b47c55a0e2d4f6b8c9e012", "repositoryName": "my-game"}
  ]
}
```

#### PUT /grants

Gives a user access to a repository. Granting access that already exists isn't an error.

```http
PUT /api/v1/grants
Content-Type: application/json

{"user": "alice", "repository": "my-game"}
```

```http
HTTP/1.1 200 OK

{"user": "alice", "repository": "0198f3c2a1b47c55a0e2d4f6b8c9e012", "repositoryName": "my-game"}
```

`repository` is a repository ID, `*`, or a known repository name. A server MAY accept the ID of a repository it doesn't know yet. lore-auth-server does, and the grant applies to that repository.

Errors: `404 not_found` for an unknown user or repository name, `409 conflict` for an ambiguous repository name.

#### DELETE /grants

Takes access away. Takes the same body as `PUT /grants`. Revoking a grant that doesn't exist isn't an error. Access the user has in other ways, for example through a `*` grant, stays.

```http
DELETE /api/v1/grants
Content-Type: application/json

{"user": "alice", "repository": "my-game"}
```

```http
HTTP/1.1 204 No Content
```

Errors: `404 not_found` for an unknown user or repository name, `409 conflict` for an ambiguous repository name.

### Repositories

#### GET /repositories

The repositories the auth service knows, sorted by name: those created while it was in charge, which the Lore server registers on creation, and those an administrator registered. It can miss repositories that were created before the auth service was enabled and never registered.

```http
GET /api/v1/repositories
```

```http
HTTP/1.1 200 OK

{
  "repositories": [
    {"id": "0198f3c2a1b47c55a0e2d4f6b8c9e012", "name": "my-game", "creator": "alice"},
    {"id": "0198f3c2a1b47c55a0e2d4f6b8c9e999", "name": "old-project", "creator": null}
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Repository ID. |
| `name` | string | Repository name. |
| `creator` | string or `null` | User who created it, or `null` if unknown. |

### API keys

API keys let scripts and CI sign in without a browser (`lore auth login --token-type api-key --token <key>`). Each key belongs to a user and acts as that user. Servers store only a digest of the key, so the secret is shown once, when the key is created.

An API key object:

```json
{"id": "3f2a9c1b7d4e", "user": "ci-bot", "label": "build server", "createdAt": "2026-10-28T09:15:00Z"}
```

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Identifier of the key. It isn't secret and can't be used to sign in. |
| `user` | string | The user the key signs in as. |
| `label` | string | Free text, may be empty. |
| `createdAt` | string | When the key was created. |

#### GET /api-keys

Optional query parameter `user`: only this user's keys (`404` if the user doesn't exist). Secrets are never returned.

```http
GET /api/v1/api-keys
```

```http
HTTP/1.1 200 OK

{
  "apiKeys": [
    {"id": "3f2a9c1b7d4e", "user": "ci-bot", "label": "build server", "createdAt": "2026-10-28T09:15:00Z"}
  ]
}
```

#### POST /api-keys

Creates a key. The response is the only time the secret, `key`, is returned. Show it to the administrator once and don't store it.

| Field | Type | |
|---|---|---|
| `user` | string | Required. The user the key signs in as. |
| `label` | string | Optional. |

```http
POST /api/v1/api-keys
Content-Type: application/json

{"user": "ci-bot", "label": "build server"}
```

```http
HTTP/1.1 201 Created

{
  "id": "3f2a9c1b7d4e",
  "user": "ci-bot",
  "label": "build server",
  "createdAt": "2026-10-28T09:15:00Z",
  "key": "lak_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
}
```

Errors: `404 not_found` for an unknown user.

#### DELETE /api-keys/{name}

Revokes **every** API key of user `{name}` and returns how many were revoked. Revoking when there are no keys isn't an error.

```http
DELETE /api/v1/api-keys/ci-bot
```

```http
HTTP/1.1 200 OK

{"revoked": 1}
```

Errors: `404 not_found` for an unknown user.

### Servers

The Lore servers that use this auth service. Clients list them after sign-in to show the repositories of every server, not only the one the user signed in through. A server object:

```json
{"url": "lore://lore.example.com:41344", "label": "Game"}
```

| Field | Type | Meaning |
|---|---|---|
| `url` | string | Server address, `scheme://host[:port]` without a path. The scheme is lower case; a trailing `/` is dropped. |
| `label` | string | Free text, may be empty. |

#### GET /servers

Available to every signed-in user, not only administrators: the list holds addresses, and each server still hides the repositories a user has no access to.

```http
GET /api/v1/servers
```

```http
HTTP/1.1 200 OK

{
  "servers": [
    {"url": "lore://lore.example.com:41337", "label": ""},
    {"url": "lore://lore.example.com:41344", "label": "Game"}
  ]
}
```

#### PUT /servers

Adds a server, or changes its label. Adding a server that is already listed isn't an error.

```http
PUT /api/v1/servers
Content-Type: application/json

{"url": "lore://lore.example.com:41344", "label": "Game"}
```

```http
HTTP/1.1 200 OK

{"url": "lore://lore.example.com:41344", "label": "Game"}
```

Errors: `400 invalid_request` for an address that isn't `scheme://host[:port]`.

#### DELETE /servers

Removes a server from the list. The server itself and its repositories aren't touched.

```http
DELETE /api/v1/servers
Content-Type: application/json

{"url": "lore://lore.example.com:41344"}
```

```http
HTTP/1.1 204 No Content
```

Errors: `404 not_found` for a server that isn't listed.

## Versioning

- `version` in the discovery document is the major version of the protocol.
- Compatible changes keep the version: new response fields, new error codes, and new endpoints that come with a new feature name.
- An incompatible change gets a new version and a new `base`. A client that doesn't support the advertised version treats the API as absent.

## Security considerations

- The user token is a bearer credential. Clients send it only over HTTPS, and only to the origin they found for the same auth service.
- An administrator's token controls every account. Its lifetime is the auth service's sign-in lifetime, which can be long. Administrators who don't need remote administration should turn the API off.
- The API is meant for native clients. Servers don't need to send CORS headers, and lore-auth-server sends none, so web pages on other origins can't call it from a browser.
- Servers SHOULD log every change with the administrator's name and address, and MUST NOT log passwords, tokens or API keys.

## Notes on lore-auth-server

- **On by default.** The API is enabled unless `admin_api = false` is set under `[server]` in the configuration file. When it is off, the discovery document and every endpoint answer `404`.
- **Servers.** lore-auth-server doesn't learn server addresses by itself: an administrator lists them (`lore-auth-server server add lore://host:port`, or `PUT /servers`).
- **Same rules as the command line.** The endpoints use the same store operations and checks as the `lore-auth-server` commands, so the results are the same. The API adds the lock-out protection described in [`PATCH /users/{name}`](#patch-usersname) and [`DELETE /users/{name}`](#delete-usersname), and it can change display names, which the command line can't.
- **Limits.** User names: letters, digits and `_ . @ -`, up to 64 characters, starting with a letter or a digit. Passwords: at least 8 characters. Display names and API key labels: up to 128 characters, without control characters; surrounding spaces are trimmed. Request bodies: up to 8 KiB.
- **Throttling.** Valid tokens are never throttled. After 5 invalid tokens (malformed, forged or from another issuer) from one address within 5 minutes, further invalid tokens from it get `429` until the window passes. This counter is separate from the login page's.
- **Logging.** Every change is logged at `INFO`, for example `admin root from 203.0.113.7: created user bob`. Rejected tokens are logged at `WARNING`.
