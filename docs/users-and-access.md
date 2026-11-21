# Users and access

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
lore-auth grant bob my-game --read-only     # clone and get changes, nothing else
lore-auth grant lead my-game --push-protected   # write, and push to protected branches
lore-auth revoke alice my-game

lore-auth repo list
lore-auth apikey create ci-bot --label "build server"   # printed once
lore-auth apikey revoke ci-bot

lore-auth server add lore://lore.example.com:41344 --label "Game"   # clients find its repositories
lore-auth server list
lore-auth server remove lore://lore.example.com:41344
```

If you run a Lore server per project, list every server with `lore-auth server add`: after one sign-in, clients find the repositories of all of them (`GET /servers` in the admin API, available to every user).

Changes apply immediately: no token reissue is needed. A user who already has an access token for a repository keeps it until it expires (`access_token_ttl_minutes`, 60 by default).

Use `--password-stdin` with `user add` and `user passwd` to script account creation.

Administrators can also do all of this remotely, from a GUI client, through the [admin API](admin-api.md).

## Access rules

| Who | Access |
|---|---|
| Administrator | every repository, including delete, lock management and pushes to protected branches |
| User with a write grant for a repository, or the `*` grant | clone, pull, push, branches, locks |
| User with a read-only grant (`--read-only`) | clone and pull only: Lore refuses pushes, new branches, locks and metadata changes |
| User with a write grant and `--push-protected` | as a write grant, and pushes to protected branches |
| Creator of a repository | clone, pull, push on that repository |
| Anyone else | nothing; the repository is hidden from `lore repository list` |

`policy.repository_create` controls whether every signed-in user (`everyone`) or only administrators (`admins`) can create repositories. Only the creator or an administrator can delete a repository.

A grant is write access unless it is made with `--read-only` (Lore 0.13 and later tell the two apart). Grants made before access levels existed are write access. Running `grant` again for the same user and repository changes the access. A grant to one repository and the `*` grant add up: the wider access wins.

A protected branch takes pushes only from users with the `push-protected` right: administrators, and users granted `--push-protected` (which needs write access). Everyone else brings changes into it by merging. Only the repository's owner, an administrator or its creator can protect or unprotect a branch (Lore 0.13 and later).

## Using it as a Lore user

```bash
lore auth login lore://lore.example.com:41337      # opens the browser
lore clone lore://lore.example.com:41337/my-game
lore auth logout --auth-url https://lore.example.com:41342   # or run `lore auth logout` inside a repository
```

GUI clients show the same login page when they need a sign-in. Apps can also show their own user name and password form instead of the page; see [app-sign-in.md](app-sign-in.md).

The client can hold several sign-ins for one server, and keeps using the one it already has. To switch users, sign out first, then sign in again:

```bash
lore auth list                                               # stored sign-ins
lore auth logout --auth-url https://lore.example.com:41342   # removes all sign-ins for this server
lore auth login lore://lore.example.com:41337
```

`lore auth clear` removes the sign-ins for **every** server.

For CI, create an API key and sign in without a browser:

```bash
lore auth login lore://lore.example.com:41337 --token-type api-key --token "$LORE_API_KEY"
```
