# Installing on Windows

lore-auth-server runs on Windows next to a Windows loreserver. These steps were checked on Windows 11 with Python 3.11 and loreserver 0.14: a trusted certificate, the service started by a Task Scheduler task, loreserver connected to it, then signing in, creating a repository and pushing to it. Issuing the certificate itself is done with win-acme, following its own guide.

The layout used below:

```text
C:\loreserver\                 loreserver.exe, its config\local.toml and data
C:\lore-auth-server\venv\      the program
C:\lore-auth-server\tls\       the certificate
C:\lore-auth-server\data\      users, grants, keys (auth.db, signing-key.pem, jwks.json)
C:\lore-auth-server\config.toml
```

Type the commands in PowerShell. loreserver stays open until step 6.

## 1. Install Python and Git

Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/) (tick "Add python.exe to PATH" in the installer), and [Git for Windows](https://git-scm.com/download/win): `pip` fetches the program through it.

## 2. Install the package

```powershell
New-Item -ItemType Directory -Force C:\lore-auth-server\tls, C:\lore-auth-server\data
py -3 -m venv C:\lore-auth-server\venv
C:\lore-auth-server\venv\Scripts\pip install git+https://github.com/dy-sh/lore-auth-server.git
```

## 3. Get a TLS certificate

Clients need a certificate they trust for the server's name, for example `lore.example.com` (see [Requirements](../README.md#requirements)). On Windows the usual tool for a free Let's Encrypt certificate is [win-acme](https://www.win-acme.com/): when issuing, choose to store it as PEM files in `C:\lore-auth-server\tls`. win-acme renews it on its own schedule. You need the certificate with its chain and the private key.

## 4. Configure

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/dy-sh/lore-auth-server/main/config.example.toml -OutFile C:\lore-auth-server\config.toml
notepad C:\lore-auth-server\config.toml
```

Set `public_grpc_url`, `public_web_url` and `tokens.audience` to your server's name, `tls_cert` and `tls_key` to the certificate files from step 3, and `data_dir` to `C:/lore-auth-server/data`. Use forward slashes in paths.

## 5. Create the first administrator and run the service

```powershell
C:\lore-auth-server\venv\Scripts\lore-auth-server --config C:\lore-auth-server\config.toml user add admin --admin
```

A Task Scheduler task keeps the service running without a window. It starts when you sign in to Windows and does not need administrator rights to create:

```powershell
$action = New-ScheduledTaskAction -Execute C:\lore-auth-server\venv\Scripts\pythonw.exe -Argument "-m lore_auth_server --config C:\lore-auth-server\config.toml serve" -WorkingDirectory C:\lore-auth-server
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName lore-auth-server -Action $action -Trigger $trigger -Settings $settings
Start-ScheduledTask -TaskName lore-auth-server
```

If Windows asks whether Python may use the network, allow it. Check that it answers:

```powershell
Invoke-RestMethod https://lore.example.com:41343/.well-known/lore-admin
# protocol: lore-admin, version: 1, ...
```

To run it only while a server must answer without anyone signed in, open the task in Task Scheduler and choose "Run whether user is logged on or not" (this asks for the account's password).

## 6. Connect loreserver

Stop loreserver (close its window) and back up its settings:

```powershell
Copy-Item C:\loreserver\config\local.toml C:\loreserver\config\local.toml.before-auth
```

Give loreserver the same certificate: append this block to `C:\loreserver\config\local.toml` in Notepad, with your file names from step 3:

```toml
[server.quic.certificate]
cert_file = "C:/lore-auth-server/tls/lore.example.com-chain.pem"
pkey_file = "C:/lore-auth-server/tls/lore.example.com-key.pem"
```

Then append the auth settings and start loreserver again:

```powershell
C:\lore-auth-server\venv\Scripts\lore-auth-server --config C:\lore-auth-server\config.toml lore-config | Add-Content C:\loreserver\config\local.toml
C:\loreserver\loreserver.exe --config C:\loreserver\config
```

The printed `[server.auth.jwk]` endpoint is a `file://C:/…/jwks.json` address; loreserver reads it as is.

Behind NAT, loreserver must reach the service by its public name from inside: open Notepad as administrator and add `127.0.0.1 lore.example.com` to `C:\Windows\System32\drivers\etc\hosts`.

## 7. Open the ports

Clients must reach TCP 41342 and 41343 in addition to loreserver's 41337 (TCP and UDP). Allow them in Windows Firewall and, behind a router, forward them to this computer.

## 8. Verify

From a client machine:

```powershell
lore repository list lore://lore.example.com:41337     # [Error] Not authenticated
lore auth login lore://lore.example.com:41337          # sign in as admin
lore repository list lore://lore.example.com:41337     # lists the repositories
```

## Updates, backups and rollback

- Update: `C:\lore-auth-server\venv\Scripts\pip install --upgrade --force-reinstall git+https://github.com/dy-sh/lore-auth-server.git`, then `Stop-ScheduledTask lore-auth-server; Start-ScheduledTask lore-auth-server`.
- Back up `C:\lore-auth-server\data` (`auth.db` and `signing-key.pem` together) and keep the copy private.
- To make the server open again, stop loreserver, put `local.toml.before-auth` back in place of `local.toml` and start it.

## Next

- People and access: [users-and-access.md](users-and-access.md)
- Settings and security: [configuration.md](configuration.md)
- When something does not work: [troubleshooting.md](troubleshooting.md)
