# Running on Windows

lore-auth-server is a Python program and runs on Windows too. Checked on Windows 11 with Python 3.11 and loreserver 0.14, both on one computer, over loopback: installing into a virtual environment, `serve`, the `lore-config` output read by loreserver (it prints a `file://C:/…/jwks.json` address), signing in, creating and pushing a repository, and access per user (`grant`).

Not checked on Windows yet: a TLS certificate for remote clients and starting the service with the computer. Until then, [installing on Linux](install-linux.md) is the tested way for a team.

## Install

In PowerShell:

```powershell
py -3 -m venv C:\lore-auth-server\venv
C:\lore-auth-server\venv\Scripts\pip install git+https://github.com/dy-sh/lore-auth-server.git
```

Git must be installed for `pip` to fetch from GitHub.

## Configure and run

Write `config.toml` as on Linux ([configuration](configuration.md)), with Windows paths for `data_dir` and the certificate, then:

```powershell
C:\lore-auth-server\venv\Scripts\lore-auth-server --config C:\lore-auth-server\config.toml user add admin --admin
C:\lore-auth-server\venv\Scripts\lore-auth-server --config C:\lore-auth-server\config.toml serve
```

Connect loreserver the same way as on Linux: append the output of `lore-auth-server … lore-config` to its `local.toml` and restart it.

## What differs from Linux

- **The certificate.** Clients need one they trust for the server's name, as on Linux. certbot is awkward on Windows; [win-acme](https://www.win-acme.com/) is the usual tool. Point `tls_cert` and `tls_key` at the files it writes, and give loreserver the same certificate.
- **Starting with the computer.** There is no systemd: use Task Scheduler (a task at startup that runs the `serve` command) or a Windows service wrapper.
- **Behind a router.** Instead of `/etc/hosts`, add the server's name to `C:\Windows\System32\drivers\etc\hosts`, pointing at the computer's own address.
