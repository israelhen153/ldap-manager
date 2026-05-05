# ldap-manager

[![CI](https://github.com/israelhen153/ldap-manager/actions/workflows/makefile.yml/badge.svg)](https://github.com/israelhen153/ldap-manager/actions/workflows/makefile.yml)

[![asciicast](https://asciinema.org/a/cl9HR8vuYwlNrCe8.svg)](https://asciinema.org/a/cl9HR8vuYwlNrCe8)

**LDAP administration for OpenLDAP. Dry-run everything before production blows up. Fits into CI pipelines and cron jobs that web UIs can't reach.**

Manage users, groups, backups, SSH keys, password policies, and server operations — all from one command. JSON output on every command, `--dry-run` on every destructive operation, and a JSON-lines audit log of everything that ran.

```
pip install ldap-manager
ldap-manager user list --enabled --json
```

---

## Production use

ldap-manager runs on an OpenLDAP server managing 100+ users and 5 groups since mid-2025. It handles:

- Monthly `backup dump` via cron with rotation
- User management with per-user password policy (ppolicy) granularity
- Periodic `ppolicy check-all` to flag expired or locked accounts
- All operations logged via the JSON-lines audit trail

---

## How it fits

ldap-manager is a CLI-first tool. It complements — not replaces — web UIs for different workflows.

| Tool | What it does well | Where it falls short for automation |
| --- | --- | --- |
| `ldapmodify` / `ldapsearch` | Direct protocol access, universal | LDIF by hand for every operation, no dry-run, no structured output |
| phpLDAPadmin / [Luminary](https://github.com/wheelybird/luminary) | Visual browsing and editing | Browser-only, no scriptability, no CI integration |
| LDAP Account Manager (LAM) | Mature web UI (PHP, GPL), multi-backend | Designed for interactive use, not automation or pipelines |
| Shell scripts | Flexible, no dependencies | Fragile, no error handling, no dry-run, hard to maintain |

**ldap-manager** fills the gap: one tool, tab completion, JSON output, dry-run on destructive operations, audit logging, and actual tests.

### Good fit

- GitOps-style LDAP provisioning from CI/CD pipelines
- Scheduled batch operations (onboarding, offboarding, password rotation)
- Nightly backups with cron or systemd timers
- Audit trails for compliance

### Not a good fit

- End-user self-service password changes (use LAM or Luminary)
- Delegated helpdesk UI for non-technical staff
- Multi-backend environments (AD, 389-DS) — OpenLDAP only, for now

---

## Features

| Category | What you get |
| --- | --- |
| **Users** | Create, update, delete, enable/disable, search with filters, dump as JSON |
| **Groups** | Create, delete, add/remove members, list, supports posixGroup and groupOfNames |
| **Backup & Restore** | Full `slapcat`/`slapadd` dumps with gzip, metadata, and config backup |
| **Batch Operations** | Bulk create/update/delete from JSON/CSV/TSV with `--dry-run` |
| **Password Reset** | Reset all users at once, CSV output with new passwords |
| **SSH Keys** | Add, remove, list `ldapPublicKey` attributes per user |
| **Server Ops** | Status, start/stop/restart, reindex with `--auto` |
| **Password Policy** | View policy config, check user expiry/lockout status |
| **LDIF Export/Import** | Standards-compliant RFC 2849 export and import with dry-run |
| **Tree Management** | List/create/delete OUs, visualize your DIT |
| **Audit Logging** | JSON-lines audit trail of all operations |
| **JSON Output** | `--json` flag on 12+ commands for scripting and pipelines |



---

## Where ldap-manager runs

Some commands talk to LDAP over the network and work from any machine. Others shell out to host tools (`slapcat`, `systemctl`) and must run on the LDAP server itself.

| Runs from anywhere (network only) | Must run on the LDAP host |
| --- | --- |
| `user`, `group`, `batch`, `import`, `export` | `backup dump` / `restore` (requires `slapcat`/`slapadd`) |
| `ssh-key-*`, `tree`, `audit`, `passwd` | `server status/start/stop/restart/reindex` (requires `systemctl` + `slapd`) |
| `ppolicy status` / `check-all` | |

Set `LDAP_URI=ldap://localhost:389` when running on the host, or the remote server URI when running as a client. Host-only commands will fail with a clear error if the required tools aren't found on PATH.

---

## Quickstart

### Install

```
# Rocky/RHEL 8+
dnf install epel-release -y
dnf install python3-ldap python3-pyyaml python3-click python3-passlib \
            openldap-clients openldap-servers -y

pip install ldap-manager
```

### Configure

```
cp config.example.yaml /etc/ldap-manager/config.yaml
vim /etc/ldap-manager/config.yaml
```

Or use environment variables:

```
export LDAP_URI="ldap://localhost:389"
export LDAP_BIND_DN="cn=admin,dc=example,dc=com"
export LDAP_BIND_PASSWORD="secret"
export LDAP_BASE_DN="dc=example,dc=com"
```

### Go

```
ldap-manager user list
```

---

## Usage

### Users

```
ldap-manager user list --enabled --json
ldap-manager user get jdoe
ldap-manager user create jdoe --cn "John Doe" --mail john@example.com
ldap-manager user update jdoe --set mail=new@example.com --set loginShell=/bin/zsh
ldap-manager user delete jdoe --yes
ldap-manager user disable jdoe
ldap-manager user enable jdoe
ldap-manager user passwd jdoe

# Search with filters
ldap-manager user search --uid "j*"
ldap-manager user search --mail "*@engineering.com" --enabled
ldap-manager user search --filter "(description=contractor*)" --json
```

### Groups

```
ldap-manager group list
ldap-manager group create devops --gid 5000
ldap-manager group add-member devops jdoe
ldap-manager group remove-member devops jdoe
ldap-manager group members devops --json
ldap-manager group delete old_team --yes
```

### Backup & Restore

```
ldap-manager backup dump --tag pre-migration
ldap-manager backup list
ldap-manager backup restore /var/backups/ldap/ldap_backup_20240101_120000
ldap-manager backup restore /path/to/backup --with-config --yes
```

### Batch Operations

```
# Bulk create from CSV/JSON
ldap-manager batch create users.csv --dry-run
ldap-manager batch create users.json --yes

# Bulk delete
ldap-manager batch delete terminations.csv --dry-run
```

### Bulk Password Reset

```
ldap-manager passwd-all --dry-run
ldap-manager passwd-all --output /secure/passwords.csv --length 24
```

### SSH Keys

```
ldap-manager user ssh-key-list jdoe
ldap-manager user ssh-key-add jdoe ~/.ssh/id_ed25519.pub
ldap-manager user ssh-key-remove jdoe 1
```

### Server Operations

```
ldap-manager server status
ldap-manager server start
ldap-manager server stop
ldap-manager server restart
ldap-manager server reindex --auto    # stops slapd, reindexes, restarts
```

### Password Policy

```
ldap-manager ppolicy status jdoe      # expiry, lockout, grace logins
ldap-manager ppolicy policy           # view current policy config
ldap-manager ppolicy check-all        # find expired/locked accounts
```

### LDIF Export & Import

```
ldap-manager user export --format ldif --scope all -o backup.ldif
ldap-manager user export --format json --enabled -o active_users.json
ldap-manager import users.ldif --dry-run
```

### Tree Management

```
ldap-manager tree show                # visualize DIT
ldap-manager tree list-ous
ldap-manager tree create-ou "ou=Contractors,dc=example,dc=com"
ldap-manager tree delete-ou "ou=OldDept,dc=example,dc=com" --recursive
```

### Audit Log

```
ldap-manager audit log --since 2024-01-01
ldap-manager audit log --action create --target jdoe
ldap-manager audit status
```

### Global Options

```
ldap-manager -c /path/to/config.yaml user list    # custom config
ldap-manager -v user list                          # verbose logging
```

---

## Configuration

Config is loaded from (in order, later overrides earlier):

1. `/etc/ldap-manager/config.yaml` (system)
2. `~/.ldap-manager.yaml` (user)
3. `--config` flag (explicit)
4. Environment variables (highest priority)

See `config.example.yaml` for all options.

---

## Development

```
git clone https://github.com/israelhen153/ldap-manager.git
cd ldap-manager
make install    # creates venv, installs deps
make ci         # lint + typecheck + security + tests
```

Tests use mocked LDAP connections — no live server needed.

```
make lint         # ruff check + format
make typecheck    # mypy
make security     # bandit
make test         # pytest with coverage
make ci           # all of the above
```

---

## Project Structure

```
ldap_manager/
├── __init__.py       # Package metadata
├── cli.py            # Click CLI — 40+ commands
├── config.py         # YAML + env config loading
├── connection.py     # LDAP connection context manager
├── users.py          # User CRUD, enable/disable, search
├── groups.py         # Group management (posixGroup + groupOfNames)
├── passwords.py      # Bulk password generation + reset
├── backup.py         # slapcat/slapadd dump + restore
├── batch.py          # Bulk operations from CSV/JSON/TSV
├── server.py         # Server status, start/stop, reindex
├── sshkeys.py        # SSH public key management
├── ppolicy.py        # Password policy status + checks
├── ldif_ops.py       # RFC 2849 LDIF export/import
├── tree.py           # OU/DIT management + visualization
└── audit.py          # JSON-lines audit logging
```

---

## Design Decisions

* **`slapcat`/`slapadd` for backup** — protocol-level export (`ldapsearch`) is lossy. It misses `cn=config`, overlays, ACLs, and operational attributes. `slapcat` captures everything.
* **`loginShell` for enable/disable** — simpler and more portable than `shadowExpire` or `nsAccountLock`. No overlay needed.
* **SSHA passwords** — most universally supported LDAP hash. Change `hash_scheme` in config if your server has `pw-argon2`.
* **Dry-run on destructive ops** — batch, import, delete, and password reset all support `--dry-run`.
* **JSON output everywhere** — `--json` on 12+ commands for piping to `jq`, scripts, and monitoring.

---

## Requirements

* Python 3.10+
* OpenLDAP client libraries (`libldap2-dev` / `openldap-devel`)
* OpenLDAP server tools on the LDAP host (for backup/restore and server ops)

## License

MIT
