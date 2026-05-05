# ldap-manager

Python CLI replacement for bash-based LDAP server management.

## Requirements

- Python 3.10+
- OpenLDAP client libraries (`libldap2-dev` / `openldap-devel`)
- OpenLDAP server tools on the LDAP host (for `slapcat`/`slapadd` backup/restore)

## Installation

```bash
# Install epel repo access
dnf install epel-release -y
# Install system deps (Rhel/Rocky)
dnf install python3-ldap python3-pyyaml python3-click openldap-clients openldap-servers python3-click python3-passlib -y

# Build time (needed to compile python-ldap from source if RPM version is too old)
dnf install openldap-devel python3-devel gcc -y

# Install the package
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

## Configuration

Copy `config.example.yaml` to one of:
- `/etc/ldap-manager/config.yaml` (system-wide)
- `~/.ldap-manager.yaml` (per-user)
- Any path passed via `--config`

Environment variables override config file values:
- `LDAP_URI`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_BASE_DN`

## Usage

### User operations

```bash
# List all users
ldap-manager user list
ldap-manager user list --enabled
ldap-manager user list --disabled
ldap-manager user list --json

# Get user details
ldap-manager user get jdoe

# Create a user
ldap-manager user create jdoe \
  --cn "John Doe" \
  --sn "Doe" \
  --given-name "John" \
  --mail "john@example.com" \
  --password

# Update attributes
ldap-manager user update jdoe --set mail=newemail@example.com --set loginShell=/bin/zsh

# Delete a user
ldap-manager user delete jdoe
ldap-manager user delete jdoe --yes  # skip confirmation

# Enable / disable
ldap-manager user disable jdoe   # shell -> /sbin/nologin
ldap-manager user enable jdoe    # shell -> /bin/bash

# Change password
ldap-manager user passwd jdoe
```

### Backup and restore

```bash
# Full dump (data + cn=config, gzipped)
ldap-manager backup dump
ldap-manager backup dump --tag pre-migration
ldap-manager backup dump --no-compress

# List backups
ldap-manager backup list

# Restore (slapd must be stopped first!)
sudo systemctl stop slapd
ldap-manager backup restore /var/backups/ldap/ldap_backup_20240101_120000
sudo systemctl start slapd

# Restore including cn=config (use with extreme caution)
ldap-manager backup restore /path/to/backup --with-config --yes
```

### Global password reset

```bash
# Reset all enabled users, output CSV with new passwords
ldap-manager passwd-all

# Dry run — generate CSV without modifying LDAP
ldap-manager passwd-all --dry-run

# Include disabled users
ldap-manager passwd-all --include-disabled

# Custom output path and password length
ldap-manager passwd-all --output /secure/passwords.csv --length 24
```

### Global options

```bash
# Use a specific config file
ldap-manager -c /path/to/config.yaml user list

# Verbose/debug logging
ldap-manager -v user list
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Tests use mocked LDAP connections — no live server needed.

## Project structure

```
ldap_manager/
├── __init__.py        # Package metadata
├── cli.py             # Click CLI commands
├── config.py          # YAML + env config loading
├── connection.py      # LDAP connection context manager
├── users.py           # User CRUD, enable/disable, password
├── passwords.py       # Bulk password generation + reset
└── backup.py          # slapcat/slapadd dump + restore
```

## Design decisions

- **slapcat/slapadd for backup**: Protocol-level export (ldapsearch) is lossy — it misses `cn=config`, overlays, ACLs, and operational attributes. `slapcat` captures everything.
- **loginShell for enable/disable**: Simpler and more portable than `shadowExpire` or `nsAccountLock`. Works everywhere, no special overlay needed.
- **SSHA passwords**: Most universally supported hash. If your server has `pw-argon2` overlay, change `hash_scheme` in config.
- **Connection as context manager**: Each CLI command opens/closes its own connection. No persistent connection pool — this is a CLI tool, not a web service.

Developed using claude code assistence and help 
