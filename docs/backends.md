# Backends and capability compatibility

`ldap-manager` ships with two backends and three schema profiles. Which commands work depends on both, and on whether you can reach the LDAP host locally (some commands shell out to `slapcat`/`systemctl`).

## Backends

| Backend    | Library      | Protocol support | Use when |
|------------|--------------|------------------|----------|
| `openldap` | `python-ldap` | LDAPv3 + local OpenLDAP tooling | You run `ldap-manager` on the same host as `slapd` and want backup/restart commands. This is the default. |
| `generic`  | `ldap3`       | LDAPv3 only | You target a remote directory (OpenLDAP, AD, 389ds) and don't need the local-host commands. |

Switch via `backend:` in config or the `--backend openldap|generic` CLI override.

## Schema profiles (generic backend only)

The `generic` backend carries no assumptions about attribute names or schema; you pick a profile via `schema:` in config. Each profile sets the attribute/objectClass names and the set of capabilities the backend claims to support.

| Profile              | `user_id_attr`     | `user_object_class` | `disable_mechanism` | `group_membership_attr` |
|----------------------|--------------------|---------------------|---------------------|-------------------------|
| `openldap_posix`     | `uid`              | `inetOrgPerson`     | `login_shell`       | `memberUid`             |
| `active_directory`   | `sAMAccountName`   | `user`              | `uac_bit`           | `member`                |
| `389ds`              | `uid`              | `inetOrgPerson`     | `login_shell`       | `member`                |

No profile selected → `supports = frozenset()` (all gated commands refuse; unchanged from a totally unconfigured generic connection).

## Command × backend matrix

Legend: ✅ works · 🔒 gated (refuses with an informative error) · ⚠️ works but schema-dependent

| Command group                        | `openldap` | `generic` + `openldap_posix` | `generic` + `active_directory` | `generic` + `389ds` |
|--------------------------------------|:----------:|:----------------------------:|:------------------------------:|:-------------------:|
| `backup dump` / `restore` / `list`   | ✅         | 🔒                            | 🔒                              | 🔒                   |
| `server status` / `start` / `stop` / `restart` / `reindex` | ✅ | 🔒              | 🔒                              | 🔒                   |
| `ppolicy status` / `policy` / `check-all` | ✅    | ✅                            | 🔒                              | 🔒                   |
| `user ssh-key-list` / `-add` / `-remove` | ✅     | ✅                            | 🔒                              | 🔒                   |
| `user list` / `get` / `search` / `dump` | ✅      | ⚠️                            | ⚠️                              | ⚠️                   |
| `user create` / `update` / `delete` / `enable` / `disable` / `passwd` | ✅ | ⚠️ | ⚠️                              | ⚠️                   |
| `user export` / `import`             | ✅         | ⚠️                            | ⚠️                              | ⚠️                   |
| `group list` / `get` / `members` / `user-groups` | ✅ | ⚠️                    | ⚠️                              | ⚠️                   |
| `group create` / `delete` / `add` / `remove` | ✅ | ⚠️                       | ⚠️                              | ⚠️                   |
| `batch`                              | ✅         | ⚠️                            | ⚠️                              | ⚠️                   |
| `passwd-all`                         | ✅         | ⚠️                            | ⚠️                              | ⚠️                   |
| `tree show` / `list-ous` / `create-ou` / `delete-ou` | ✅ | ✅                     | ✅                              | ✅                   |
| `audit log` / `status`               | ✅         | ✅                            | ✅                              | ✅                   |

### What the symbols mean

- **🔒 gated** — the command checks `backend.supports` and refuses with a clean two-line error before touching LDAP or executing any subprocess. The error names the command, the missing capability, and the current backend. Example:
  ```
  Error: 'backup dump' requires capability 'backup' (needs slapcat on the LDAP host).
  Current backend: 'generic' does not provide this capability.
  ```
- **⚠️ works but schema-dependent** — the command will talk to LDAP, but the underlying module still hardcodes POSIX conventions (`posixAccount`, `uidNumber`, `loginShell`, `memberUid`) that don't translate cleanly to Active Directory. Against AD you'll see LDAP errors like "objectClass violation" or empty result sets. Against OpenLDAP POSIX or 389ds POSIX deployments these commands behave normally. Making user/group modules fully schema-aware is tracked as future work.

## Capabilities reference

Each backend publishes a `supports: frozenset[str]` — the markers callers gate on.

| Marker                   | Meaning                                                                                               | Published by                         |
|--------------------------|-------------------------------------------------------------------------------------------------------|--------------------------------------|
| `backup`                 | Can exec `slapcat`/`slapadd` on the LDAP host.                                                        | `OpenLDAPBackend`                    |
| `server_ops`             | Can exec `systemctl slapd` / read `/proc` on the LDAP host.                                           | `OpenLDAPBackend`                    |
| `ppolicy_overlay`        | Server has OpenLDAP's `ppolicy` overlay loaded (`pwdChangedTime`, `pwdAccountLockedTime`, etc.).      | `OpenLDAPBackend`, generic+`openldap_posix` |
| `cn_config_probe`        | `cn=config` is readable (for `olcPasswordHash` detection, etc.).                                      | `OpenLDAPBackend`, generic+`openldap_posix`, generic+`389ds` |
| `password_hash_client`   | Client computes `{SSHA}` / `{ARGON2}` / `{SSHA512}` and pushes pre-hashed `userPassword`.             | `OpenLDAPBackend`, generic+`openldap_posix`, generic+`389ds` |
| `ssh_public_key_schema`  | Server has the `openssh-lpk` schema (`ldapPublicKey` objectClass + `sshPublicKey` attribute).          | `OpenLDAPBackend`, generic+`openldap_posix` |
| `posix_accounts`         | POSIX account schema (`posixAccount`, `uidNumber`, `gidNumber`, `loginShell`).                         | `OpenLDAPBackend`, generic+`openldap_posix`, generic+`389ds` |

Active Directory's `supports` is currently empty: none of the OpenLDAP-specific markers translate cleanly. AD-specific markers (e.g. `uac_disable`, `ad_password_policy`) can be added without breaking the set.

## Choosing a backend

- **Default OpenLDAP install, local operations** → `backend: openldap`. Everything works.
- **Remote OpenLDAP / 389ds / managed LDAP** → `backend: generic` with the appropriate profile. Backup and server commands stay 🔒 (you'll run those separately on the LDAP host); everything else works.
- **Active Directory** → `backend: generic`, `schema: active_directory`. The command map is narrower; user-lifecycle commands may hit schema mismatches on write operations.
