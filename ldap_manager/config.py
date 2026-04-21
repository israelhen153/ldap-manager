"""Configuration loading with layered overrides.

Resolution order (last wins):
  1. config.example.yaml defaults (baked into code)
  2. /etc/ldap-manager/config.yaml
  3. ~/.ldap-manager.yaml
  4. --config CLI flag
  5. Environment variables (LDAP_URI, LDAP_BIND_DN, LDAP_BIND_PASSWORD, LDAP_BASE_DN)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_SYSTEM_CONFIG = Path("/etc/ldap-manager/config.yaml")
_USER_CONFIG = Path.home() / ".ldap-manager.yaml"

# ── Env var mapping ────────────────────────────────────────────────
_ENV_MAP: dict[str, tuple[str, ...]] = {
    "LDAP_URI": ("ldap", "uri"),
    "LDAP_BIND_DN": ("ldap", "bind_dn"),
    "LDAP_BIND_PASSWORD": ("ldap", "bind_password"),
    "LDAP_BASE_DN": ("ldap", "base_dn"),
    "LDAP_USERS_OU": ("ldap", "users_ou"),
    "LDAP_START_TLS": ("ldap", "start_tls"),
    "LDAP_TLS_CACERT": ("ldap", "tls_cacert"),
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* (mutates base)."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
    return base


def _set_nested(d: dict, keys: tuple[str, ...], value: Any) -> None:
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def _apply_env(cfg: dict) -> None:
    for env_var, key_path in _ENV_MAP.items():
        val: Any = os.environ.get(env_var)
        if val is not None:
            if val.lower() in ("true", "1", "yes"):
                val = True
            elif val.lower() in ("false", "0", "no"):
                val = False
            _set_nested(cfg, key_path, val)


@dataclass
class LDAPConfig:
    uri: str = "ldap://localhost:389"
    bind_dn: str = "cn=admin,dc=example,dc=com"
    bind_password: str = "changeme"
    base_dn: str = "dc=example,dc=com"
    users_ou: str = "ou=People,dc=example,dc=com"
    groups_ou: str = "ou=Groups,dc=example,dc=com"
    start_tls: bool = False
    tls_cacert: str = "/etc/ssl/certs/ca-certificates.crt"
    timeout: int = 10


@dataclass
class UsersConfig:
    default_shell: str = "/bin/bash"
    disabled_shell: str = "/sbin/nologin"
    home_prefix: str = "/home"
    uid_min: int = 10000
    uid_max: int = 60000
    default_gid: int = 10000
    object_classes: list[str] = field(default_factory=lambda: ["inetOrgPerson", "posixAccount", "shadowAccount"])
    # ── Creation defaults ──────────────────────────────────────────
    # Mail domain — if set, new users get uid@mail_domain automatically
    mail_domain: str = ""
    # Default password for new users (empty = no password set on create)
    default_password: str = "123456"
    # Auto-generate password on create (overrides default_password)
    generate_password_on_create: bool = False


@dataclass
class BackupConfig:
    backup_dir: str = "/var/backups/ldap"
    slapcat_bin: str = "/usr/sbin/slapcat"
    slapadd_bin: str = "/usr/sbin/slapadd"
    retention_count: int = 10


@dataclass
class PasswordConfig:
    hash_scheme: str = "{SSHA}"
    generated_length: int = 20
    bulk_output_file: str = "/tmp/ldap_passwords.csv"
    default_password: str = "123456"


@dataclass
class AuditConfig:
    """Audit logging configuration.

    ``sinks`` is a list of sink specs. Each entry is a dict with a
    ``type`` key (``file``, ``syslog``, ``http``, or ``stdout``) plus
    any sink-specific options (path, facility, url, headers…).

    If left empty (the default), :func:`ldap_manager.audit.build_sinks`
    falls back to a single ``FileSink`` at the historical default
    path, preserving backward compatibility for users who never opt
    in to the new config.
    """

    sinks: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Config:
    ldap: LDAPConfig = field(default_factory=LDAPConfig)
    users: UsersConfig = field(default_factory=UsersConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    password: PasswordConfig = field(default_factory=PasswordConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)


def load_config(config_path: str | Path | None = None) -> Config:
    """Load and merge configuration from all sources."""
    raw: dict[str, Any] = {}

    # Layer 1 & 2: system, then user config
    for path in (_SYSTEM_CONFIG, _USER_CONFIG):
        if path.is_file():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            _deep_merge(raw, data)

    # Layer 3: explicit --config path
    if config_path:
        p = Path(config_path)
        if not p.is_file():
            raise FileNotFoundError(f"Config file not found: {p}")
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        _deep_merge(raw, data)

    # Layer 4: environment variables (highest priority)
    _apply_env(raw)

    # Build typed config
    return Config(
        ldap=LDAPConfig(**raw.get("ldap", {})),
        users=UsersConfig(**raw.get("users", {})),
        backup=BackupConfig(**raw.get("backup", {})),
        password=PasswordConfig(**raw.get("password", {})),
        audit=AuditConfig(**raw.get("audit", {})),
    )
