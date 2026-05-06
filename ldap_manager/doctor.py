"""System diagnostic and auto-fix for ldap-manager.

    ldap-manager doctor          # diagnose only
    ldap-manager doctor --fix    # fix what's safe, skip what isn't

Safe auto-fixes (``--fix``):
  * Create missing directories (backup, audit log)
  * Fix config file permissions (``chmod 600``)
  * Create missing standard OUs (People, Groups)

Never auto-fixed:
  * Schema / overlay loading — requires manual server configuration
  * User data (locked accounts, expired passwords) — policy decisions
  * Server process management — too risky to automate
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

try:
    import ldap

    _LDAP = True
except ImportError:
    _LDAP = False

log = logging.getLogger(__name__)


@dataclass
class Check:
    """Result of a single diagnostic check."""

    name: str
    passed: bool
    detail: str = ""
    fixable: bool = False
    fix_fn: Any = None  # callable or None
    fix_hint: str = ""


# ── Individual checks ────────────────────────────────────────────────


def _check_connection(cfg: Any) -> Check:
    uri = cfg.ldap.uri
    try:
        conn = ldap.initialize(uri)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
        conn.simple_bind_s(cfg.ldap.bind_dn, cfg.ldap.bind_password)
        conn.unbind_s()
        return Check(f"Connection to {uri}", True)
    except ldap.INVALID_CREDENTIALS:
        return Check(f"Bind to {uri}", False, detail="Invalid credentials", fix_hint="Check bind_dn / bind_password in config.")
    except ldap.SERVER_DOWN:
        return Check(f"Connection to {uri}", False, detail="Server unreachable", fix_hint="Is slapd running? Check LDAP_URI.")
    except Exception as e:
        return Check(f"Connection to {uri}", False, detail=str(e))


def _check_base_dn(conn: Any, base_dn: str) -> Check:
    try:
        conn.search_s(base_dn, ldap.SCOPE_BASE, "(objectClass=*)")
        return Check(f"Base DN {base_dn}", True)
    except ldap.NO_SUCH_OBJECT:
        return Check(
            f"Base DN {base_dn}",
            False,
            detail="Not found in directory",
            fix_hint="Verify base_dn in config matches your DIT root.",
        )


def _check_ou(conn: Any, ou_name: str, base_dn: str) -> Check:
    ou_dn = f"ou={ou_name},{base_dn}"
    try:
        conn.search_s(ou_dn, ldap.SCOPE_BASE, "(objectClass=*)")
        return Check(f"ou={ou_name}", True)
    except ldap.NO_SUCH_OBJECT:

        def _fix(c: Any = conn, d: str = ou_dn, n: str = ou_name) -> None:
            attrs = [
                ("objectClass", [b"organizationalUnit", b"top"]),
                ("ou", [n.encode()]),
            ]
            c.add_s(d, attrs)

        return Check(f"ou={ou_name}", False, fixable=True, fix_fn=_fix, fix_hint=f"Create: ldap-manager tree create-ou {ou_name}")


def _check_schema_attr(conn: Any, attr_name: str, label: str) -> Check:
    try:
        res = conn.search_s("cn=subschema", ldap.SCOPE_BASE, "(objectClass=*)", ["attributeTypes"])
        blob = str(res).lower()
        if attr_name.lower() in blob:
            return Check(f"{label} schema loaded", True)
        return Check(f"{label} schema loaded", False, fix_hint=f"Load the {label} LDIF into cn=config.")
    except Exception:
        return Check(f"{label} schema", False, detail="Could not query schema", fix_hint=f"Load the {label} LDIF into cn=config.")


def _check_overlay(conn: Any, name: str) -> Check:
    try:
        res = conn.search_s("cn=config", ldap.SCOPE_SUBTREE, f"(olcOverlay={name})")
        if res:
            return Check(f"{name} overlay", True)
        return Check(f"{name} overlay", False, fix_hint=f"Load {name} overlay in cn=config.")
    except ldap.INSUFFICIENT_ACCESS:
        return Check(f"{name} overlay", False, detail="Cannot read cn=config (need root DN)")
    except Exception as e:
        return Check(f"{name} overlay", False, detail=str(e))


def _check_directory(path: str, label: str) -> Check:
    target = Path(path)
    if target.is_dir():
        if os.access(path, os.W_OK):
            return Check(f"{label} ({path})", True)

        def _fix_perms(_t: Path = target) -> None:
            _t.chmod(0o700)

        return Check(
            f"{label} ({path})", False, detail="Not writable", fixable=True, fix_fn=_fix_perms, fix_hint=f"chmod 700 {path}"
        )

    def _fix_mkdir(_t: Path = target) -> None:
        _t.mkdir(parents=True, mode=0o700, exist_ok=True)

    return Check(
        f"{label} ({path})", False, detail="Does not exist", fixable=True, fix_fn=_fix_mkdir, fix_hint=f"mkdir -p {path}"
    )


def _check_config_perms(path: str) -> Check:
    target = Path(path)
    if not target.exists():
        return Check("Config file", False, detail=f"{path} not found")
    mode = oct(target.stat().st_mode)[-3:]
    if mode in ("600", "400"):
        return Check(f"Config permissions ({path})", True)

    def _fix(_t: Path = target) -> None:
        _t.chmod(0o600)

    return Check(
        f"Config permissions ({path})",
        False,
        detail=f"mode {mode}, should be 600",
        fixable=True,
        fix_fn=_fix,
        fix_hint=f"chmod 600 {path}",
    )


def _check_slapd() -> Check:
    try:
        r = subprocess.run(["systemctl", "is-active", "slapd"], capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == "active":
            pr = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True, text=True, timeout=5)
            pid = pr.stdout.strip().split("\n")[0] if pr.stdout.strip() else "?"
            return Check(f"slapd running (pid {pid})", True)
        return Check("slapd running", False, detail=f"status: {r.stdout.strip()}", fix_hint="systemctl start slapd")
    except FileNotFoundError:
        return Check("slapd running", False, detail="systemctl not found (not on LDAP host?)")
    except Exception as e:
        return Check("slapd running", False, detail=str(e))


def _check_locked(conn: Any, base_dn: str) -> Check:
    try:
        res = conn.search_s(f"ou=People,{base_dn}", ldap.SCOPE_ONELEVEL, "(pwdAccountLockedTime=*)", ["uid"])
        if not res:
            return Check("No locked accounts", True)
        uids = []
        for dn, attrs in res:
            if dn and "uid" in attrs:
                uids.append(attrs["uid"][0].decode())
        n = len(uids)
        sample = ", ".join(uids[:5])
        extra = f" (+{n - 5} more)" if n > 5 else ""
        return Check(
            f"{n} locked account(s)", False, detail=f"{sample}{extra}", fix_hint="Review: ldap-manager ppolicy check-all"
        )
    except ldap.NO_SUCH_OBJECT:
        return Check("Locked accounts", True, detail="ou=People not found, skipped")
    except ldap.UNDEFINED_TYPE:
        return Check("Locked accounts", True, detail="ppolicy not active, skipped")
    except Exception as e:
        return Check("Locked accounts", False, detail=str(e))


# ── Main runner ──────────────────────────────────────────────────────


def run_doctor(cfg: Any, config_path: str | None = None, *, do_fix: bool = False) -> int:
    """Run all diagnostic checks.  Returns 0 if all pass, 1 otherwise."""
    checks: list[Check] = []
    conn = None

    # ── Connection ──
    c = _check_connection(cfg)
    checks.append(c)
    if c.passed:
        try:
            conn = ldap.initialize(cfg.ldap.uri)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
            conn.simple_bind_s(cfg.ldap.bind_dn, cfg.ldap.bind_password)
        except Exception:
            conn = None

    base = cfg.ldap.base_dn

    # ── DIT structure ──
    if conn:
        checks.append(_check_base_dn(conn, base))
        checks.append(_check_ou(conn, "People", base))
        checks.append(_check_ou(conn, "Groups", base))

    # ── Schemas / overlays ──
    if conn:
        checks.append(_check_schema_attr(conn, "sshPublicKey", "openssh-lpk"))
        checks.append(_check_overlay(conn, "ppolicy"))
        checks.append(_check_overlay(conn, "argon2"))

    # ── Accounts ──
    if conn:
        checks.append(_check_locked(conn, base))

    # ── Server ──
    checks.append(_check_slapd())

    # ── Filesystem ──
    checks.append(_check_directory(cfg.backup.backup_dir, "Backup directory"))

    # ── Config ──
    if config_path and Path(config_path).exists():
        checks.append(_check_config_perms(config_path))

    if cfg.users.generate_password_on_create:
        checks.append(Check("Config: generate_password_on_create", True))
    else:
        checks.append(
            Check(
                "Config: generate_password_on_create",
                False,
                detail="Using default_password instead of random generation",
                fix_hint="Set generate_password_on_create: true in config",
            )
        )

    # ── Output ──
    fixed = 0
    needs_attention = 0
    ok = 0

    for c in checks:
        if c.passed:
            click.echo(click.style("  ✓ ", fg="green") + c.name)
            ok += 1
        else:
            click.echo(click.style("  ✗ ", fg="red") + c.name)
            if c.detail:
                click.echo(f"    {c.detail}")
            if do_fix and c.fixable and c.fix_fn:
                try:
                    c.fix_fn()
                    click.echo(click.style("    → Fixed", fg="green"))
                    fixed += 1
                except Exception as e:
                    click.echo(click.style(f"    → Fix failed: {e}", fg="red"))
                    needs_attention += 1
            elif c.fixable and not do_fix:
                click.echo("    → Fixable with --fix")
                needs_attention += 1
            else:
                if c.fix_hint:
                    click.echo(f"    → {c.fix_hint}")
                needs_attention += 1

    # ── Summary ──
    click.echo("")
    parts = [click.style(f"OK: {ok}", fg="green")]
    if fixed:
        parts.append(click.style(f"Fixed: {fixed}", fg="green"))
    if needs_attention:
        parts.append(click.style(f"Needs attention: {needs_attention}", fg="red"))
    click.echo("  ".join(parts))

    if conn:
        try:
            conn.unbind_s()
        except Exception:
            pass

    return 0 if needs_attention == 0 else 1
