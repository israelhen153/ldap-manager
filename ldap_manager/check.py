"""Configuration and connectivity checks.

Validates config file, LDAP connectivity, bind credentials,
and directory structure in a single pass.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import ldap

from .config import Config, LDAPConfig

log = logging.getLogger(__name__)


@dataclass
class CheckResult:
    """Result of a single check."""

    name: str
    detail: str
    passed: bool
    skipped: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "detail": self.detail,
            "passed": self.passed,
        }
        if self.skipped:
            d["skipped"] = True
        if self.error:
            d["error"] = self.error
        return d


def run_all_checks(
    cfg: Config,
    config_path: str | None = None,
) -> list[CheckResult]:
    """Run all config and connectivity checks.

    Returns a list of CheckResult objects. Checks that depend on
    a failed earlier check are skipped automatically.
    """
    results: list[CheckResult] = []

    # 1. Config file
    results.append(_check_config_file(config_path))

    # 2. LDAP URI reachable
    uri_result = _check_uri_reachable(cfg.ldap)
    results.append(uri_result)

    # 3. Bind credentials
    if not uri_result.passed:
        results.append(
            CheckResult(
                name="Bind DN",
                detail=cfg.ldap.bind_dn,
                passed=False,
                skipped=True,
                error="Skipped — LDAP URI not reachable",
            )
        )
        bind_ok = False
    else:
        bind_result = _check_bind(cfg.ldap)
        results.append(bind_result)
        bind_ok = bind_result.passed

    # 4-6 depend on successful bind
    if not bind_ok:
        skip_msg = "Skipped — bind failed"
        for name, detail in [
            ("Base DN", cfg.ldap.base_dn),
            ("Users OU", cfg.ldap.users_ou),
            ("Groups OU", cfg.ldap.groups_ou),
        ]:
            results.append(
                CheckResult(
                    name=name,
                    detail=detail,
                    passed=False,
                    skipped=True,
                    error=skip_msg,
                )
            )
    else:
        # 4. Base DN exists
        results.append(_check_dn_exists(cfg.ldap, "Base DN", cfg.ldap.base_dn))

        # 5. Users OU exists
        results.append(_check_dn_exists(cfg.ldap, "Users OU", cfg.ldap.users_ou))

        # 6. Groups OU exists
        results.append(_check_dn_exists(cfg.ldap, "Groups OU", cfg.ldap.groups_ou))

    return results


def _check_config_file(config_path: str | None) -> CheckResult:
    """Check that a config file was found and parsed."""
    search_paths = []
    if config_path:
        search_paths.append(Path(config_path))
    else:
        search_paths.append(Path("/etc/ldap-manager/config.yaml"))
        search_paths.append(Path.home() / ".ldap-manager.yaml")

    found = [p for p in search_paths if p.is_file()]

    if found:
        return CheckResult(
            name="Config file",
            detail=str(found[0]),
            passed=True,
        )

    # Config still works with defaults + env vars
    return CheckResult(
        name="Config file",
        detail="No config file found (using defaults + env vars)",
        passed=True,
    )


def _check_uri_reachable(lcfg: LDAPConfig) -> CheckResult:
    """TCP connect to the LDAP host and port."""
    parsed = urlparse(lcfg.uri)
    host = parsed.hostname or "localhost"

    if parsed.scheme == "ldaps":
        default_port = 636
    else:
        default_port = 389

    port = parsed.port or default_port

    try:
        sock = socket.create_connection((host, port), timeout=lcfg.timeout)
        sock.close()
        return CheckResult(
            name="LDAP URI",
            detail=lcfg.uri,
            passed=True,
        )
    except (TimeoutError, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return CheckResult(
            name="LDAP URI",
            detail=lcfg.uri,
            passed=False,
            error=_friendly_connect_error(exc, host, port),
        )


def _check_bind(lcfg: LDAPConfig) -> CheckResult:
    """Attempt an LDAP bind with configured credentials."""
    try:
        conn = ldap.initialize(lcfg.uri)
        conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, lcfg.timeout)
        conn.set_option(ldap.OPT_REFERRALS, 0)

        if lcfg.start_tls and lcfg.uri.startswith("ldap://"):
            conn.start_tls_s()

        conn.simple_bind_s(lcfg.bind_dn, lcfg.bind_password)
        conn.unbind_s()

        return CheckResult(
            name="Bind DN",
            detail=lcfg.bind_dn,
            passed=True,
        )
    except ldap.INVALID_CREDENTIALS:
        return CheckResult(
            name="Bind DN",
            detail=lcfg.bind_dn,
            passed=False,
            error="Invalid credentials. Check bind_dn and bind_password in config.",
        )
    except ldap.SERVER_DOWN:
        return CheckResult(
            name="Bind DN",
            detail=lcfg.bind_dn,
            passed=False,
            error="Server down or unreachable during bind.",
        )
    except ldap.LDAPError as exc:
        msg = exc.args[0].get("desc", str(exc)) if exc.args else str(exc)
        return CheckResult(
            name="Bind DN",
            detail=lcfg.bind_dn,
            passed=False,
            error=f"LDAP error: {msg}",
        )


def _check_dn_exists(lcfg: LDAPConfig, name: str, dn: str) -> CheckResult:
    """Verify a DN exists and is readable."""
    try:
        conn = ldap.initialize(lcfg.uri)
        conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, lcfg.timeout)
        conn.set_option(ldap.OPT_REFERRALS, 0)

        if lcfg.start_tls and lcfg.uri.startswith("ldap://"):
            conn.start_tls_s()

        conn.simple_bind_s(lcfg.bind_dn, lcfg.bind_password)

        results = conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["dn"])
        conn.unbind_s()

        if results and results[0][0] is not None:
            return CheckResult(name=name, detail=dn, passed=True)

        return CheckResult(
            name=name,
            detail=dn,
            passed=False,
            error="DN exists but returned no data.",
        )

    except ldap.NO_SUCH_OBJECT:
        return CheckResult(
            name=name,
            detail=dn,
            passed=False,
            error="DN not found. Create it or update config.",
        )
    except ldap.INSUFFICIENT_ACCESS:
        return CheckResult(
            name=name,
            detail=dn,
            passed=False,
            error="Permission denied. Bind DN lacks read access to this entry.",
        )
    except ldap.LDAPError as exc:
        msg = exc.args[0].get("desc", str(exc)) if exc.args else str(exc)
        return CheckResult(
            name=name,
            detail=dn,
            passed=False,
            error=f"LDAP error: {msg}",
        )


def _friendly_connect_error(exc: Exception, host: str, port: int) -> str:
    """Turn socket errors into actionable messages."""
    if isinstance(exc, socket.timeout):
        return f"Connection to {host}:{port} timed out. Check host, port, and firewall rules."
    if isinstance(exc, socket.gaierror):
        return f"Cannot resolve hostname '{host}'. Check LDAP URI in config."
    if isinstance(exc, ConnectionRefusedError):
        return f"Connection refused on {host}:{port}. Is slapd running?"
    return f"Cannot connect to {host}:{port}: {exc}"
