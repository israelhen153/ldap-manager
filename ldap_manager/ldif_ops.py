"""LDIF export and import for user entries.

Produces RFC 2849 compliant LDIF that can be consumed by ldapadd/slapadd
or imported back through this tool.
"""

from __future__ import annotations

import base64
import logging
from io import StringIO
from pathlib import Path

import ldap
from ldap.ldapobject import LDAPObject

from .config import Config

log = logging.getLogger(__name__)


def export_ldif(
    conn: LDAPObject,
    cfg: Config,
    *,
    output: Path | None = None,
    enabled_only: bool = False,
    disabled_only: bool = False,
    scope: str = "users",
) -> str:
    """Export entries as LDIF.

    Args:
        conn: Bound LDAP connection
        cfg: Config object
        output: File path to write (None = return as string)
        enabled_only: Skip disabled users (users scope only)
        disabled_only: Skip enabled users (users scope only)
        scope: "users", "groups", or "all"

    Returns:
        LDIF string
    """
    disabled_shells = {"/sbin/nologin", "/bin/false", "/usr/sbin/nologin"}

    bases = []
    if scope in ("users", "all"):
        bases.append(cfg.ldap.users_ou)
    if scope in ("groups", "all"):
        bases.append(cfg.ldap.groups_ou)

    buf = StringIO()
    count = 0

    buf.write(f"# LDIF export from {cfg.ldap.uri}\n")
    buf.write(f"# Base DNs: {', '.join(bases)}\n")
    buf.write(f"# Scope: {scope}\n\n")

    for base_dn in bases:
        try:
            results = conn.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                "(objectClass=*)",
                None,  # all attrs
            )
        except ldap.NO_SUCH_OBJECT:
            continue

        for dn, attrs in results:
            if dn is None:
                continue

            # Apply enable/disable filter for user entries
            if enabled_only or disabled_only:
                shell_vals = attrs.get("loginShell", [])
                if shell_vals:
                    shell = shell_vals[0].decode("utf-8", errors="replace")
                    is_enabled = shell not in disabled_shells
                    if enabled_only and not is_enabled:
                        continue
                    if disabled_only and is_enabled:
                        continue

            _write_entry(buf, dn, attrs)
            count += 1

    ldif_str = buf.getvalue()

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(ldif_str, encoding="utf-8")
        log.info("Exported %d entries to %s", count, output)

    return ldif_str


def _write_entry(buf: StringIO, dn: str, attrs: dict[str, list[bytes]]) -> None:
    """Write a single LDAP entry as LDIF."""
    # DN — base64 encode if it contains non-ASCII
    try:
        dn.encode("ascii")
        buf.write(f"dn: {dn}\n")
    except UnicodeEncodeError:
        encoded = base64.b64encode(dn.encode("utf-8")).decode("ascii")
        buf.write(f"dn:: {encoded}\n")

    for attr_name, values in sorted(attrs.items()):
        for val in values:
            try:
                text = val.decode("utf-8")
                # Check if value needs base64 (contains control chars or starts with special chars)
                if _needs_base64(text):
                    encoded = base64.b64encode(val).decode("ascii")
                    buf.write(f"{attr_name}:: {encoded}\n")
                else:
                    buf.write(f"{attr_name}: {text}\n")
            except UnicodeDecodeError:
                # Binary value — always base64
                encoded = base64.b64encode(val).decode("ascii")
                buf.write(f"{attr_name}:: {encoded}\n")

    buf.write("\n")


def _needs_base64(text: str) -> bool:
    """Check if an LDIF value needs base64 encoding per RFC 2849."""
    if not text:
        return False
    # Starts with space, colon, or less-than
    if text[0] in (" ", ":", "<"):
        return True
    # Contains control characters or NUL
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        return True
    # Trailing space
    return True if text[-1] == " " else False



def import_ldif(
    conn: LDAPObject,
    ldif_path: Path,
    *,
    dry_run: bool = False,
    stop_on_error: bool = False,
) -> dict[str, int]:
    """Import entries from an LDIF file.

    Args:
        conn: Bound LDAP connection
        ldif_path: Path to LDIF file
        dry_run: Parse and validate but don't modify LDAP
        stop_on_error: Abort on first error

    Returns:
        Dict with counts: {"added": N, "errors": N, "skipped": N}
    """
    if not ldif_path.is_file():
        raise FileNotFoundError(f"LDIF file not found: {ldif_path}")

    entries = _parse_ldif(ldif_path)
    counts = {"added": 0, "errors": 0, "skipped": 0}

    for dn, attrs in entries:
        if dry_run:
            log.info("[DRY RUN] Would add: %s", dn)
            counts["added"] += 1
            continue

        try:
            add_list = [(attr, vals) for attr, vals in attrs.items()]
            conn.add_s(dn, add_list)
            counts["added"] += 1
            log.info("Added: %s", dn)
        except ldap.ALREADY_EXISTS:
            log.warning("Skipped (already exists): %s", dn)
            counts["skipped"] += 1
        except ldap.LDAPError as exc:
            log.error("Failed to add %s: %s", dn, exc)
            counts["errors"] += 1
            if stop_on_error:
                break

    return counts


def _parse_ldif(ldif_path: Path) -> list[tuple[str, dict[str, list[bytes]]]]:
    """Parse an LDIF file into (dn, attrs) tuples."""
    entries: list[tuple[str, dict[str, list[bytes]]]] = []
    current_dn: str | None = None
    current_attrs: dict[str, list[bytes]] = {}

    lines = ldif_path.read_text(encoding="utf-8").splitlines()

    # Handle line folding (continuation lines start with single space)
    unfolded: list[str] = []
    for line in lines:
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)

    for line in unfolded:
        line = line.rstrip()

        # Skip comments
        if line.startswith("#"):
            continue

        # Empty line = end of entry
        if not line:
            if current_dn is not None:
                entries.append((current_dn, current_attrs))
                current_dn = None
                current_attrs = {}
            continue

        # Parse attribute: value
        if "::" in line:
            # Base64 encoded
            attr, b64_val = line.split("::", 1)
            attr = attr.strip()
            val = base64.b64decode(b64_val.strip())
        elif ":" in line:
            attr, text_val = line.split(":", 1)
            attr = attr.strip()
            val = text_val.strip().encode("utf-8")
        else:
            continue

        if attr.lower() == "dn":
            current_dn = val.decode("utf-8")
        else:
            current_attrs.setdefault(attr, []).append(val)

    # Don't forget last entry
    if current_dn is not None:
        entries.append((current_dn, current_attrs))

    return entries
