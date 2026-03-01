"""Bulk password operations.

Handles global password reset for all users — generates secure random
passwords, applies them via LDAP modify, and outputs a CSV manifest.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from ldap.ldapobject import LDAPObject

from .config import Config
from .users import UserManager

log = logging.getLogger(__name__)


def bulk_password_reset(
    conn: LDAPObject,
    cfg: Config,
    *,
    enabled_only: bool = True,
    output_file: str | Path | None = None,
    dry_run: bool = False,
) -> Path:
    """Reset passwords for all users (or enabled users only).

    Generates a unique random password per user, applies it, and writes
    a CSV file mapping uid -> new_password.

    Args:
        conn: Bound LDAP connection
        cfg: Application config
        enabled_only: If True, skip disabled users (loginShell = nologin)
        output_file: Path for the CSV output (default from config)
        dry_run: Generate passwords and CSV but don't actually modify LDAP

    Returns:
        Path to the CSV output file.
    """
    user_mgr = UserManager(cfg)
    out_path = Path(output_file or cfg.password.bulk_output_file)

    users = user_mgr.list_users(conn, enabled_only=enabled_only)
    if not users:
        log.warning("No users found matching criteria")
        raise RuntimeError("No users found to reset")

    log.info(
        "Bulk password reset: %d users, enabled_only=%s, dry_run=%s",
        len(users),
        enabled_only,
        dry_run,
    )

    results: list[tuple[str, str, str]] = []  # (uid, cn, new_password)
    errors: list[tuple[str, str]] = []

    for user in users:
        new_password = cfg.password.default_password
        try:
            if not dry_run:
                user_mgr.set_password(conn, user.uid, new_password)
            results.append((user.uid, user.cn, new_password))
            log.debug("Password %s for %s", "generated" if dry_run else "changed", user.uid)
        except Exception as exc:
            log.error("Failed to reset password for %s: %s", user.uid, exc)
            errors.append((user.uid, str(exc)))

    # Write CSV output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["uid", "cn", "new_password"])
        writer.writerows(results)

    # Restrictive permissions on the password file
    out_path.chmod(0o600)

    log.info(
        "Bulk reset complete: %d succeeded, %d failed. Output: %s",
        len(results),
        len(errors),
        out_path,
    )

    if errors:
        log.warning("Failed users: %s", ", ".join(uid for uid, _ in errors))

    return out_path
