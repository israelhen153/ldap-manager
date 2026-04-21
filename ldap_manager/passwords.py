"""Bulk password operations.

Handles global password reset for all users — generates secure random
passwords, applies them via LDAP modify, and optionally writes a CSV
manifest to a caller-supplied path.

Writing plaintext passwords to disk is a liability: the caller must opt
in explicitly and the CLI gates that on ``--confirm-plaintext``. When no
``output_file`` is given, passwords are generated, applied, and immediately
dropped — the function returns only aggregate counts.
"""

from __future__ import annotations

import csv
import logging
import os
import secrets
import stat
import string
from dataclasses import dataclass, field
from pathlib import Path

from ldap.ldapobject import LDAPObject

from .config import Config
from .users import UserManager

log = logging.getLogger(__name__)


# Alphabet for generated passwords — ASCII letters + digits. Deliberately
# excludes punctuation: those bytes survive CSV/shell round-trips better and
# the entropy from length is cheaper than the compatibility cost of symbols.
_PASSWORD_ALPHABET = string.ascii_letters + string.digits


class InsecureOutputDirError(Exception):
    """Raised when the CSV output's parent directory is world-readable.

    Plaintext passwords landing inside a directory with ``o+r`` means any
    local account can read them the instant they exist, regardless of the
    file's own 0600. Refuse upfront rather than silently create the file.
    """


@dataclass
class BulkResetResult:
    """Outcome of a bulk_password_reset run.

    ``output_path`` is None when the caller asked for summary-only mode
    (no ``output_file``). ``rotated`` counts successful modify_s calls
    (or would-be modifies in dry-run). ``errors`` holds (uid, message)
    tuples for users that raised during set_password.
    """

    rotated: int
    errors: list[tuple[str, str]] = field(default_factory=list)
    output_path: Path | None = None


def _generate_password(length: int) -> str:
    """Generate a cryptographically random password of the given length."""
    if length < 1:
        raise ValueError(f"Password length must be >= 1, got {length}")
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def bulk_password_reset(
    conn: LDAPObject,
    cfg: Config,
    *,
    enabled_only: bool = True,
    output_file: str | Path | None = None,
    dry_run: bool = False,
    length: int | None = None,
) -> BulkResetResult:
    """Reset passwords for all users (or enabled users only).

    Generates a unique random password per user and applies it via LDAP
    modify. If ``output_file`` is provided, also writes a CSV manifest
    (uid, cn, new_password). If it is None, passwords are rotated and
    dropped — only the aggregate result is returned.

    Args:
        conn: Bound LDAP connection.
        cfg: Application config.
        enabled_only: If True, skip disabled users (loginShell = nologin).
        output_file: Path for the CSV output, or None for summary-only.
        dry_run: Generate passwords and CSV but don't actually modify LDAP.
        length: Generated password length. Defaults to
            ``cfg.password.generated_length`` when None.

    Returns:
        BulkResetResult with rotated count, errors, and output_path
        (None in summary-only mode).
    """
    user_mgr = UserManager(cfg)
    pw_length = length if length is not None else cfg.password.generated_length

    # If a file destination is requested, validate the parent directory
    # BEFORE touching LDAP — we don't want to rotate every user's password
    # just to then refuse to write the manifest to a world-readable dir.
    out_path: Path | None = None
    if output_file is not None:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        parent_mode = out_path.parent.stat().st_mode
        if parent_mode & stat.S_IROTH:
            raise InsecureOutputDirError(
                f"Refusing to write plaintext passwords into {out_path.parent}: "
                f"directory is world-readable (mode {oct(parent_mode & 0o777)}). "
                "Tighten permissions (e.g. chmod o-r) and retry."
            )

    users = user_mgr.list_users(conn, enabled_only=enabled_only)
    if not users:
        log.warning("No users found matching criteria")
        raise RuntimeError("No users found to reset")

    log.info(
        "Bulk password reset: %d users, enabled_only=%s, dry_run=%s, output=%s",
        len(users),
        enabled_only,
        dry_run,
        output_file or "<summary-only>",
    )

    results: list[tuple[str, str, str]] = []  # (uid, cn, new_password)
    errors: list[tuple[str, str]] = []

    for user in users:
        new_password = _generate_password(pw_length)
        try:
            if not dry_run:
                user_mgr.set_password(conn, user.uid, new_password)
            results.append((user.uid, user.cn, new_password))
            log.debug("Password %s for %s", "generated" if dry_run else "changed", user.uid)
        except Exception as exc:
            log.error("Failed to reset password for %s: %s", user.uid, exc)
            errors.append((user.uid, str(exc)))

    if out_path is not None:
        # Create the file with 0600 BEFORE any password bytes land in it.
        # os.open with explicit mode avoids a window where the file exists
        # with the umask-derived mode while we're writing rows.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(out_path, flags, 0o600)
        # chmod explicitly too — umask masks the O_CREAT mode, and if the
        # file already existed O_CREAT is a no-op for mode.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["uid", "cn", "new_password"])
            writer.writerows(results)

    log.info(
        "Bulk reset complete: %d succeeded, %d failed. Output: %s",
        len(results),
        len(errors),
        out_path if out_path else "<summary-only>",
    )

    if errors:
        log.warning("Failed users: %s", ", ".join(uid for uid, _ in errors))

    return BulkResetResult(rotated=len(results), errors=errors, output_path=out_path)
