"""Batch operations for bulk user management.

Simple model: one action applied to a file of usernames.

    ldap-manager batch disable /path/to/users.txt
    ldap-manager batch enable /path/to/users.txt
    ldap-manager batch delete /path/to/users.txt

The user file is plain text, one uid per line. Blank lines and lines
starting with # are ignored.

For create/update which need additional data per user, use a JSON or CSV
file — the format is auto-detected by extension.

    ldap-manager batch create new_hires.json
    ldap-manager batch update changes.csv
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ldap.ldapobject import LDAPObject

from .config import Config
from .users import UserManager

log = logging.getLogger(__name__)

VALID_ACTIONS = {"create", "update", "delete", "enable", "disable"}


@dataclass
class BatchResult:
    """Outcome of a batch run."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    errors: list[dict[str, str]] = field(default_factory=list)

    def record_success(self, uid: str) -> None:
        self.total += 1
        self.succeeded += 1

    def record_failure(self, uid: str, error: str) -> None:
        self.total += 1
        self.failed += 1
        self.errors.append({"uid": uid, "error": error})

    def record_skip(self, uid: str, reason: str) -> None:
        self.total += 1
        self.skipped += 1
        log.info("Skipped %s: %s", uid, reason)

    def summary(self) -> str:
        lines = [f"Total: {self.total}  Succeeded: {self.succeeded}  Failed: {self.failed}  Skipped: {self.skipped}"]
        if self.errors:
            lines.append("Errors:")
            for e in self.errors:
                lines.append(f"  {e['uid']}: {e['error']}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "skipped": self.skipped,
            "errors": self.errors,
        }


def load_uid_list(path: str | Path) -> list[str]:
    """Load a plain text file of usernames, one per line.

    Ignores blank lines and comments (lines starting with #).
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    uids = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        uids.append(line)
    return uids


def load_structured_file(path: str | Path) -> list[dict[str, Any]]:
    """Load a JSON or CSV file with per-user data (for create/update).

    JSON: array of objects, each with at least "uid".
    CSV:  header row with "uid" column required.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    suffix = path.suffix.lower()

    if suffix == ".json":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and "users" in data:
            data = data["users"]
        if not isinstance(data, list):
            raise ValueError('JSON must be an array or {"users": [...]}')
        return data

    elif suffix in (".csv", ".tsv"):
        delimiter = "\t" if suffix == ".tsv" else ","
        with open(path, encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f, delimiter=delimiter)]

    else:
        raise ValueError(f"Unsupported format: {suffix}. Use .json or .csv for create/update")


def run_batch(
    conn: LDAPObject,
    cfg: Config,
    action: str,
    file_path: str | Path,
    *,
    dry_run: bool = False,
    stop_on_error: bool = False,
) -> BatchResult:
    """Execute a batch action against a file of users.

    For enable/disable/delete: file is a plain text uid list (.txt or any
    extension not .json/.csv/.tsv).

    For create/update: file must be .json or .csv with per-user attributes.

    Args:
        conn: Bound LDAP connection
        cfg: Application config
        action: One of: create, update, delete, enable, disable
        file_path: Path to the input file
        dry_run: Log but don't modify LDAP
        stop_on_error: Abort on first failure

    Returns:
        BatchResult with counts and error details
    """
    action = action.lower().strip()
    if action not in VALID_ACTIONS:
        raise ValueError(f"Invalid action: {action}. Must be one of: {VALID_ACTIONS}")

    mgr = UserManager(cfg)
    result = BatchResult()
    file_path = Path(file_path)

    if action in ("create", "update"):
        entries = load_structured_file(file_path)
        for entry in entries:
            uid = entry.get("uid", "").strip()
            if not uid:
                result.record_failure("(missing)", "no uid in entry")
                if stop_on_error:
                    break
                continue
            _run_one(mgr, conn, action, uid, result, dry_run, data=entry)
            if stop_on_error and result.failed:
                break
    else:
        uids = load_uid_list(file_path)
        for uid in uids:
            _run_one(mgr, conn, action, uid, result, dry_run)
            if stop_on_error and result.failed:
                break

    return result


def _run_one(
    mgr: UserManager,
    conn: LDAPObject,
    action: str,
    uid: str,
    result: BatchResult,
    dry_run: bool,
    data: dict[str, Any] | None = None,
) -> None:
    """Execute a single operation within a batch."""
    prefix = "[DRY RUN] " if dry_run else ""
    log.info("%s%s: %s", prefix, action.upper(), uid)

    if dry_run:
        result.record_success(uid)
        return

    try:
        if action == "create":
            assert data is not None
            _, generated_pw = mgr.create_user(
                conn,
                uid,
                cn=data.get("cn"),
                sn=data.get("sn"),
                given_name=data.get("given_name", ""),
                mail=data.get("mail", ""),
                uid_number=_int_or_none(data.get("uid_number")),
                gid_number=_int_or_none(data.get("gid_number")),
                home_directory=data.get("home_directory"),
                login_shell=data.get("login_shell"),
                explicit_password=data.get("password"),
            )
            if generated_pw:
                log.info("Generated password for %s: %s", uid, generated_pw)
        elif action == "update":
            assert data is not None
            attrs = data.get("attrs", {})
            if not attrs:
                skip = {"uid", "attrs"}
                attrs = {k: v for k, v in data.items() if k not in skip and v}
            if not attrs:
                result.record_skip(uid, "no attributes to change")
                return
            mgr.update_user(conn, uid, **attrs)
        elif action == "delete":
            mgr.delete_user(conn, uid)
        elif action == "enable":
            mgr.enable_user(conn, uid)
        elif action == "disable":
            mgr.disable_user(conn, uid)

        result.record_success(uid)

    except Exception as exc:
        log.error("Failed %s on %s: %s", action, uid, exc)
        result.record_failure(uid, str(exc))


def _int_or_none(val: Any) -> int | None:
    if val is None or val == "":
        return None
    return int(val)
