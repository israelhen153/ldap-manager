"""Structured audit logging for LDAP operations.

Writes a JSON-lines audit log of every modification operation.
Each line is a self-contained JSON object with timestamp, action,
target, operator, and details.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Default audit log location
DEFAULT_AUDIT_LOG = "/var/log/ldap-manager/audit.jsonl"


class AuditLogger:
    """Append-only JSON-lines audit logger."""

    def __init__(self, log_path: str | Path | None = None) -> None:
        if log_path is None:
            log_path = os.environ.get("LDAP_MANAGER_AUDIT_LOG", DEFAULT_AUDIT_LOG)
        self._path = Path(log_path)
        self._enabled = True

        # Try to create the log directory and file
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Touch the file to verify we can write
            if not self._path.exists():
                self._path.touch(mode=0o640)
        except PermissionError:
            log.warning(
                "Cannot write audit log to %s — audit logging disabled. "
                "Create the directory or set LDAP_MANAGER_AUDIT_LOG env var.",
                self._path,
            )
            self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def path(self) -> Path:
        return self._path

    def log(
        self,
        action: str,
        target: str,
        *,
        operator: str = "",
        details: dict[str, Any] | None = None,
        success: bool = True,
        error: str = "",
    ) -> None:
        """Write an audit log entry.

        Args:
            action: Operation performed (e.g. "user.create", "group.add_member")
            target: DN or identifier of the target (e.g. "uid=jdoe,ou=People,...")
            operator: Who performed the action (bind DN, defaults to config bind_dn)
            details: Additional structured data about the operation
            success: Whether the operation succeeded
            error: Error message if failed
        """
        if not self._enabled:
            return

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "operator": operator,
            "success": success,
            "hostname": os.uname().nodename,
        }

        if details:
            entry["details"] = details
        if error:
            entry["error"] = error

        try:
            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except (OSError, PermissionError) as exc:
            log.warning("Failed to write audit log: %s", exc)

    def query(
        self,
        *,
        action: str | None = None,
        target: str | None = None,
        since: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query the audit log.

        Args:
            action: Filter by action prefix (e.g. "user" matches "user.create")
            target: Filter by target substring
            since: ISO timestamp — only entries after this time
            limit: Max entries to return (newest first)

        Returns:
            List of audit log entries, newest first.
        """
        if not self._path.is_file():
            return []

        entries: list[dict[str, Any]] = []
        try:
            with open(self._path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if action and not entry.get("action", "").startswith(action):
                        continue
                    if target and target not in entry.get("target", ""):
                        continue
                    if since and entry.get("timestamp", "") < since:
                        continue

                    entries.append(entry)
        except OSError:
            return []

        # Newest first, limited
        entries.reverse()
        return entries[:limit]
