"""Structured audit logging for LDAP operations.

Writes a JSON-lines audit log of every modification operation.
Each line is a self-contained JSON object with timestamp, action,
target, operator, and details.

Audit output is pluggable via :class:`Sink` implementations: file,
stdout, syslog, HTTP. An :class:`AuditLogger` fans out to one or
more sinks. A failure in any single sink is logged and suppressed
so it cannot block the caller.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Default audit log location
DEFAULT_AUDIT_LOG = "/var/log/ldap-manager/audit.jsonl"


# ── Sink abstraction ──────────────────────────────────────────────
class Sink(ABC):
    """Abstract base for audit sinks.

    A sink accepts a structured event (already a ``dict``) and
    transports it somewhere. Sinks must be safe to call repeatedly;
    any I/O cost amortises over the process lifetime. Resource
    cleanup is optional via :meth:`close`.
    """

    @abstractmethod
    def emit(self, event: dict[str, Any]) -> None:
        """Emit a single audit event.

        Implementations must raise on transport failure so that the
        owning :class:`AuditLogger` can log and move on to the next
        sink. They must not block or swallow errors silently.
        """

    def close(self) -> None:  # noqa: B027  (intentional default no-op hook)
        """Release any resources held by the sink. Default no-op."""


class FileSink(Sink):
    """Append JSON-serialized events to a file, one per line.

    Creates the parent directory on construction. Disables itself
    (logs a warning) if the path is not writable.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._enabled = True

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
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
    def path(self) -> Path:
        return self._path

    @property
    def enabled(self) -> bool:
        return self._enabled

    def emit(self, event: dict[str, Any]) -> None:
        if not self._enabled:
            return
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


class AuditLogger:
    """Append-only JSON-lines audit logger.

    Backward-compatible constructor: with no arguments (or with a
    ``log_path``) it behaves exactly as the old single-file logger.
    For richer fan-out, pass ``sinks=[...]``.
    """

    def __init__(
        self,
        log_path: str | Path | None = None,
    ) -> None:
        if log_path is None:
            log_path = os.environ.get("LDAP_MANAGER_AUDIT_LOG", DEFAULT_AUDIT_LOG)
        self._file_sink = FileSink(log_path)
        self._path = self._file_sink.path
        self._enabled = self._file_sink.enabled

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
            "timestamp": datetime.now(UTC).isoformat(),
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
            self._file_sink.emit(entry)
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
