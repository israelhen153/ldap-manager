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
import logging.handlers
import os
import sys
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import request as urllib_request

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


class StdoutSink(Sink):
    """Write each event as a JSON line to stdout.

    Handy for container workflows where stdout is harvested by the
    platform. No buffering beyond the standard Python stream.
    """

    def emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


# Facility name → SysLogHandler constant. Covers the codes most
# operators actually use for application audit streams.
_SYSLOG_FACILITIES: dict[str, int] = {
    "user": logging.handlers.SysLogHandler.LOG_USER,
    "daemon": logging.handlers.SysLogHandler.LOG_DAEMON,
    "auth": logging.handlers.SysLogHandler.LOG_AUTH,
    "authpriv": logging.handlers.SysLogHandler.LOG_AUTHPRIV,
    "local0": logging.handlers.SysLogHandler.LOG_LOCAL0,
    "local1": logging.handlers.SysLogHandler.LOG_LOCAL1,
    "local2": logging.handlers.SysLogHandler.LOG_LOCAL2,
    "local3": logging.handlers.SysLogHandler.LOG_LOCAL3,
    "local4": logging.handlers.SysLogHandler.LOG_LOCAL4,
    "local5": logging.handlers.SysLogHandler.LOG_LOCAL5,
    "local6": logging.handlers.SysLogHandler.LOG_LOCAL6,
    "local7": logging.handlers.SysLogHandler.LOG_LOCAL7,
}


class SyslogSink(Sink):
    """Send JSON-serialized events to syslog.

    Wraps ``logging.handlers.SysLogHandler``. Each event becomes one
    syslog message. ``address`` defaults to ``/dev/log`` on Unix, as
    does the underlying handler.
    """

    def __init__(
        self,
        facility: str = "local3",
        address: str | tuple[str, int] | None = None,
    ) -> None:
        facility_code = _SYSLOG_FACILITIES.get(facility.lower())
        if facility_code is None:
            raise ValueError(f"Unknown syslog facility {facility!r}. Known: {sorted(_SYSLOG_FACILITIES)}")
        handler_kwargs: dict[str, Any] = {"facility": facility_code}
        if address is not None:
            handler_kwargs["address"] = address
        self._handler = logging.handlers.SysLogHandler(**handler_kwargs)
        self._logger = logging.getLogger(f"ldap_manager.audit.syslog.{id(self)}")
        self._logger.addHandler(self._handler)
        self._logger.setLevel(logging.INFO)
        # Don't let parent loggers (e.g. root) double-emit the audit events.
        self._logger.propagate = False

    def emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        self._logger.info(line)

    def close(self) -> None:
        self._logger.removeHandler(self._handler)
        self._handler.close()


class HTTPSink(Sink):
    """POST events as JSON to an HTTP endpoint.

    Uses ``urllib.request`` to avoid a new dependency. Headers default
    to ``Content-Type: application/json``; callers can supply extras
    (e.g. ``Authorization``) via the ``headers`` kwarg.
    """

    def __init__(
        self,
        url: str,
        timeout_seconds: float = 5.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._url = url
        self._timeout = timeout_seconds
        merged = {"Content-Type": "application/json"}
        if headers:
            merged.update(headers)
        self._headers = merged

    def emit(self, event: dict[str, Any]) -> None:
        body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        # URL is operator-configured in YAML; http/https sinks are the
        # whole point of this class, so urllib's scheme-blacklist warning
        # does not apply.
        req = urllib_request.Request(  # noqa: S310
            self._url,
            data=body,
            headers=self._headers,
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=self._timeout):  # noqa: S310  # nosec B310
            # Drain the response so the connection is released.
            pass


class AuditLogger:
    """Append-only JSON-lines audit logger with pluggable sinks.

    Backward-compatible constructor: with no arguments (or with just a
    ``log_path``) it writes to a single :class:`FileSink`, preserving
    the pre-sinks behaviour. Pass ``sinks=[...]`` for fan-out.

    CRITICAL INVARIANT: if a sink's ``emit()`` raises, the error is
    logged to stderr and the remaining sinks still run. An audit-
    pipeline failure must never block the caller.
    """

    def __init__(
        self,
        log_path: str | Path | None = None,
        *,
        sinks: list[Sink] | None = None,
    ) -> None:
        if sinks is None:
            if log_path is None:
                log_path = os.environ.get("LDAP_MANAGER_AUDIT_LOG", DEFAULT_AUDIT_LOG)
            file_sink = FileSink(log_path)
            self._sinks: list[Sink] = [file_sink]
            self._path = file_sink.path
            self._enabled = file_sink.enabled
        else:
            self._sinks = list(sinks)
            # Preserve .path / .enabled for legacy callers (cli.py audit
            # status/log commands). Fall back to the default path so
            # .query() on that file still works.
            default_path = log_path or os.environ.get("LDAP_MANAGER_AUDIT_LOG", DEFAULT_AUDIT_LOG)
            file_sinks = [s for s in self._sinks if isinstance(s, FileSink)]
            self._path = file_sinks[0].path if file_sinks else Path(default_path)
            # Logger is enabled if at least one sink exists.
            self._enabled = bool(self._sinks)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def path(self) -> Path:
        return self._path

    @property
    def sinks(self) -> list[Sink]:
        return list(self._sinks)

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
        """Write an audit log entry to every configured sink.

        Per-sink failures are caught: a broken HTTP endpoint must not
        stop us from writing to the file. Errors are surfaced to stderr
        so operators can see what's dropping.

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

        entry: dict[str, Any] = {
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

        for sink in self._sinks:
            try:
                sink.emit(entry)
            # Must catch *everything*: the whole point of the invariant is
            # that a buggy sink cannot stop the caller.
            except Exception as exc:  # pragma: no branch
                # Write directly to stderr — logging may itself be routed
                # through an audit handler that's also in trouble.
                sys.stderr.write(f"[ldap-manager] audit sink {type(sink).__name__} failed: {type(exc).__name__}: {exc}\n")

    def close(self) -> None:
        """Close every configured sink, swallowing errors."""
        for sink in self._sinks:
            try:
                sink.close()
            except Exception as exc:  # pragma: no branch
                sys.stderr.write(f"[ldap-manager] audit sink {type(sink).__name__} close failed: {type(exc).__name__}: {exc}\n")

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
