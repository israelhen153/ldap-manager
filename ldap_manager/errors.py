"""Error formatting for the CLI boundary.

:func:`format_error` turns raw Python/LDAP exceptions into one-line
messages suitable for ``click.ClickException``.  It is called from
:class:`ldap_manager.cli._ErrorHandlingGroup`, which wraps every
Click command automatically — no per-function decorators needed.

:func:`exit_code_for` maps exceptions to structured exit codes so
scripts can distinguish error categories without parsing text:

    1  General / unknown error
    2  Usage error (Click default)
    3  Connection failed (server down, timeout, connection refused)
    4  Authentication failed (invalid credentials)
    5  Entry not found
    6  Entry already exists
    7  Permission denied
    8  Validation error (bad input, constraint violation)
    9  File / IO error

The mapping is deliberately explicit: each LDAP error type gets its
own message so operators can act on it without reading a traceback.
"""

from __future__ import annotations

import json
from typing import Any

import click

try:
    import ldap

    _LDAP_AVAILABLE = True
except ImportError:
    _LDAP_AVAILABLE = False

try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


def _ldap_detail(exc: Exception) -> str:
    """Extract the human-readable part of an LDAP exception."""
    if exc.args and isinstance(exc.args[0], dict):
        d: dict[str, Any] = exc.args[0]
        desc = d.get("desc", "")
        info = d.get("info", "")
        return f"{desc}: {info}" if info else desc
    return str(exc)


# Map LDAP exception type → short, actionable message.
_LDAP_MSGS: dict[type, str] = {}
if _LDAP_AVAILABLE:
    _LDAP_MSGS = {
        ldap.ALREADY_EXISTS: "Entry already exists",
        ldap.NO_SUCH_OBJECT: "Entry not found",
        ldap.INVALID_DN_SYNTAX: "Invalid DN syntax",
        ldap.INSUFFICIENT_ACCESS: "Permission denied",
        ldap.INVALID_CREDENTIALS: "Invalid bind credentials — check bind_dn and bind_password",
        ldap.SERVER_DOWN: "Cannot connect to LDAP server — check LDAP_URI and that slapd is running",
        ldap.CONNECT_ERROR: "Connection refused — check LDAP_URI and port",
        ldap.TIMEOUT: "Connection timed out",
        ldap.UNAVAILABLE: "LDAP server unavailable",
        ldap.UNWILLING_TO_PERFORM: "Server refused the operation",
        ldap.NO_SUCH_ATTRIBUTE: "Attribute not found on entry",
        ldap.UNDEFINED_TYPE: "Unknown attribute type",
        ldap.OBJECT_CLASS_VIOLATION: "Object class violation — missing required attribute",
        ldap.NAMING_VIOLATION: "Naming violation — check DN format",
        ldap.CONSTRAINT_VIOLATION: "Constraint violation — value rejected by server policy",
        ldap.TYPE_OR_VALUE_EXISTS: "Value already exists on this attribute",
        ldap.FILTER_ERROR: "Invalid LDAP search filter",
    }


def format_error(exc: Exception) -> str:
    """Convert an exception to a clean, one-line error message.

    Called from the CLI error-handling group when an exception escapes
    a Click command.  Returns a string suitable for
    ``click.ClickException(format_error(e))``.
    """
    # ── LDAP errors ──
    if _LDAP_AVAILABLE and isinstance(exc, ldap.LDAPError):
        base = _LDAP_MSGS.get(type(exc))
        detail = _ldap_detail(exc)
        if base:
            return f"{base} ({detail})" if detail else base
        return f"LDAP error ({type(exc).__name__}): {detail}"

    # ── File / IO errors ──
    if isinstance(exc, FileNotFoundError):
        return f"File not found: {exc.filename or exc}"
    if isinstance(exc, PermissionError):
        return f"Permission denied: {exc.filename or exc}"
    if isinstance(exc, IsADirectoryError):
        return f"Is a directory: {exc.filename or exc}"

    # ── Config errors ──
    if _YAML_AVAILABLE and isinstance(exc, yaml.YAMLError):
        return f"Invalid YAML configuration: {exc}"
    if isinstance(exc, json.JSONDecodeError):
        return f"Invalid JSON at line {exc.lineno}: {exc.msg}"

    # ── Application errors ──
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, RuntimeError):
        return str(exc)

    # ── Fallback — include the type so it's debuggable ──
    return f"{type(exc).__name__}: {exc}"


# ── Structured exit codes ────────────────────────────────────────────

EXIT_GENERAL = 1
EXIT_USAGE = 2  # Click default for bad arguments
EXIT_CONNECTION = 3
EXIT_AUTH = 4
EXIT_NOT_FOUND = 5
EXIT_ALREADY_EXISTS = 6
EXIT_PERMISSION = 7
EXIT_VALIDATION = 8
EXIT_IO = 9

_EXIT_CODES: dict[type, int] = {}
if _LDAP_AVAILABLE:
    _EXIT_CODES = {
        ldap.SERVER_DOWN: EXIT_CONNECTION,
        ldap.CONNECT_ERROR: EXIT_CONNECTION,
        ldap.TIMEOUT: EXIT_CONNECTION,
        ldap.UNAVAILABLE: EXIT_CONNECTION,
        ldap.INVALID_CREDENTIALS: EXIT_AUTH,
        ldap.NO_SUCH_OBJECT: EXIT_NOT_FOUND,
        ldap.ALREADY_EXISTS: EXIT_ALREADY_EXISTS,
        ldap.INSUFFICIENT_ACCESS: EXIT_PERMISSION,
        ldap.INVALID_DN_SYNTAX: EXIT_VALIDATION,
        ldap.CONSTRAINT_VIOLATION: EXIT_VALIDATION,
        ldap.NAMING_VIOLATION: EXIT_VALIDATION,
        ldap.OBJECT_CLASS_VIOLATION: EXIT_VALIDATION,
        ldap.FILTER_ERROR: EXIT_VALIDATION,
    }


def exit_code_for(exc: Exception) -> int:
    """Map an exception to a structured exit code.

    Used by ``_ErrorHandlingGroup`` in cli.py so scripts can
    distinguish error categories without parsing text.
    """
    if _LDAP_AVAILABLE and isinstance(exc, ldap.LDAPError):
        return _EXIT_CODES.get(type(exc), EXIT_GENERAL)
    if isinstance(exc, (FileNotFoundError, PermissionError, IsADirectoryError, OSError)):
        return EXIT_IO
    if isinstance(exc, ValueError):
        # ValueError is used for "not found" and "already exists" in the
        # manager classes — inspect the message to differentiate.
        msg = str(exc).lower()
        if "not found" in msg:
            return EXIT_NOT_FOUND
        if "already exists" in msg:
            return EXIT_ALREADY_EXISTS
        return EXIT_VALIDATION
    if isinstance(exc, click.ClickException):
        return EXIT_VALIDATION
    return EXIT_GENERAL
