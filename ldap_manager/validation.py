"""Input validation for ldap-manager.

Centralised guards that run *before* any LDAP call.  Import and call
``validate_uid`` at the entry of every method that accepts an
untrusted uid string.  The regex is a whitelist — only POSIX-safe
characters pass — so new attack vectors are blocked by default.
"""

from __future__ import annotations

import re

import click

# Starts with a letter, then alphanumeric + dot/dash/underscore.
# This is stricter than LDAP requires, but matches POSIX username
# conventions and prevents DN injection, null-byte truncation, and
# argument-parser confusion from leading dashes.
_UID_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]*$")
_UID_MAX = 256


def validate_uid(uid: str) -> str:
    """Validate a UID string.  Returns *uid* unchanged or raises
    :class:`click.ClickException` with a human-readable message.

    Catches: empty / None, null bytes, spaces, DN-special characters,
    leading digits/dashes/dots, and unreasonable lengths.
    """
    if not uid or not _UID_RE.match(uid):
        raise click.ClickException(
            f"Invalid UID: {uid!r}. "
            "Must start with a letter, contain only a-z, 0-9, dot, dash, underscore."
        )
    if len(uid) > _UID_MAX:
        raise click.ClickException(
            f"UID too long ({len(uid)} chars, max {_UID_MAX})."
        )
    return uid
