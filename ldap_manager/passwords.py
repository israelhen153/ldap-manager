"""Bulk password operations and scheme-aware password hashing.

This module has two concerns:

1. **Bulk reset** — generate secure random passwords for every user and
   apply them via LDAP modify, with an optional CSV manifest. Writing
   plaintext passwords to disk is a liability: the caller must opt in
   explicitly and the CLI gates that on ``--confirm-plaintext``. When no
   ``output_file`` is given, passwords are generated, applied, and
   immediately dropped — the function returns only aggregate counts.

2. **Password hashing** — :func:`hash_password` implements the three
   schemes ldap-manager supports on OpenLDAP (``argon2id``, ``ssha512``,
   ``ssha``) and :func:`resolve_hash_scheme` turns the config value (which
   may be ``"auto"``) into a concrete scheme. :func:`detect_hash_support`
   probes ``cn=config`` for ``olcPasswordHash`` so ``auto`` can match the
   server's own policy without operator intervention.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import logging
import os
import secrets
import stat
import string
from dataclasses import dataclass, field
from pathlib import Path
from weakref import WeakKeyDictionary

import ldap

from .backends import Backend
from .config import Config
from .users import UserManager

log = logging.getLogger(__name__)

# ── Hash schemes ───────────────────────────────────────────────────
#
# Supported schemes, ordered from strongest (preferred) to weakest. A
# server is said to "support" a scheme if its ``olcPasswordHash`` lists
# the equivalent OpenLDAP tag (``{ARGON2}``, ``{SSHA512}``, ``{SSHA}``).
_SCHEME_PRIORITY = ("argon2id", "ssha512", "ssha")

# Normalised scheme -> OpenLDAP userPassword prefix tag.
_SCHEME_TAGS = {
    "argon2id": "{ARGON2}",
    "ssha512": "{SSHA512}",
    "ssha": "{SSHA}",
}

# Map of the tag-as-seen-in-cn=config back to our canonical scheme name.
# OpenLDAP may report either ``{ARGON2}`` or ``{ARGON2ID}``; accept both.
_TAG_TO_SCHEME = {
    "{ARGON2}": "argon2id",
    "{ARGON2ID}": "argon2id",
    "{SSHA512}": "ssha512",
    "{SSHA}": "ssha",
}

# Legacy/config-format aliases. Operators used to configure the hash
# scheme as the bare OpenLDAP prefix (e.g. ``"{SSHA}"``); translate that
# to the canonical scheme name so existing YAML keeps working.
_SCHEME_ALIASES = {
    "{argon2}": "argon2id",
    "{argon2id}": "argon2id",
    "argon2": "argon2id",
    "argon2id": "argon2id",
    "{ssha512}": "ssha512",
    "ssha512": "ssha512",
    "{ssha}": "ssha",
    "ssha": "ssha",
}

# Per-backend cache for detect_hash_support. WeakKeyDictionary lets the
# entry evaporate when the Backend instance is garbage-collected — we
# don't want to hold backends alive just to cache a string. MagicMock,
# OpenLDAPBackend, and the _FakeConn used by the detection tests are all
# weakly referenceable, so no fallback is needed.
_DETECT_CACHE: WeakKeyDictionary[Backend, str] = WeakKeyDictionary()


def _normalize_scheme(scheme: str) -> str:
    """Map a user-supplied scheme string to our canonical name.

    Accepts the canonical ``"argon2id"``/``"ssha512"``/``"ssha"`` forms
    as well as the legacy OpenLDAP-prefix forms (``"{SSHA}"``, etc.)
    that older configs may carry. Case-insensitive.
    """
    key = scheme.strip().lower()
    if key not in _SCHEME_ALIASES:
        raise ValueError(f"Unknown password hash scheme {scheme!r}. Expected one of: {', '.join(_SCHEME_PRIORITY)} (or 'auto').")
    return _SCHEME_ALIASES[key]


def detect_hash_support(backend: Backend) -> str:
    """Return the strongest password hash scheme the server advertises.

    Probes ``cn=config`` for ``olcPasswordHash`` and picks the strongest
    scheme (per :data:`_SCHEME_PRIORITY`) that both the server supports
    AND we can actually emit. Result is cached per-backend so repeated
    ``auto`` resolves in one session don't re-probe.

    Failure modes that return ``"ssha"`` (never raise):
      * Access denied (bind user can't read cn=config).
      * cn=config not present (not all setups use dynamic config).
      * Any unexpected LDAP error.

    When ``argon2id`` would otherwise win but ``argon2-cffi`` isn't
    importable, it's skipped — we can't hash what we can't produce.
    """
    cached = _DETECT_CACHE.get(backend)
    if cached is not None:
        return cached

    # We probe the olcConfig subtree for any olcPasswordHash value. The
    # attribute lives on the frontend/database overlays depending on the
    # setup; subtree-search from cn=config catches all of them.
    #
    # Catch broadly: LDAP errors are the expected failure (insufficient
    # access, cn=config absent), but we also don't want unexpected result
    # shapes (e.g. a mocked connection returning an exhausted iterator)
    # to abort a legitimate password change. Falling back to SSHA is
    # always safe.
    found_tags: set[str] = set()
    try:
        results = backend.search(
            "cn=config",
            ldap.SCOPE_SUBTREE,
            "(olcPasswordHash=*)",
            ["olcPasswordHash"],
        )
        for _dn, attrs in results:
            for raw in attrs.get("olcPasswordHash", []):
                try:
                    found_tags.add(raw.decode("utf-8").strip().upper())
                except UnicodeDecodeError:
                    continue
    except Exception as exc:
        log.warning(
            "Could not probe cn=config for olcPasswordHash (%s); falling back to SSHA for hash scheme detection.",
            exc,
        )
        _DETECT_CACHE[backend] = "ssha"
        return "ssha"

    supported = {_TAG_TO_SCHEME[tag] for tag in found_tags if tag in _TAG_TO_SCHEME}

    # If the server didn't advertise anything we understand, fall back.
    # SSHA is always safe — every OpenLDAP build ships it.
    if not supported:
        log.info("cn=config returned no recognised olcPasswordHash values; defaulting to SSHA.")
        _DETECT_CACHE[backend] = "ssha"
        return "ssha"

    # Walk the priority list; pick the strongest we can actually emit.
    for scheme in _SCHEME_PRIORITY:
        if scheme not in supported:
            continue
        if scheme == "argon2id" and not _argon2_available():
            log.warning(
                "Server advertises {ARGON2} but argon2-cffi is not "
                "installed; skipping argon2id. Install with "
                "'pip install argon2-cffi' to use it."
            )
            continue
        _DETECT_CACHE[backend] = scheme
        return scheme

    # Server only advertised things we can't produce (shouldn't really
    # happen — SSHA should always be in the supported set).
    _DETECT_CACHE[backend] = "ssha"
    return "ssha"


def resolve_hash_scheme(cfg: Config, backend: Backend) -> str:
    """Resolve ``cfg.password.hash_scheme`` to a concrete scheme name.

    Precedence:
      * ``"auto"`` → :func:`detect_hash_support`.
      * Anything else → :func:`_normalize_scheme` (raises on unknown).

    An explicit scheme ALWAYS wins over ``auto`` detection. That's the
    escape hatch for operators who know better than our probe.
    """
    raw = (cfg.password.hash_scheme or "auto").strip()
    if raw.lower() == "auto":
        return detect_hash_support(backend)
    return _normalize_scheme(raw)


def _argon2_available() -> bool:
    """Return True iff argon2-cffi is importable in this process."""
    try:
        import argon2  # noqa: F401
    except ImportError:
        return False
    return True


def _hash_ssha(password: str) -> bytes:
    """Salted SHA-1 with a 16-byte salt, base64(digest|salt) body."""
    salt = os.urandom(16)
    digest = hashlib.sha1(password.encode("utf-8") + salt).digest()
    body = base64.b64encode(digest + salt).decode("ascii")
    return f"{_SCHEME_TAGS['ssha']}{body}".encode()


def _hash_ssha512(password: str) -> bytes:
    """Salted SHA-512 with a 16-byte salt, base64(digest|salt) body."""
    salt = os.urandom(16)
    digest = hashlib.sha512(password.encode("utf-8") + salt).digest()
    body = base64.b64encode(digest + salt).decode("ascii")
    return f"{_SCHEME_TAGS['ssha512']}{body}".encode()


def _hash_argon2id(password: str) -> bytes:
    """Argon2id via argon2-cffi, prefixed with OpenLDAP's ``{ARGON2}``.

    Parameters (time_cost=3, memory_cost=64 MiB, parallelism=4, hash_len=32,
    salt_len=16) track OWASP 2024 recommendations for interactive auth.
    """
    try:
        from argon2 import PasswordHasher
        from argon2.low_level import Type
    except ImportError as exc:  # pragma: no cover - exercised via soft-path test
        raise RuntimeError("argon2id requested but argon2-cffi is not installed; pip install argon2-cffi") from exc

    hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )
    encoded = hasher.hash(password)
    return f"{_SCHEME_TAGS['argon2id']}{encoded}".encode()


def hash_password(password: str, scheme: str) -> bytes:
    """Hash ``password`` under the given scheme, returning the bytes to
    drop into the ``userPassword`` attribute (prefix + body).

    ``scheme`` is the normalised name (``"argon2id"``, ``"ssha512"``,
    ``"ssha"``) or one of the accepted aliases — see
    :func:`_normalize_scheme`.
    """
    normalized = _normalize_scheme(scheme)
    if normalized == "argon2id":
        return _hash_argon2id(password)
    if normalized == "ssha512":
        return _hash_ssha512(password)
    if normalized == "ssha":
        return _hash_ssha(password)
    # _normalize_scheme would have raised already, but keep the branch
    # explicit for the type-checker.
    raise ValueError(f"Unknown password hash scheme: {scheme!r}")


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
    backend: Backend,
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
        backend: Bound LDAP backend.
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

    users = user_mgr.list_users(backend, enabled_only=enabled_only)
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
                user_mgr.set_password(backend, user.uid, new_password)
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
