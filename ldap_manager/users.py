"""User CRUD operations against LDAP.

All public methods accept a bound LDAPObject (from LDAPConnection context).
This keeps the connection lifecycle outside this module — easier to test,
easier to compose operations within a single connection.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import ldap
import ldap.modlist as modlist
from ldap.ldapobject import LDAPObject

from .config import Config

log = logging.getLogger(__name__)

# Attributes we always pull back for user listings
_USER_ATTRS = [
    "uid",
    "cn",
    "sn",
    "givenName",
    "mail",
    "uidNumber",
    "gidNumber",
    "homeDirectory",
    "loginShell",
    "userPassword",
    "shadowExpire",
]


@dataclass
class UserEntry:
    """Thin representation of an LDAP user entry."""

    dn: str
    uid: str
    cn: str
    sn: str
    given_name: str
    mail: str
    uid_number: int
    gid_number: int
    home_directory: str
    login_shell: str
    enabled: bool

    @classmethod
    def from_ldap(cls, dn: str, attrs: dict[str, list[bytes]]) -> UserEntry:
        def _s(key: str, default: str = "") -> str:
            vals = attrs.get(key, [])
            return vals[0].decode("utf-8") if vals else default

        def _i(key: str, default: int = 0) -> int:
            vals = attrs.get(key, [])
            return int(vals[0].decode("utf-8")) if vals else default

        shell = _s("loginShell", "/bin/bash")
        disabled_shells = {"/sbin/nologin", "/bin/false", "/usr/sbin/nologin"}
        enabled = shell not in disabled_shells

        return cls(
            dn=dn,
            uid=_s("uid"),
            cn=_s("cn"),
            sn=_s("sn"),
            given_name=_s("givenName"),
            mail=_s("mail"),
            uid_number=_i("uidNumber"),
            gid_number=_i("gidNumber"),
            home_directory=_s("homeDirectory"),
            login_shell=shell,
            enabled=enabled,
        )


class UserManager:
    """LDAP user CRUD operations."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._lcfg = cfg.ldap
        self._ucfg = cfg.users

    # ── DUMP (JSON export) ─────────────────────────────────────────
    def dump_users(
        self,
        conn: LDAPObject,
        *,
        enabled_only: bool = False,
        disabled_only: bool = False,
        extra_attrs: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Dump all users with ALL their LDAP attributes as plain dicts.

        Unlike list_users/UserEntry which only returns a curated subset,
        this pulls every attribute the bound user has read access to.
        Binary values (userPassword, jpegPhoto, etc.) are base64-encoded.

        Args:
            conn: Bound LDAP connection
            enabled_only: Skip disabled users
            disabled_only: Skip enabled users
            extra_attrs: If set, fetch ONLY these attrs (plus uid/loginShell
                         for filtering). Default None = fetch all.

        Returns:
            List of dicts, each representing a user. All values are strings
            or lists of strings — safe to json.dumps() directly.
        """
        import base64

        # Always need loginShell for enable/disable filtering
        fetch_attrs = None  # None = fetch all
        if extra_attrs is not None:
            required = {"uid", "loginShell"}
            fetch_attrs = list(required | set(extra_attrs))

        search_filter = "(objectClass=posixAccount)"
        try:
            results = conn.search_s(
                self._lcfg.users_ou,
                ldap.SCOPE_SUBTREE,
                search_filter,
                fetch_attrs,
            )
        except ldap.NO_SUCH_OBJECT:
            return []

        disabled_shells = {"/sbin/nologin", "/bin/false", "/usr/sbin/nologin"}
        users: list[dict[str, Any]] = []

        for dn, attrs in results:
            if dn is None:
                continue

            # Determine enabled status for filtering
            shell_vals = attrs.get("loginShell", [])
            shell = shell_vals[0].decode("utf-8", errors="replace") if shell_vals else "/bin/bash"
            is_enabled = shell not in disabled_shells

            if enabled_only and not is_enabled:
                continue
            if disabled_only and is_enabled:
                continue

            # Convert all attributes to JSON-safe types
            entry: dict[str, Any] = {"dn": dn, "_enabled": is_enabled}

            for attr_name, values in attrs.items():
                decoded = []
                for val in values:
                    try:
                        decoded.append(val.decode("utf-8"))
                    except UnicodeDecodeError:
                        # Binary attribute (password hash, photo, cert, etc.)
                        decoded.append(base64.b64encode(val).decode("ascii"))

                # Single-valued attrs get unwrapped for cleaner JSON
                entry[attr_name] = decoded[0] if len(decoded) == 1 else decoded

            users.append(entry)

        return sorted(users, key=lambda u: u.get("uid", ""))

    # ── SEARCH ──────────────────────────────────────────────────────
    def search_users(
        self,
        conn: LDAPObject,
        *,
        ldap_filter: str | None = None,
        uid: str | None = None,
        cn: str | None = None,
        mail: str | None = None,
        gid: int | None = None,
        shell: str | None = None,
        enabled_only: bool = False,
        disabled_only: bool = False,
    ) -> list[UserEntry]:
        """Search users with an LDAP filter and/or convenience fields.

        Combines raw LDAP filter passthrough with shorthand fields.
        All conditions are ANDed together.

        Args:
            conn: Bound LDAP connection
            ldap_filter: Raw LDAP filter, e.g. "(description=contractor*)"
            uid: Wildcard match on uid, e.g. "j*" or "jdoe"
            cn: Wildcard match on cn
            mail: Wildcard match on mail
            gid: Exact match on gidNumber
            shell: Exact match on loginShell
            enabled_only: Exclude disabled users
            disabled_only: Exclude enabled users

        Returns:
            List of matching UserEntry objects, sorted by uid.
        """
        parts = ["(objectClass=posixAccount)"]

        if uid:
            parts.append(f"(uid={uid})")
        if cn:
            parts.append(f"(cn={cn})")
        if mail:
            parts.append(f"(mail={mail})")
        if gid is not None:
            parts.append(f"(gidNumber={gid})")
        if shell:
            parts.append(f"(loginShell={shell})")
        if ldap_filter:
            # Strip outer parens if missing — be forgiving
            f = ldap_filter.strip()
            if not f.startswith("("):
                f = f"({f})"
            parts.append(f)

        search_filter = f"(&{''.join(parts)})"
        log.debug("Search filter: %s", search_filter)

        try:
            results = conn.search_s(self._lcfg.users_ou, ldap.SCOPE_SUBTREE, search_filter, _USER_ATTRS)
        except ldap.NO_SUCH_OBJECT:
            return []
        except ldap.FILTER_ERROR as exc:
            raise ValueError(f"Invalid LDAP filter: {exc}") from exc

        users = []
        for dn, attrs in results:
            if dn is None:
                continue
            user = UserEntry.from_ldap(dn, attrs)
            if enabled_only and not user.enabled:
                continue
            if disabled_only and user.enabled:
                continue
            users.append(user)

        return sorted(users, key=lambda u: u.uid)

    # ── READ ───────────────────────────────────────────────────────
    def get_user(self, conn: LDAPObject, uid: str) -> UserEntry | None:
        """Fetch a single user by uid. Returns None if not found."""
        search_filter = f"(&(objectClass=posixAccount)(uid={_escape(uid)}))"
        try:
            results = conn.search_s(self._lcfg.users_ou, ldap.SCOPE_SUBTREE, search_filter, _USER_ATTRS)
        except ldap.NO_SUCH_OBJECT:
            return None

        if not results:
            return None

        dn, attrs = results[0]
        if dn is None:
            return None
        return UserEntry.from_ldap(dn, attrs)

    def list_users(
        self,
        conn: LDAPObject,
        *,
        enabled_only: bool = False,
        disabled_only: bool = False,
    ) -> list[UserEntry]:
        """List all users under the users OU."""
        search_filter = "(objectClass=posixAccount)"
        try:
            results = conn.search_s(self._lcfg.users_ou, ldap.SCOPE_SUBTREE, search_filter, _USER_ATTRS)
        except ldap.NO_SUCH_OBJECT:
            return []

        users = []
        for dn, attrs in results:
            if dn is None:
                continue
            user = UserEntry.from_ldap(dn, attrs)
            if enabled_only and not user.enabled:
                continue
            if disabled_only and user.enabled:
                continue
            users.append(user)

        return sorted(users, key=lambda u: u.uid)

    # ── CREATE ─────────────────────────────────────────────────────
    def create_user(
        self,
        conn: LDAPObject,
        uid: str,
        cn: str | None = None,
        sn: str | None = None,
        *,
        given_name: str = "",
        mail: str = "",
        uid_number: int | None = None,
        gid_number: int | None = None,
        home_directory: str | None = None,
        login_shell: str | None = "/bin/bash",
        explicit_password: str | None = "123456",
    ) -> tuple[str, str | None]:
        """Create a new posixAccount user entry.

        Only uid is required. Everything else is derived from config:
          - cn defaults to uid
          - sn defaults to uid
          - mail defaults to uid@mail_domain (if mail_domain set in config)
          - password auto-generated if generate_password_on_create is true
          - uid_number auto-assigned from configured range
          - home, shell, gid all from config

        Returns (dn, generated_password) — password is None if not generated.
        """
        if self.get_user(conn, uid) is not None:
            raise ValueError(f"User '{uid}' already exists")

        # Derive defaults from config
        if cn is None:
            cn = uid
        if sn is None:
            sn = uid
        if not mail and self._ucfg.mail_domain:
            mail = f"{uid}@{self._ucfg.mail_domain}"
        if uid_number is None:
            uid_number = self._next_uid_number(conn)
        if gid_number is None:
            gid_number = self._ucfg.default_gid
        if home_directory is None:
            home_directory = f"{self._ucfg.home_prefix}/{uid}"
        if login_shell is None:
            login_shell = self._ucfg.default_shell

        # Password: explicit > generate > default > none
        generated_password = None
        if explicit_password is None:
            if self._ucfg.generate_password_on_create:
                generated_password = explicit_password
            elif self._ucfg.default_password:
                generated_password = self._ucfg.default_password

        dn = f"uid={_escape(uid)},{self._lcfg.users_ou}"

        entry: dict[str, list[bytes]] = {
            "objectClass": [c.encode() for c in self._ucfg.object_classes],
            "uid": [uid.encode()],
            "cn": [cn.encode()],
            "sn": [sn.encode()],
            "uidNumber": [str(uid_number).encode()],
            "gidNumber": [str(gid_number).encode()],
            "homeDirectory": [home_directory.encode()],
            "loginShell": [login_shell.encode()],
        }

        if given_name:
            entry["givenName"] = [given_name.encode()]
        if mail:
            entry["mail"] = [mail.encode()]
        if generated_password:
            entry["userPassword"] = [_hash_password(generated_password, self._resolve_scheme(conn))]

        add_list = modlist.addModlist(entry)
        conn.add_s(dn, add_list)
        log.info("Created user %s (%s)", uid, dn)
        return dn, explicit_password

    # ── UPDATE ─────────────────────────────────────────────────────
    def update_user(self, conn: LDAPObject, uid: str, **attrs: str | int) -> None:
        """Update arbitrary attributes on a user entry.

        Accepts keyword arguments mapping attribute names to new values.
        Example: update_user(conn, "jdoe", mail="new@example.com", loginShell="/bin/zsh")
        """
        user = self.get_user(conn, uid)
        if user is None:
            raise ValueError(f"User '{uid}' not found")

        mod_list = []
        for attr_name, value in attrs.items():
            mod_list.append((ldap.MOD_REPLACE, attr_name, [str(value).encode()]))

        if not mod_list:
            return

        conn.modify_s(user.dn, mod_list)
        log.info("Updated user %s: %s", uid, list(attrs.keys()))

    # ── DELETE ─────────────────────────────────────────────────────
    def delete_user(self, conn: LDAPObject, uid: str) -> None:
        """Delete a user entry."""
        user = self.get_user(conn, uid)
        if user is None:
            raise ValueError(f"User '{uid}' not found")

        conn.delete_s(user.dn)
        log.info("Deleted user %s (%s)", uid, user.dn)

    # ── ENABLE / DISABLE ──────────────────────────────────────────
    def disable_user(self, conn: LDAPObject, uid: str) -> None:
        """Disable user by setting loginShell to nologin."""
        user = self.get_user(conn, uid)
        if user is None:
            raise ValueError(f"User '{uid}' not found")
        if not user.enabled:
            log.warning("User %s is already disabled", uid)
            return

        conn.modify_s(
            user.dn,
            [(ldap.MOD_REPLACE, "loginShell", [self._ucfg.disabled_shell.encode()])],
        )
        log.info("Disabled user %s (shell -> %s)", uid, self._ucfg.disabled_shell)

    def enable_user(self, conn: LDAPObject, uid: str) -> None:
        """Re-enable user by restoring default loginShell."""
        user = self.get_user(conn, uid)
        if user is None:
            raise ValueError(f"User '{uid}' not found")
        if user.enabled:
            log.warning("User %s is already enabled", uid)
            return

        conn.modify_s(
            user.dn,
            [(ldap.MOD_REPLACE, "loginShell", [self._ucfg.default_shell.encode()])],
        )
        log.info("Enabled user %s (shell -> %s)", uid, self._ucfg.default_shell)

    # ── PASSWORD ──────────────────────────────────────────────────
    def set_password(self, conn: LDAPObject, uid: str, password: str) -> None:
        """Set a user's password.

        The hash scheme is resolved from ``cfg.password.hash_scheme``:
        ``"auto"`` (the default) triggers cn=config detection on first
        call per connection; any other value is used verbatim.
        """
        user = self.get_user(conn, uid)
        if user is None:
            raise ValueError(f"User '{uid}' not found")

        hashed = _hash_password(password, self._resolve_scheme(conn))
        conn.modify_s(user.dn, [(ldap.MOD_REPLACE, "userPassword", [hashed])])
        log.info("Password changed for user %s", uid)

    def _resolve_scheme(self, conn: LDAPObject) -> str:
        """Turn ``cfg.password.hash_scheme`` into a concrete scheme.

        Import is lazy — at module import time passwords.py imports
        users.py for UserManager; importing passwords.py here too would
        still work (it's already loaded) but the late import keeps the
        dependency direction visible.
        """
        from .passwords import resolve_hash_scheme

        return resolve_hash_scheme(self._cfg, conn)

    # ── INTERNAL ──────────────────────────────────────────────────
    def _next_uid_number(self, conn: LDAPObject) -> int:
        """Find the next available uidNumber in the configured range."""
        results = conn.search_s(
            self._lcfg.users_ou,
            ldap.SCOPE_SUBTREE,
            "(objectClass=posixAccount)",
            ["uidNumber"],
        )
        used = set()
        for _, attrs in results:
            for val in attrs.get("uidNumber", []):
                try:
                    used.add(int(val.decode()))
                except ValueError:
                    pass

        for candidate in range(self._ucfg.uid_min, self._ucfg.uid_max + 1):
            if candidate not in used:
                return candidate

        raise RuntimeError(f"No available uidNumber in range {self._ucfg.uid_min}-{self._ucfg.uid_max}")


# ── Helpers ────────────────────────────────────────────────────────


def _escape(value: str) -> str:
    """Escape special characters for use in DN components and filters."""
    # For DN: escape per RFC 4514
    # For filters: escape per RFC 4515
    # This handles the critical ones; python-ldap's filter.escape_filter_chars
    # is used for search filters, but DN escaping is simpler.
    for char in ("\\", ",", "+", '"', "<", ">", ";", "=", "\0"):
        value = value.replace(char, f"\\{char}")
    return value


def _hash_password(password: str, scheme: str = "ssha") -> bytes:
    """Hash a password under the given scheme.

    Delegates to :func:`ldap_manager.passwords.hash_password` — this
    thin wrapper exists so users.py keeps its internal helper name and
    callers inside this module don't have to reach across modules.

    ``scheme`` defaults to ``"ssha"`` purely to keep this helper safe to
    call in isolation (e.g. from tests). Production callers pass the
    resolved scheme from :func:`passwords.resolve_hash_scheme`.
    """
    # Local import keeps the module graph acyclic: passwords imports users
    # at top level for UserManager access.
    from .passwords import hash_password

    return hash_password(password, scheme)
