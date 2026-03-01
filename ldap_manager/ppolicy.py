"""Password policy (PPolicy) awareness.

Reads ppolicy overlay state to show password expiration, lockout status,
and policy details. Requires the ppolicy overlay to be loaded on the server.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import ldap
from ldap.ldapobject import LDAPObject

from .config import Config

log = logging.getLogger(__name__)

# PPolicy operational attributes
_PPOLICY_ATTRS = [
    "pwdChangedTime",
    "pwdAccountLockedTime",
    "pwdFailureTime",
    "pwdGraceUseTime",
    "pwdReset",
    "pwdPolicySubentry",
]

# PPolicy configuration attributes
_PPOLICY_CONFIG_ATTRS = [
    "pwdMaxAge",
    "pwdMinAge",
    "pwdMinLength",
    "pwdMaxFailure",
    "pwdLockout",
    "pwdLockoutDuration",
    "pwdGraceAuthNLimit",
    "pwdMustChange",
    "pwdCheckQuality",
    "pwdInHistory",
    "pwdExpireWarning",
]


@dataclass
class PasswordStatus:
    """Password state for a single user."""

    uid: str
    dn: str
    changed_time: str | None
    locked: bool
    locked_time: str | None
    failure_count: int
    must_change: bool
    expires: str | None
    grace_remaining: int | None
    policy_dn: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "dn": self.dn,
            "changed_time": self.changed_time,
            "locked": self.locked,
            "locked_time": self.locked_time,
            "failure_count": self.failure_count,
            "must_change": self.must_change,
            "expires": self.expires,
            "grace_remaining": self.grace_remaining,
            "policy_dn": self.policy_dn,
        }


@dataclass
class PolicyConfig:
    """PPolicy overlay configuration."""

    dn: str
    max_age: int | None
    min_age: int | None
    min_length: int | None
    max_failure: int | None
    lockout: bool
    lockout_duration: int | None
    grace_limit: int | None
    must_change: bool
    check_quality: int | None
    in_history: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "dn": self.dn,
            "max_age_seconds": self.max_age,
            "min_age_seconds": self.min_age,
            "min_length": self.min_length,
            "max_failure": self.max_failure,
            "lockout": self.lockout,
            "lockout_duration_seconds": self.lockout_duration,
            "grace_limit": self.grace_limit,
            "must_change_on_reset": self.must_change,
            "check_quality": self.check_quality,
            "passwords_in_history": self.in_history,
        }


class PPasswordManager:
    """Read password policy state from LDAP."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._lcfg = cfg.ldap

    def get_user_status(self, conn: LDAPObject, uid: str) -> PasswordStatus | None:
        """Get password policy status for a user."""
        search_filter = f"(&(objectClass=posixAccount)(uid={uid}))"

        # Request operational ppolicy attributes alongside uid
        attrs = ["uid", "dn"] + _PPOLICY_ATTRS

        try:
            results = conn.search_s(
                self._lcfg.users_ou,
                ldap.SCOPE_SUBTREE,
                search_filter,
                attrs,
            )
        except ldap.NO_SUCH_OBJECT:
            return None

        if not results or results[0][0] is None:
            return None

        dn, entry_attrs = results[0]

        def _s(key: str) -> str | None:
            vals = entry_attrs.get(key, [])
            return vals[0].decode("utf-8") if vals else None

        def _b(key: str) -> bool:
            val = _s(key)
            return val is not None and val.upper() == "TRUE"

        changed = _s("pwdChangedTime")
        locked_time = _s("pwdAccountLockedTime")
        locked = locked_time is not None and locked_time != "000001010000Z"
        failures = entry_attrs.get("pwdFailureTime", [])
        grace_uses = entry_attrs.get("pwdGraceUseTime", [])
        policy_dn = _s("pwdPolicySubentry")

        # Calculate expiry if we have a policy with pwdMaxAge
        expires = None
        policy = None
        if changed:
            try:
                # Try user-specific policy first, fall back to default
                policy = self.get_policy(conn, policy_dn) if policy_dn else self.get_policy(conn)
                if policy and policy.max_age:
                    changed_dt = _parse_generalized_time(changed)
                    if changed_dt:
                        from datetime import timedelta

                        expire_dt = changed_dt + timedelta(seconds=policy.max_age)
                        expires = expire_dt.isoformat()
            except Exception:
                pass

        grace = None
        if policy and policy.grace_limit is not None:
            grace = max(0, policy.grace_limit - len(grace_uses))

        return PasswordStatus(
            uid=uid,
            dn=dn,
            changed_time=changed,
            locked=locked,
            locked_time=locked_time,
            failure_count=len(failures),
            must_change=_b("pwdReset"),
            expires=expires,
            grace_remaining=grace if policy and policy.grace_limit else None,
            policy_dn=policy_dn or (policy.dn if policy else None),
        )

    def get_policy(self, conn: LDAPObject, policy_dn: str | None = None) -> PolicyConfig | None:
        """Read a password policy configuration.

        If policy_dn is None, tries to find the default policy.
        """
        if policy_dn is None:
            # Look for default policy under base DN
            try:
                results = conn.search_s(
                    self._lcfg.base_dn,
                    ldap.SCOPE_SUBTREE,
                    "(objectClass=pwdPolicy)",
                    _PPOLICY_CONFIG_ATTRS,
                )
                if not results or results[0][0] is None:
                    return None
                policy_dn = results[0][0]
                attrs = results[0][1]
            except ldap.NO_SUCH_OBJECT:
                return None
        else:
            try:
                results = conn.search_s(
                    policy_dn,
                    ldap.SCOPE_BASE,
                    "(objectClass=*)",
                    _PPOLICY_CONFIG_ATTRS,
                )
                if not results or results[0][0] is None:
                    return None
                attrs = results[0][1]
            except ldap.NO_SUCH_OBJECT:
                return None

        def _i(key: str) -> int | None:
            vals = attrs.get(key, [])
            if vals:
                try:
                    return int(vals[0].decode("utf-8"))
                except ValueError:
                    return None
            return None

        def _b(key: str) -> bool:
            vals = attrs.get(key, [])
            return vals[0].decode("utf-8").upper() == "TRUE" if vals else False

        return PolicyConfig(
            dn=policy_dn,
            max_age=_i("pwdMaxAge"),
            min_age=_i("pwdMinAge"),
            min_length=_i("pwdMinLength"),
            max_failure=_i("pwdMaxFailure"),
            lockout=_b("pwdLockout"),
            lockout_duration=_i("pwdLockoutDuration"),
            grace_limit=_i("pwdGraceAuthNLimit"),
            must_change=_b("pwdMustChange"),
            check_quality=_i("pwdCheckQuality"),
            in_history=_i("pwdInHistory"),
        )

    def check_all_users(
        self,
        conn: LDAPObject,
        *,
        expired_only: bool = False,
        locked_only: bool = False,
    ) -> list[PasswordStatus]:
        """Get password status for all users.

        Args:
            expired_only: Only return users with expired passwords
            locked_only: Only return locked users
        """
        try:
            results = conn.search_s(
                self._lcfg.users_ou,
                ldap.SCOPE_SUBTREE,
                "(objectClass=posixAccount)",
                ["uid"] + _PPOLICY_ATTRS,
            )
        except ldap.NO_SUCH_OBJECT:
            return []

        statuses = []
        for dn, attrs in results:
            if dn is None:
                continue

            uid_vals = attrs.get("uid", [])
            if not uid_vals:
                continue
            uid = uid_vals[0].decode("utf-8")

            status = self.get_user_status(conn, uid)
            if status is None:
                continue

            if expired_only and not (status.expires and status.expires < datetime.now(timezone.utc).isoformat()):
                continue
            if locked_only and not status.locked:
                continue

            statuses.append(status)

        return sorted(statuses, key=lambda s: s.uid)


def _parse_generalized_time(gt: str) -> datetime | None:
    """Parse LDAP GeneralizedTime (e.g. 20240115143022Z) to datetime."""
    try:
        # Strip fractional seconds if present
        gt = gt.split(".")[0]
        if gt.endswith("Z"):
            gt = gt[:-1]
        return datetime.strptime(gt, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None
