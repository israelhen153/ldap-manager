"""LDAP group management.

Supports both posixGroup (memberUid) and groupOfNames (member DN) styles.
Auto-detects which objectClass a group uses and operates accordingly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import ldap
import ldap.modlist as modlist

from .backends import Backend
from .config import Config

log = logging.getLogger(__name__)

_GROUP_ATTRS = [
    "cn",
    "gidNumber",
    "description",
    "memberUid",
    "member",
    "objectClass",
]


@dataclass
class GroupEntry:
    """Representation of an LDAP group."""

    dn: str
    cn: str
    gid_number: int
    description: str
    members: list[str]  # uids for posixGroup, DNs for groupOfNames
    object_classes: list[str]
    is_posix: bool  # True = posixGroup (memberUid), False = groupOfNames (member DN)

    @classmethod
    def from_ldap(cls, dn: str, attrs: dict[str, list[bytes]]) -> GroupEntry:
        def _s(key: str, default: str = "") -> str:
            vals = attrs.get(key, [])
            return vals[0].decode("utf-8") if vals else default

        def _i(key: str, default: int = 0) -> int:
            vals = attrs.get(key, [])
            return int(vals[0].decode("utf-8")) if vals else default

        def _sl(key: str) -> list[str]:
            return [v.decode("utf-8") for v in attrs.get(key, [])]

        ocs = _sl("objectClass")
        oc_lower = [o.lower() for o in ocs]
        is_posix = "posixgroup" in oc_lower

        if is_posix:
            members = _sl("memberUid")
        else:
            members = _sl("member")

        return cls(
            dn=dn,
            cn=_s("cn"),
            gid_number=_i("gidNumber"),
            description=_s("description"),
            members=members,
            object_classes=ocs,
            is_posix=is_posix,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dn": self.dn,
            "cn": self.cn,
            "gid_number": self.gid_number,
            "description": self.description,
            "members": self.members,
            "member_count": len(self.members),
            "type": "posixGroup" if self.is_posix else "groupOfNames",
        }


class GroupManager:
    """LDAP group CRUD and membership operations."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._lcfg = cfg.ldap

    # ── READ ───────────────────────────────────────────────────────
    def get_group(self, backend: Backend, cn: str) -> GroupEntry | None:
        """Fetch a single group by cn."""
        search_filter = f"(&(|(objectClass=posixGroup)(objectClass=groupOfNames))(cn={cn}))"
        try:
            results = backend.search(self._lcfg.groups_ou, ldap.SCOPE_SUBTREE, search_filter, _GROUP_ATTRS)
        except ldap.NO_SUCH_OBJECT:
            return None

        if not results:
            return None

        dn, attrs = results[0]
        if dn is None:
            return None
        return GroupEntry.from_ldap(dn, attrs)

    def list_groups(self, backend: Backend) -> list[GroupEntry]:
        """List all groups under the groups OU."""
        search_filter = "(|(objectClass=posixGroup)(objectClass=groupOfNames))"
        try:
            results = backend.search(self._lcfg.groups_ou, ldap.SCOPE_SUBTREE, search_filter, _GROUP_ATTRS)
        except ldap.NO_SUCH_OBJECT:
            return []

        groups = []
        for dn, attrs in results:
            if dn is None:
                continue
            groups.append(GroupEntry.from_ldap(dn, attrs))

        return sorted(groups, key=lambda g: g.cn)

    # ── CREATE ─────────────────────────────────────────────────────
    def create_group(
        self,
        backend: Backend,
        cn: str,
        gid_number: int,
        *,
        description: str = "",
        posix: bool = True,
    ) -> str | None:
        """Create a new group. Returns the DN.

        Args:
            cn: Group name
            gid_number: GID number
            description: Optional description
            posix: If True, create posixGroup. If False, create groupOfNames.
        """
        if self.get_group(backend, cn) is not None:
            raise ValueError(f"Group '{cn}' already exists")

        dn = f"cn={cn},{self._lcfg.groups_ou}"

        if posix:
            entry: dict[str, list[bytes]] = {
                "objectClass": [b"posixGroup", b"top"],
                "cn": [cn.encode()],
                "gidNumber": [str(gid_number).encode()],
            }
        else:
            entry = {
                "objectClass": [b"groupOfNames", b"top"],
                "cn": [cn.encode()],
                # groupOfNames requires at least one member
                "member": [b""],
            }

        if description:
            entry["description"] = [description.encode()]

        add_list = modlist.addModlist(entry)
        backend.add(dn, add_list)
        log.info("Created group %s (%s)", cn, dn)
        return dn

    # ── DELETE ─────────────────────────────────────────────────────
    def delete_group(self, backend: Backend, cn: str) -> None:
        """Delete a group."""
        group = self.get_group(backend, cn)
        if group is None:
            raise ValueError(f"Group '{cn}' not found")
        backend.delete(group.dn)
        log.info("Deleted group %s (%s)", cn, group.dn)

    # ── MEMBERSHIP ─────────────────────────────────────────────────
    def add_member(self, backend: Backend, group_cn: str, uid: str) -> None:
        """Add a user to a group."""
        group = self.get_group(backend, group_cn)
        if group is None:
            raise ValueError(f"Group '{group_cn}' not found")

        if group.is_posix:
            if uid in group.members:
                log.warning("User %s is already a member of %s", uid, group_cn)
                return
            backend.modify(group.dn, [(ldap.MOD_ADD, "memberUid", [uid.encode()])])
        else:
            member_dn = f"uid={uid},{self._lcfg.users_ou}"
            if member_dn in group.members:
                log.warning("User %s is already a member of %s", uid, group_cn)
                return
            backend.modify(group.dn, [(ldap.MOD_ADD, "member", [member_dn.encode()])])

        log.info("Added %s to group %s", uid, group_cn)

    def remove_member(self, backend: Backend, group_cn: str, uid: str) -> None:
        """Remove a user from a group."""
        group = self.get_group(backend, group_cn)
        if group is None:
            raise ValueError(f"Group '{group_cn}' not found")

        if group.is_posix:
            if uid not in group.members:
                raise ValueError(f"User '{uid}' is not a member of group '{group_cn}'")
            backend.modify(group.dn, [(ldap.MOD_DELETE, "memberUid", [uid.encode()])])
        else:
            member_dn = f"uid={uid},{self._lcfg.users_ou}"
            if member_dn not in group.members:
                raise ValueError(f"User '{uid}' is not a member of group '{group_cn}'")
            backend.modify(group.dn, [(ldap.MOD_DELETE, "member", [member_dn.encode()])])

        log.info("Removed %s from group %s", uid, group_cn)

    def get_user_groups(self, backend: Backend, uid: str) -> list[GroupEntry]:
        """Find all groups a user belongs to."""
        member_dn = f"uid={uid},{self._lcfg.users_ou}"
        search_filter = f"(|(&(objectClass=posixGroup)(memberUid={uid}))(&(objectClass=groupOfNames)(member={member_dn})))"
        try:
            results = backend.search(self._lcfg.groups_ou, ldap.SCOPE_SUBTREE, search_filter, _GROUP_ATTRS)
        except ldap.NO_SUCH_OBJECT:
            return []

        groups = []
        for dn, attrs in results:
            if dn is None:
                continue
            groups.append(GroupEntry.from_ldap(dn, attrs))

        return sorted(groups, key=lambda g: g.cn)
