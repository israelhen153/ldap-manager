"""Organizational Unit (OU) and DIT tree management.

Create, delete, list, and move OUs and arbitrary entries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import ldap
from ldap.ldapobject import LDAPObject

from .config import Config

log = logging.getLogger(__name__)


@dataclass
class OUEntry:
    """Representation of an organizationalUnit."""

    dn: str
    ou: str
    description: str
    children_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "dn": self.dn,
            "ou": self.ou,
            "description": self.description,
            "children_count": self.children_count,
        }


class TreeManager:
    """Manage the DIT tree structure."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._lcfg = cfg.ldap

    # ── LIST OUs ───────────────────────────────────────────────────
    def list_ous(
        self,
        conn: LDAPObject,
        base_dn: str | None = None,
    ) -> list[OUEntry]:
        """List all organizationalUnits under a base DN."""
        if base_dn is None:
            base_dn = self._lcfg.base_dn

        try:
            results = conn.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                "(objectClass=organizationalUnit)",
                ["ou", "description"],
            )
        except ldap.NO_SUCH_OBJECT:
            return []

        ous = []
        for dn, attrs in results:
            if dn is None:
                continue

            ou_vals = attrs.get("ou", [])
            ou_name = ou_vals[0].decode("utf-8") if ou_vals else ""

            desc_vals = attrs.get("description", [])
            desc = desc_vals[0].decode("utf-8") if desc_vals else ""

            # Count direct children
            children = 0
            try:
                child_results = conn.search_s(dn, ldap.SCOPE_ONELEVEL, "(objectClass=*)", ["dn"])
                children = len([r for r in child_results if r[0] is not None])
            except ldap.NO_SUCH_OBJECT:
                pass

            ous.append(OUEntry(dn=dn, ou=ou_name, description=desc, children_count=children))

        return sorted(ous, key=lambda o: o.dn)

    # ── CREATE OU ──────────────────────────────────────────────────
    def create_ou(
        self,
        conn: LDAPObject,
        ou_name: str,
        parent_dn: str | None = None,
        description: str = "",
    ) -> str:
        """Create an organizationalUnit. Returns the DN."""
        if parent_dn is None:
            parent_dn = self._lcfg.base_dn

        dn = f"ou={ou_name},{parent_dn}"

        # Check if already exists
        try:
            conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["dn"])
            raise ValueError(f"OU '{dn}' already exists")
        except ldap.NO_SUCH_OBJECT:
            pass

        entry = [
            ("objectClass", [b"organizationalUnit", b"top"]),
            ("ou", [ou_name.encode()]),
        ]
        if description:
            entry.append(("description", [description.encode()]))

        conn.add_s(dn, entry)
        log.info("Created OU: %s", dn)
        return dn

    # ── DELETE OU ──────────────────────────────────────────────────
    def delete_ou(
        self,
        conn: LDAPObject,
        dn: str,
        *,
        recursive: bool = False,
    ) -> int:
        """Delete an OU.

        Args:
            dn: Full DN of the OU
            recursive: Delete children first. If False and OU has children,
                      raises ValueError.

        Returns:
            Number of entries deleted.
        """
        # Check it exists
        try:
            conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["dn"])
        except ldap.NO_SUCH_OBJECT:
            raise ValueError(f"OU '{dn}' not found")

        # Check for children
        children = conn.search_s(dn, ldap.SCOPE_ONELEVEL, "(objectClass=*)", ["dn"])
        children = [c for c in children if c[0] is not None]

        if children and not recursive:
            raise ValueError(f"OU '{dn}' has {len(children)} children. Use --recursive to delete them all.")

        count = 0
        if recursive:
            # Delete deepest entries first (reverse sort by DN length)
            all_entries = conn.search_s(dn, ldap.SCOPE_SUBTREE, "(objectClass=*)", ["dn"])
            all_entries = [e for e in all_entries if e[0] is not None]
            # Sort longest DN first (deepest entries)
            all_entries.sort(key=lambda e: len(e[0]), reverse=True)

            for entry_dn, _ in all_entries:
                conn.delete_s(entry_dn)
                count += 1
                log.debug("Deleted: %s", entry_dn)
        else:
            conn.delete_s(dn)
            count = 1

        log.info("Deleted %d entries under %s", count, dn)
        return count

    # ── TREE VIEW ──────────────────────────────────────────────────
    def tree(
        self,
        conn: LDAPObject,
        base_dn: str | None = None,
        max_depth: int = 3,
    ) -> list[dict[str, Any]]:
        """Build a tree representation of the DIT.

        Returns a list of entries with depth information.
        """
        if base_dn is None:
            base_dn = self._lcfg.base_dn

        result: list[dict[str, Any]] = []
        self._walk_tree(conn, base_dn, 0, max_depth, result)
        return result

    def _walk_tree(
        self,
        conn: LDAPObject,
        dn: str,
        depth: int,
        max_depth: int,
        result: list[dict[str, Any]],
    ) -> None:
        """Recursively walk the DIT."""
        if depth > max_depth:
            return

        try:
            entries = conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["objectClass"])
        except ldap.NO_SUCH_OBJECT:
            return

        if entries and entries[0][0] is not None:
            ocs = [v.decode("utf-8") for v in entries[0][1].get("objectClass", [])]
            result.append({"dn": dn, "depth": depth, "object_classes": ocs})

        # Get direct children
        try:
            children = conn.search_s(dn, ldap.SCOPE_ONELEVEL, "(objectClass=*)", ["dn"])
        except ldap.NO_SUCH_OBJECT:
            return

        for child_dn, _ in sorted(children, key=lambda e: e[0] or ""):
            if child_dn is not None:
                self._walk_tree(conn, child_dn, depth + 1, max_depth, result)
