"""Tests for ldap_manager.groups."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ldap_manager.config import Config
from ldap_manager.groups import GroupEntry, GroupManager


def _make_posix_group(
    cn: str = "developers",
    gid: int = 20000,
    members: list[str] | None = None,
) -> tuple[str, dict[str, list[bytes]]]:
    dn = f"cn={cn},ou=Groups,dc=test,dc=com"
    attrs: dict[str, list[bytes]] = {
        "cn": [cn.encode()],
        "gidNumber": [str(gid).encode()],
        "objectClass": [b"posixGroup", b"top"],
        "description": [b"A dev group"],
    }
    if members:
        attrs["memberUid"] = [m.encode() for m in members]
    return dn, attrs


def _make_gon_group(
    cn: str = "admins",
    members_dn: list[str] | None = None,
) -> tuple[str, dict[str, list[bytes]]]:
    dn = f"cn={cn},ou=Groups,dc=test,dc=com"
    attrs: dict[str, list[bytes]] = {
        "cn": [cn.encode()],
        "gidNumber": [b"30000"],
        "objectClass": [b"groupOfNames", b"top"],
    }
    if members_dn:
        attrs["member"] = [m.encode() for m in members_dn]
    return dn, attrs


class TestGroupEntry:
    def test_posix_group(self) -> None:
        dn, attrs = _make_posix_group(members=["alice", "bob"])
        g = GroupEntry.from_ldap(dn, attrs)
        assert g.cn == "developers"
        assert g.is_posix is True
        assert g.members == ["alice", "bob"]

    def test_groupofnames(self) -> None:
        dn, attrs = _make_gon_group(members_dn=["uid=alice,ou=People,dc=test,dc=com"])
        g = GroupEntry.from_ldap(dn, attrs)
        assert g.is_posix is False
        assert len(g.members) == 1

    def test_to_dict(self) -> None:
        dn, attrs = _make_posix_group(members=["alice"])
        g = GroupEntry.from_ldap(dn, attrs)
        d = g.to_dict()
        assert d["cn"] == "developers"
        assert d["member_count"] == 1
        assert d["type"] == "posixGroup"


class TestGroupManagerRead:
    def test_get_group(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [_make_posix_group()]
        mgr = GroupManager(cfg)
        g = mgr.get_group(mock_conn, "developers")
        assert g is not None
        assert g.cn == "developers"

    def test_get_group_not_found(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = GroupManager(cfg)
        assert mgr.get_group(mock_conn, "nope") is None

    def test_list_groups(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [
            _make_posix_group("alpha", 20000),
            _make_posix_group("beta", 20001),
        ]
        mgr = GroupManager(cfg)
        groups = mgr.list_groups(mock_conn)
        assert len(groups) == 2
        assert groups[0].cn == "alpha"


class TestGroupManagerWrite:
    def test_create_posix(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = GroupManager(cfg)
        dn = mgr.create_group(mock_conn, "newgroup", 25000)
        assert "newgroup" in dn
        mock_conn.add_s.assert_called_once()

    def test_create_duplicate_raises(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [_make_posix_group()]
        mgr = GroupManager(cfg)
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_group(mock_conn, "developers", 20000)

    def test_delete_group(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [_make_posix_group()]
        mgr = GroupManager(cfg)
        mgr.delete_group(mock_conn, "developers")
        mock_conn.delete_s.assert_called_once()

    def test_delete_not_found(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = GroupManager(cfg)
        with pytest.raises(ValueError, match="not found"):
            mgr.delete_group(mock_conn, "nope")


class TestGroupMembership:
    def test_add_member_posix(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [_make_posix_group(members=[])]
        mgr = GroupManager(cfg)
        mgr.add_member(mock_conn, "developers", "jdoe")
        mock_conn.modify_s.assert_called_once()

    def test_add_member_already_exists(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [_make_posix_group(members=["jdoe"])]
        mgr = GroupManager(cfg)
        mgr.add_member(mock_conn, "developers", "jdoe")
        mock_conn.modify_s.assert_not_called()

    def test_remove_member_posix(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [_make_posix_group(members=["jdoe"])]
        mgr = GroupManager(cfg)
        mgr.remove_member(mock_conn, "developers", "jdoe")
        mock_conn.modify_s.assert_called_once()

    def test_remove_nonmember_raises(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [_make_posix_group(members=["alice"])]
        mgr = GroupManager(cfg)
        with pytest.raises(ValueError, match="not a member"):
            mgr.remove_member(mock_conn, "developers", "jdoe")

    def test_get_user_groups(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [
            _make_posix_group("devs", 20000, ["jdoe"]),
            _make_posix_group("ops", 20001, ["jdoe"]),
        ]
        mgr = GroupManager(cfg)
        groups = mgr.get_user_groups(mock_conn, "jdoe")
        assert len(groups) == 2
