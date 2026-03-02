"""Tests for ldap_manager.tree - TreeManager."""

from __future__ import annotations

from unittest.mock import MagicMock

import ldap
import pytest

from ldap_manager.config import Config
from ldap_manager.tree import TreeManager


@pytest.fixture
def cfg() -> Config:
    return Config()


@pytest.fixture
def mock_conn() -> MagicMock:
    return MagicMock()


@pytest.fixture
def mgr(cfg: Config) -> TreeManager:
    return TreeManager(cfg)


class TestListOUs:
    def test_list_ous_returns_entries(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = [
            [
                ("ou=People,dc=example,dc=com", {"ou": [b"People"], "description": [b"Users"]}),
                ("ou=Groups,dc=example,dc=com", {"ou": [b"Groups"], "description": []}),
            ],
            [],  # children count for People
            [],  # children count for Groups
        ]
        ous = mgr.list_ous(mock_conn)
        assert len(ous) == 2
        assert ous[0].ou == "Groups"  # sorted by DN
        assert ous[1].ou == "People"

    def test_list_ous_empty(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = ldap.NO_SUCH_OBJECT
        ous = mgr.list_ous(mock_conn)
        assert ous == []


class TestCreateOU:
    def test_create_ou(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = ldap.NO_SUCH_OBJECT  # does not exist yet
        dn = mgr.create_ou(mock_conn, "Contractors")
        assert "ou=Contractors" in dn
        mock_conn.add_s.assert_called_once()

    def test_create_ou_already_exists(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [("ou=People,dc=example,dc=com", {})]
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_ou(mock_conn, "People")

    def test_create_ou_with_description(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = ldap.NO_SUCH_OBJECT
        mgr.create_ou(mock_conn, "Vendors", description="External vendors")
        call_args = mock_conn.add_s.call_args[0]
        attrs = dict(call_args[1])
        assert b"External vendors" in attrs.get("description", [])


class TestDeleteOU:
    def test_delete_ou_no_children(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = [
            [("ou=Old,dc=example,dc=com", {})],  # exists check
            [],  # no children
        ]
        count = mgr.delete_ou(mock_conn, "ou=Old,dc=example,dc=com")
        assert count == 1
        mock_conn.delete_s.assert_called_once()

    def test_delete_ou_with_children_raises(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = [
            [("ou=Old,dc=example,dc=com", {})],  # exists
            [("uid=jdoe,ou=Old,dc=example,dc=com", {})],  # has children
        ]
        with pytest.raises(ValueError, match="children"):
            mgr.delete_ou(mock_conn, "ou=Old,dc=example,dc=com")

    def test_delete_ou_recursive(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        ou_dn = "ou=Old,dc=example,dc=com"
        child_dn = "uid=jdoe,ou=Old,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            [(ou_dn, {})],  # exists
            [(child_dn, {})],  # has children
            [(child_dn, {}), (ou_dn, {})],  # subtree search
        ]
        count = mgr.delete_ou(mock_conn, ou_dn, recursive=True)
        assert count == 2

    def test_delete_ou_not_found(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = ldap.NO_SUCH_OBJECT
        with pytest.raises(ValueError, match="not found"):
            mgr.delete_ou(mock_conn, "ou=Ghost,dc=example,dc=com")


class TestTree:
    def test_tree_returns_entries(self, mgr: TreeManager, mock_conn: MagicMock) -> None:
        base = "dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            [(base, {"objectClass": [b"organization", b"top"]})],  # base
            [("ou=People," + base, {})],  # children of base
            [("ou=People," + base, {"objectClass": [b"organizationalUnit"]})],  # People entry
            [],  # children of People
        ]
        result = mgr.tree(mock_conn)
        assert len(result) >= 1
        assert result[0]["dn"] == base
