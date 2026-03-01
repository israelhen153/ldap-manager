"""Tests for ldap_manager.users."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ldap_manager.config import Config
from ldap_manager.users import UserEntry, UserManager, _hash_password

from .conftest import make_ldap_entry


class TestUserEntry:
    def test_from_ldap_enabled(self) -> None:
        dn, attrs = make_ldap_entry(shell="/bin/bash")
        user = UserEntry.from_ldap(dn, attrs)
        assert user.uid == "jdoe"
        assert user.cn == "John Doe"
        assert user.enabled is True

    def test_from_ldap_disabled_nologin(self) -> None:
        dn, attrs = make_ldap_entry(shell="/sbin/nologin")
        user = UserEntry.from_ldap(dn, attrs)
        assert user.enabled is False

    def test_from_ldap_disabled_false(self) -> None:
        dn, attrs = make_ldap_entry(shell="/bin/false")
        user = UserEntry.from_ldap(dn, attrs)
        assert user.enabled is False

    def test_from_ldap_disabled_usr_sbin(self) -> None:
        dn, attrs = make_ldap_entry(shell="/usr/sbin/nologin")
        user = UserEntry.from_ldap(dn, attrs)
        assert user.enabled is False

    def test_from_ldap_missing_attrs(self) -> None:
        dn = "uid=sparse,ou=People,dc=test,dc=com"
        attrs: dict[str, list[bytes]] = {"uid": [b"sparse"]}
        user = UserEntry.from_ldap(dn, attrs)
        assert user.uid == "sparse"
        assert user.cn == ""
        assert user.uid_number == 0
        assert user.enabled is True  # default shell is /bin/bash


class TestUserManagerRead:
    def test_get_user_found(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry()]
        mgr = UserManager(cfg)
        user = mgr.get_user(mock_conn, "jdoe")
        assert user is not None
        assert user.uid == "jdoe"

    def test_get_user_not_found(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = UserManager(cfg)
        assert mgr.get_user(mock_conn, "nobody") is None

    def test_get_user_none_dn(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [(None, {})]
        mgr = UserManager(cfg)
        assert mgr.get_user(mock_conn, "ghost") is None

    def test_list_users_all(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
            make_ldap_entry("bob", "Bob B", "B", 10002, shell="/sbin/nologin"),
        ]
        mgr = UserManager(cfg)
        users = mgr.list_users(mock_conn)
        assert len(users) == 2

    def test_list_users_enabled_only(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
            make_ldap_entry("bob", "Bob B", "B", 10002, shell="/sbin/nologin"),
        ]
        mgr = UserManager(cfg)
        users = mgr.list_users(mock_conn, enabled_only=True)
        assert len(users) == 1
        assert users[0].uid == "alice"

    def test_list_users_disabled_only(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
            make_ldap_entry("bob", "Bob B", "B", 10002, shell="/sbin/nologin"),
        ]
        mgr = UserManager(cfg)
        users = mgr.list_users(mock_conn, disabled_only=True)
        assert len(users) == 1
        assert users[0].uid == "bob"

    def test_list_users_sorted(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("zara", "Zara Z", "Z", 10003),
            make_ldap_entry("alice", "Alice A", "A", 10001),
        ]
        mgr = UserManager(cfg)
        users = mgr.list_users(mock_conn)
        assert users[0].uid == "alice"
        assert users[1].uid == "zara"


class TestUserManagerCreate:
    def test_create_minimal(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = [[], []]  # get_user, _next_uid_number
        mgr = UserManager(cfg)
        dn, pw = mgr.create_user(mock_conn, "newuser")
        assert "newuser" in dn
        assert pw == "123456"
        mock_conn.add_s.assert_called_once()

    def test_create_autogen_password(self, cfg_autogen: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = [[], []]
        mgr = UserManager(cfg_autogen)
        _, pw = mgr.create_user(mock_conn, "newuser")
        assert pw is not None
        assert len(pw) == 6

    def test_create_explicit_password_overrides_autogen(self, cfg_autogen: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = [[], []]
        mgr = UserManager(cfg_autogen)
        _, pw = mgr.create_user(mock_conn, "newuser", explicit_password="explicit123!")
        assert pw == "explicit123!"  # not auto-generated

    def test_create_duplicate_raises(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry("existing")]
        mgr = UserManager(cfg)
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_user(mock_conn, "existing")

    def test_create_with_all_overrides(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.side_effect = [[], []]
        mgr = UserManager(cfg)
        dn, _ = mgr.create_user(
            mock_conn,
            "full",
            cn="Full User",
            sn="User",
            given_name="Full",
            mail="custom@other.com",
            uid_number=99999,
            gid_number=99999,
            home_directory="/opt/full",
            login_shell="/bin/zsh",
        )
        assert "full" in dn


class TestUserManagerModify:
    def test_update_user(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry()]
        mgr = UserManager(cfg)
        mgr.update_user(mock_conn, "jdoe", mail="new@test.com")
        mock_conn.modify_s.assert_called_once()

    def test_update_nonexistent_raises(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = UserManager(cfg)
        with pytest.raises(ValueError, match="not found"):
            mgr.update_user(mock_conn, "ghost", mail="x")

    def test_update_empty_noop(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry()]
        mgr = UserManager(cfg)
        mgr.update_user(mock_conn, "jdoe")
        mock_conn.modify_s.assert_not_called()

    def test_delete_user(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry()]
        mgr = UserManager(cfg)
        mgr.delete_user(mock_conn, "jdoe")
        mock_conn.delete_s.assert_called_once()

    def test_delete_nonexistent_raises(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = UserManager(cfg)
        with pytest.raises(ValueError, match="not found"):
            mgr.delete_user(mock_conn, "ghost")

    def test_disable_user(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry(shell="/bin/bash")]
        mgr = UserManager(cfg)
        mgr.disable_user(mock_conn, "jdoe")
        call_args = mock_conn.modify_s.call_args[0][1]
        assert b"/sbin/nologin" in call_args[0][2]

    def test_disable_already_disabled(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry(shell="/sbin/nologin")]
        mgr = UserManager(cfg)
        mgr.disable_user(mock_conn, "jdoe")
        mock_conn.modify_s.assert_not_called()

    def test_enable_user(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry(shell="/sbin/nologin")]
        mgr = UserManager(cfg)
        mgr.enable_user(mock_conn, "jdoe")
        call_args = mock_conn.modify_s.call_args[0][1]
        assert b"/bin/bash" in call_args[0][2]

    def test_enable_already_enabled(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry(shell="/bin/bash")]
        mgr = UserManager(cfg)
        mgr.enable_user(mock_conn, "jdoe")
        mock_conn.modify_s.assert_not_called()

    def test_set_password(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry()]
        mgr = UserManager(cfg)
        mgr.set_password(mock_conn, "jdoe", "newpass123")
        mock_conn.modify_s.assert_called_once()
        mod_val = mock_conn.modify_s.call_args[0][1][0][2][0]
        assert mod_val.startswith(b"{SSHA}")


class TestPasswordHashing:
    def test_ssha_format(self) -> None:
        hashed = _hash_password("testpass")
        assert hashed.startswith(b"{SSHA}")

    def test_different_passwords_different_hashes(self) -> None:
        h1 = _hash_password("pass1")
        h2 = _hash_password("pass2")
        assert h1 != h2

    def test_same_password_different_salt(self) -> None:
        h1 = _hash_password("samepass")
        h2 = _hash_password("samepass")
        assert h1 != h2  # salt differs


class TestUserManagerSearch:
    def test_search_by_gid(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
        ]
        mgr = UserManager(cfg)
        users = mgr.search_users(mock_conn, gid=10000)
        assert len(users) == 1
        # Verify the filter included gidNumber
        call_filter = mock_conn.search_s.call_args[0][2]
        assert "gidNumber=10000" in call_filter

    def test_search_by_mail_wildcard(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [make_ldap_entry("jdoe")]
        mgr = UserManager(cfg)
        mgr.search_users(mock_conn, mail="*@test.com")
        call_filter = mock_conn.search_s.call_args[0][2]
        assert "mail=*@test.com" in call_filter

    def test_search_raw_filter(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = UserManager(cfg)
        mgr.search_users(mock_conn, ldap_filter="(description=contractor*)")
        call_filter = mock_conn.search_s.call_args[0][2]
        assert "(description=contractor*)" in call_filter

    def test_search_raw_filter_auto_parens(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = UserManager(cfg)
        mgr.search_users(mock_conn, ldap_filter="description=temp")
        call_filter = mock_conn.search_s.call_args[0][2]
        assert "(description=temp)" in call_filter

    def test_search_combined(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = UserManager(cfg)
        mgr.search_users(mock_conn, gid=10000, mail="*@corp.com", shell="/bin/bash")
        call_filter = mock_conn.search_s.call_args[0][2]
        assert "gidNumber=10000" in call_filter
        assert "mail=*@corp.com" in call_filter
        assert "loginShell=/bin/bash" in call_filter

    def test_search_enabled_only(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", shell="/bin/bash"),
            make_ldap_entry("bob", shell="/sbin/nologin"),
        ]
        mgr = UserManager(cfg)
        users = mgr.search_users(mock_conn, enabled_only=True)
        assert len(users) == 1
        assert users[0].uid == "alice"

    def test_search_no_results(self, cfg: Config, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        mgr = UserManager(cfg)
        users = mgr.search_users(mock_conn, uid="nobody*")
        assert users == []
