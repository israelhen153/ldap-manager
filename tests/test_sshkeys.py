"""Tests for ldap_manager.sshkeys - SSHKeyManager."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ldap_manager.config import Config
from ldap_manager.sshkeys import SSHKeyManager


@pytest.fixture
def cfg() -> Config:
    return Config()


@pytest.fixture
def mock_conn() -> MagicMock:
    return MagicMock()


@pytest.fixture
def mgr(cfg: Config) -> SSHKeyManager:
    return SSHKeyManager(cfg)


SAMPLE_KEY_RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1234 user@host"
SAMPLE_KEY_ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI5678 user@host"


def _user_search_result(dn: str = "uid=jdoe,ou=People,dc=example,dc=com") -> list:
    return [(dn, {"objectClass": [b"posixAccount", b"inetOrgPerson"]})]


def _keys_result(dn: str, keys: list[str]) -> list:
    return [(dn, {"sshPublicKey": [k.encode() for k in keys]})]


def _no_keys_result(dn: str) -> list:
    return [(dn, {})]


class TestSSHKeyList:
    def test_list_keys_returns_keys(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        dn = "uid=jdoe,ou=People,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            _user_search_result(dn),
            _keys_result(dn, [SAMPLE_KEY_RSA, SAMPLE_KEY_ED25519]),
        ]
        keys = mgr.list_keys(mock_conn, "jdoe")
        assert len(keys) == 2
        assert SAMPLE_KEY_RSA in keys

    def test_list_keys_empty(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        dn = "uid=jdoe,ou=People,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            _user_search_result(dn),
            _no_keys_result(dn),
        ]
        keys = mgr.list_keys(mock_conn, "jdoe")
        assert keys == []

    def test_list_keys_user_not_found(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        mock_conn.search_s.return_value = []
        with pytest.raises(ValueError, match="not found"):
            mgr.list_keys(mock_conn, "nobody")


class TestSSHKeyAdd:
    def test_add_key_valid(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        dn = "uid=jdoe,ou=People,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            _user_search_result(dn),  # _get_user_dn
            _user_search_result(dn),  # list_keys -> _get_user_dn
            _no_keys_result(dn),  # list_keys -> search for keys
            [(dn, {"objectClass": [b"posixAccount"]})],  # _ensure_objectclass
        ]
        mgr.add_key(mock_conn, "jdoe", SAMPLE_KEY_RSA)
        mock_conn.modify_s.assert_called()

    def test_add_key_empty_raises(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        with pytest.raises(ValueError, match="Empty key"):
            mgr.add_key(mock_conn, "jdoe", "")

    def test_add_key_invalid_format(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        with pytest.raises(ValueError, match="Invalid SSH key format"):
            mgr.add_key(mock_conn, "jdoe", "not-a-key")

    def test_add_key_unknown_type(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        with pytest.raises(ValueError, match="Unknown key type"):
            mgr.add_key(mock_conn, "jdoe", "ssh-fake AAAAB3 comment")


class TestSSHKeyRemove:
    def test_remove_key_by_index(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        dn = "uid=jdoe,ou=People,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            _user_search_result(dn),  # list_keys -> _get_user_dn
            _keys_result(dn, [SAMPLE_KEY_RSA, SAMPLE_KEY_ED25519]),  # list_keys
            _user_search_result(dn),  # _get_user_dn for remove
        ]
        removed = mgr.remove_key(mock_conn, "jdoe", 0)
        assert removed == SAMPLE_KEY_RSA

    def test_remove_key_out_of_range(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        dn = "uid=jdoe,ou=People,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            _user_search_result(dn),
            _keys_result(dn, [SAMPLE_KEY_RSA]),
        ]
        with pytest.raises(ValueError, match="out of range"):
            mgr.remove_key(mock_conn, "jdoe", 5)

    def test_remove_key_no_keys(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        dn = "uid=jdoe,ou=People,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            _user_search_result(dn),
            _no_keys_result(dn),
        ]
        with pytest.raises(ValueError, match="no SSH keys"):
            mgr.remove_key(mock_conn, "jdoe", 0)


class TestSSHKeyRemoveAll:
    def test_remove_all(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        dn = "uid=jdoe,ou=People,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            _user_search_result(dn),
            _keys_result(dn, [SAMPLE_KEY_RSA, SAMPLE_KEY_ED25519]),
            _user_search_result(dn),
        ]
        count = mgr.remove_all_keys(mock_conn, "jdoe")
        assert count == 2

    def test_remove_all_empty(self, mgr: SSHKeyManager, mock_conn: MagicMock) -> None:
        dn = "uid=jdoe,ou=People,dc=example,dc=com"
        mock_conn.search_s.side_effect = [
            _user_search_result(dn),
            _no_keys_result(dn),
        ]
        count = mgr.remove_all_keys(mock_conn, "jdoe")
        assert count == 0
