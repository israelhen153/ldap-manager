"""Shared fixtures for ldap-manager tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ldap_manager.config import (
    BackupConfig,
    Config,
    LDAPConfig,
    PasswordConfig,
    UsersConfig,
)


@pytest.fixture
def cfg() -> Config:
    """Standard test config."""
    return Config(
        ldap=LDAPConfig(
            uri="ldap://localhost",
            bind_dn="cn=admin,dc=test,dc=com",
            bind_password="secret",
            base_dn="dc=test,dc=com",
            users_ou="ou=People,dc=test,dc=com",
            groups_ou="ou=Groups,dc=test,dc=com",
        ),
        users=UsersConfig(
            default_shell="/bin/bash",
            disabled_shell="/sbin/nologin",
            uid_min=10000,
            uid_max=60000,
            default_gid=10000,
            mail_domain="test.com",
            generate_password_on_create=False,
        ),
        backup=BackupConfig(),
        password=PasswordConfig(generated_length=20),
    )


@pytest.fixture
def cfg_autogen(cfg: Config) -> Config:
    """Config with auto-generate password on create enabled."""
    cfg.users.generate_password_on_create = True
    return cfg


@pytest.fixture
def mock_conn() -> MagicMock:
    """Mock LDAPObject."""
    return MagicMock()


def make_ldap_entry(
    uid: str = "jdoe",
    cn: str = "John Doe",
    sn: str = "Doe",
    uid_number: int = 10001,
    shell: str = "/bin/bash",
    mail: str | None = None,
) -> tuple[str, dict[str, list[bytes]]]:
    """Build a fake LDAP search result entry."""
    dn = f"uid={uid},ou=People,dc=test,dc=com"
    attrs: dict[str, list[bytes]] = {
        "uid": [uid.encode()],
        "cn": [cn.encode()],
        "sn": [sn.encode()],
        "givenName": [b"John"],
        "mail": [(mail or f"{uid}@test.com").encode()],
        "uidNumber": [str(uid_number).encode()],
        "gidNumber": [b"10000"],
        "homeDirectory": [f"/home/{uid}".encode()],
        "loginShell": [shell.encode()],
    }
    return dn, attrs
