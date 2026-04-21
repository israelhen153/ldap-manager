"""Tests for ldap_manager.ppolicy - PPasswordManager."""

from __future__ import annotations

from unittest.mock import MagicMock

import ldap
import pytest

from ldap_manager.backends import Backend
from ldap_manager.config import Config
from ldap_manager.ppolicy import PasswordStatus, PolicyConfig, PPasswordManager, _parse_generalized_time


@pytest.fixture
def cfg() -> Config:
    return Config()


@pytest.fixture
def mock_backend() -> MagicMock:
    mock = MagicMock(spec=Backend)
    mock.supports = frozenset()
    return mock


@pytest.fixture
def mgr(cfg: Config) -> PPasswordManager:
    return PPasswordManager(cfg)


def _policy_entry(dn: str = "cn=default,ou=Policies,dc=example,dc=com") -> list:
    return [
        (
            dn,
            {
                "pwdMaxAge": [b"15552000"],
                "pwdMinLength": [b"8"],
                "pwdMaxFailure": [b"5"],
                "pwdLockout": [b"TRUE"],
                "pwdLockoutDuration": [b"3600"],
                "pwdGraceAuthNLimit": [b"3"],
                "pwdMustChange": [b"FALSE"],
                "pwdCheckQuality": [b"1"],
                "pwdInHistory": [b"5"],
            },
        )
    ]


class TestParseGeneralizedTime:
    def test_basic(self) -> None:
        dt = _parse_generalized_time("20240115143022Z")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15

    def test_with_fractional(self) -> None:
        dt = _parse_generalized_time("20240115143022.123Z")
        assert dt is not None
        assert dt.year == 2024

    def test_invalid(self) -> None:
        assert _parse_generalized_time("not-a-date") is None

    def test_empty(self) -> None:
        assert _parse_generalized_time("") is None


class TestGetPolicy:
    def test_get_policy_by_dn(self, mgr: PPasswordManager, mock_backend: MagicMock) -> None:
        mock_backend.search.return_value = _policy_entry()
        policy = mgr.get_policy(mock_backend, "cn=default,ou=Policies,dc=example,dc=com")
        assert policy is not None
        assert policy.max_age == 15552000
        assert policy.min_length == 8
        assert policy.lockout is True
        assert policy.grace_limit == 3

    def test_get_default_policy(self, mgr: PPasswordManager, mock_backend: MagicMock) -> None:
        mock_backend.search.return_value = _policy_entry()
        policy = mgr.get_policy(mock_backend)
        assert policy is not None

    def test_get_policy_not_found(self, mgr: PPasswordManager, mock_backend: MagicMock) -> None:
        mock_backend.search.side_effect = ldap.NO_SUCH_OBJECT
        policy = mgr.get_policy(mock_backend, "cn=ghost,dc=example,dc=com")
        assert policy is None

    def test_policy_to_dict(self) -> None:
        policy = PolicyConfig(
            dn="cn=default",
            max_age=180,
            min_age=0,
            min_length=8,
            max_failure=5,
            lockout=True,
            lockout_duration=3600,
            grace_limit=3,
            must_change=False,
            check_quality=1,
            in_history=5,
        )
        d = policy.to_dict()
        assert d["max_age_seconds"] == 180
        assert d["lockout"] is True


class TestGetUserStatus:
    def test_user_clean(self, mgr: PPasswordManager, mock_backend: MagicMock) -> None:
        mock_backend.search.return_value = [
            (
                "uid=jdoe,ou=People,dc=example,dc=com",
                {
                    "uid": [b"jdoe"],
                    "pwdChangedTime": [b"20240601120000Z"],
                },
            ),
        ]
        status = mgr.get_user_status(mock_backend, "jdoe")
        assert status is not None
        assert status.uid == "jdoe"
        assert status.locked is False
        assert status.failure_count == 0

    def test_user_locked(self, mgr: PPasswordManager, mock_backend: MagicMock) -> None:
        mock_backend.search.return_value = [
            (
                "uid=jdoe,ou=People,dc=example,dc=com",
                {
                    "uid": [b"jdoe"],
                    "pwdAccountLockedTime": [b"20240601120000Z"],
                    "pwdFailureTime": [b"20240601115500Z", b"20240601115800Z"],
                },
            ),
        ]
        status = mgr.get_user_status(mock_backend, "jdoe")
        assert status is not None
        assert status.locked is True
        assert status.failure_count == 2

    def test_user_not_found(self, mgr: PPasswordManager, mock_backend: MagicMock) -> None:
        mock_backend.search.return_value = []
        status = mgr.get_user_status(mock_backend, "nobody")
        assert status is None

    def test_password_status_to_dict(self) -> None:
        status = PasswordStatus(
            uid="jdoe",
            dn="uid=jdoe,ou=People,dc=test",
            changed_time="20240601",
            locked=False,
            locked_time=None,
            failure_count=0,
            must_change=False,
            expires=None,
            grace_remaining=None,
            policy_dn=None,
        )
        d = status.to_dict()
        assert d["uid"] == "jdoe"
        assert d["locked"] is False


class TestCheckAllUsers:
    def test_check_all(self, mgr: PPasswordManager, mock_backend: MagicMock) -> None:
        mock_backend.search.side_effect = [
            [  # check_all_users search
                ("uid=alice,ou=People,dc=example,dc=com", {"uid": [b"alice"]}),
                ("uid=bob,ou=People,dc=example,dc=com", {"uid": [b"bob"]}),
            ],
            # get_user_status for alice
            [("uid=alice,ou=People,dc=example,dc=com", {"uid": [b"alice"]})],
            # get_user_status for bob
            [("uid=bob,ou=People,dc=example,dc=com", {"uid": [b"bob"]})],
        ]
        statuses = mgr.check_all_users(mock_backend)
        assert len(statuses) == 2

    def test_check_all_empty(self, mgr: PPasswordManager, mock_backend: MagicMock) -> None:
        mock_backend.search.side_effect = ldap.NO_SUCH_OBJECT
        statuses = mgr.check_all_users(mock_backend)
        assert statuses == []
