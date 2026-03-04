"""Tests for ldap_manager.check — config and connectivity checks."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import ldap
import pytest

from ldap_manager.check import (
    CheckResult,
    _check_bind,
    _check_config_file,
    _check_dn_exists,
    _check_uri_reachable,
    _friendly_connect_error,
    run_all_checks,
)
from ldap_manager.config import Config, LDAPConfig


@pytest.fixture
def cfg() -> Config:
    return Config()


@pytest.fixture
def lcfg() -> LDAPConfig:
    return LDAPConfig()


class TestCheckResult:
    def test_to_dict_passed(self) -> None:
        r = CheckResult(name="Test", detail="some detail", passed=True)
        d = r.to_dict()
        assert d["name"] == "Test"
        assert d["passed"] is True
        assert "skipped" not in d
        assert "error" not in d

    def test_to_dict_failed(self) -> None:
        r = CheckResult(name="Test", detail="x", passed=False, error="broke")
        d = r.to_dict()
        assert d["passed"] is False
        assert d["error"] == "broke"

    def test_to_dict_skipped(self) -> None:
        r = CheckResult(name="Test", detail="x", passed=False, skipped=True, error="dep failed")
        d = r.to_dict()
        assert d["skipped"] is True


class TestCheckConfigFile:
    def test_explicit_path_exists(self, tmp_path) -> None:
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("ldap:\n  uri: ldap://localhost\n")
        result = _check_config_file(str(cfg_file))
        assert result.passed is True
        assert str(cfg_file) in result.detail

    def test_no_config_file_still_passes(self) -> None:
        result = _check_config_file("/nonexistent/path/config.yaml")
        # No file found but defaults + env vars work
        assert result.passed is True

    def test_none_path_uses_defaults(self) -> None:
        result = _check_config_file(None)
        assert result.passed is True


class TestCheckUriReachable:
    @patch("ldap_manager.check.socket.create_connection")
    def test_reachable(self, mock_conn: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn.return_value = MagicMock()
        result = _check_uri_reachable(lcfg)
        assert result.passed is True

    @patch("ldap_manager.check.socket.create_connection")
    def test_connection_refused(self, mock_conn: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn.side_effect = ConnectionRefusedError()
        result = _check_uri_reachable(lcfg)
        assert result.passed is False
        assert "slapd running" in result.error

    @patch("ldap_manager.check.socket.create_connection")
    def test_timeout(self, mock_conn: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn.side_effect = TimeoutError()
        result = _check_uri_reachable(lcfg)
        assert result.passed is False
        assert "timed out" in result.error

    @patch("ldap_manager.check.socket.create_connection")
    def test_dns_failure(self, mock_conn: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn.side_effect = socket.gaierror()
        result = _check_uri_reachable(lcfg)
        assert result.passed is False
        assert "resolve" in result.error

    def test_ldaps_default_port(self) -> None:
        lcfg = LDAPConfig(uri="ldaps://ldap.example.com")
        with patch("ldap_manager.check.socket.create_connection") as mock_conn:
            mock_conn.return_value = MagicMock()
            _check_uri_reachable(lcfg)
            mock_conn.assert_called_once_with(("ldap.example.com", 636), timeout=10)


class TestCheckBind:
    @patch("ldap_manager.check.ldap.initialize")
    def test_bind_success(self, mock_init: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_init.return_value = mock_conn
        result = _check_bind(lcfg)
        assert result.passed is True
        mock_conn.simple_bind_s.assert_called_once()
        mock_conn.unbind_s.assert_called_once()

    @patch("ldap_manager.check.ldap.initialize")
    def test_bind_invalid_credentials(self, mock_init: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS
        mock_init.return_value = mock_conn
        result = _check_bind(lcfg)
        assert result.passed is False
        assert "credentials" in result.error.lower()

    @patch("ldap_manager.check.ldap.initialize")
    def test_bind_server_down(self, mock_init: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.simple_bind_s.side_effect = ldap.SERVER_DOWN
        mock_init.return_value = mock_conn
        result = _check_bind(lcfg)
        assert result.passed is False
        assert "down" in result.error.lower()


class TestCheckDnExists:
    @patch("ldap_manager.check.ldap.initialize")
    def test_dn_exists(self, mock_init: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.search_s.return_value = [("dc=example,dc=com", {})]
        mock_init.return_value = mock_conn
        result = _check_dn_exists(lcfg, "Base DN", "dc=example,dc=com")
        assert result.passed is True

    @patch("ldap_manager.check.ldap.initialize")
    def test_dn_not_found(self, mock_init: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.search_s.side_effect = ldap.NO_SUCH_OBJECT
        mock_init.return_value = mock_conn
        result = _check_dn_exists(lcfg, "Base DN", "dc=ghost,dc=com")
        assert result.passed is False
        assert "not found" in result.error.lower()

    @patch("ldap_manager.check.ldap.initialize")
    def test_dn_insufficient_access(self, mock_init: MagicMock, lcfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.search_s.side_effect = ldap.INSUFFICIENT_ACCESS
        mock_init.return_value = mock_conn
        result = _check_dn_exists(lcfg, "Users OU", "ou=People,dc=example,dc=com")
        assert result.passed is False
        assert "permission" in result.error.lower()


class TestRunAllChecks:
    @patch("ldap_manager.check._check_dn_exists")
    @patch("ldap_manager.check._check_bind")
    @patch("ldap_manager.check._check_uri_reachable")
    def test_all_pass(self, mock_uri, mock_bind, mock_dn, cfg: Config) -> None:
        mock_uri.return_value = CheckResult(name="LDAP URI", detail="ldap://localhost", passed=True)
        mock_bind.return_value = CheckResult(name="Bind DN", detail="cn=admin", passed=True)
        mock_dn.return_value = CheckResult(name="DN", detail="dc=test", passed=True)
        results = run_all_checks(cfg)
        passed = [r for r in results if r.passed]
        assert len(passed) == len(results)

    @patch("ldap_manager.check._check_uri_reachable")
    def test_uri_fail_skips_rest(self, mock_uri, cfg: Config) -> None:
        mock_uri.return_value = CheckResult(name="LDAP URI", detail="ldap://localhost", passed=False, error="refused")
        results = run_all_checks(cfg)
        skipped = [r for r in results if r.skipped]
        # Bind + Base DN + Users OU + Groups OU = 4 skipped
        assert len(skipped) == 4

    @patch("ldap_manager.check._check_bind")
    @patch("ldap_manager.check._check_uri_reachable")
    def test_bind_fail_skips_dn_checks(self, mock_uri, mock_bind, cfg: Config) -> None:
        mock_uri.return_value = CheckResult(name="LDAP URI", detail="ldap://localhost", passed=True)
        mock_bind.return_value = CheckResult(name="Bind DN", detail="cn=admin", passed=False, error="bad creds")
        results = run_all_checks(cfg)
        skipped = [r for r in results if r.skipped]
        # Base DN + Users OU + Groups OU = 3 skipped
        assert len(skipped) == 3


class TestFriendlyConnectError:
    def test_timeout(self) -> None:
        msg = _friendly_connect_error(TimeoutError(), "ldap.local", 389)
        assert "timed out" in msg

    def test_dns(self) -> None:
        msg = _friendly_connect_error(socket.gaierror(), "bad.host", 389)
        assert "resolve" in msg

    def test_refused(self) -> None:
        msg = _friendly_connect_error(ConnectionRefusedError(), "localhost", 389)
        assert "slapd running" in msg

    def test_generic(self) -> None:
        msg = _friendly_connect_error(OSError("weird"), "localhost", 389)
        assert "weird" in msg
