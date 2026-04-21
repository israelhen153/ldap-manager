"""Capability gate behaviour on CLI commands.

Every command that requires a backend-specific feature (slapcat, the
ppolicy overlay, openssh-lpk, etc.) runs through
``_require_capability`` before it touches managers or opens an LDAP
connection. These tests pin the error contract:

* The command exits non-zero.
* The message names the command, the missing capability, and the
  current backend.
* No Python traceback leaks to stderr.

We drive the CLI with the generic backend and the default
:class:`SchemaConfig` (no profile applied, ``supports=frozenset()``),
so every gate trips. That also guards against a future refactor
silently dropping the check.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ldap_manager.cli import main
from ldap_manager.config import Config


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def generic_cfg() -> Config:
    """Config using the generic backend with no profile — empty supports."""
    cfg = Config()
    cfg.backend = "generic"
    return cfg


def _assert_capability_error(result, command: str, capability: str) -> None:
    """Assert the failure has the expected two-line gate format."""
    assert result.exit_code != 0, f"expected non-zero exit, got {result.exit_code}"
    # The gate emits "Error: '<command>' requires capability '<cap>' ..." on stderr.
    assert f"'{command}'" in result.output, f"message should name the command: {result.output}"
    assert f"'{capability}'" in result.output, f"message should name the capability: {result.output}"
    assert "Current backend: 'generic'" in result.output, f"message should name the current backend: {result.output}"
    # No Python traceback should leak — those start with "Traceback (most recent call last)".
    assert "Traceback" not in result.output, f"traceback leaked: {result.output}"


class TestBackupGate:
    """The three backup commands require the 'backup' capability."""

    @patch("ldap_manager.cli.load_config")
    def test_dump_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["backup", "dump"])
        _assert_capability_error(result, "backup dump", "backup")

    @patch("ldap_manager.cli.load_config")
    def test_restore_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["backup", "restore", "/tmp/nowhere", "--yes"])
        _assert_capability_error(result, "backup restore", "backup")

    @patch("ldap_manager.cli.load_config")
    def test_list_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["backup", "list"])
        _assert_capability_error(result, "backup list", "backup")


class TestServerGate:
    """All five server subcommands require 'server_ops'."""

    @pytest.mark.parametrize(
        "args,command",
        [
            (["server", "status"], "server status"),
            (["server", "reindex"], "server reindex"),
            (["server", "start"], "server start"),
            (["server", "stop"], "server stop"),
            (["server", "restart"], "server restart"),
        ],
    )
    @patch("ldap_manager.cli.load_config")
    def test_server_subcommand_rejects_generic(self, mock_load, runner, generic_cfg, args, command):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, args)
        _assert_capability_error(result, command, "server_ops")


class TestPpolicyGate:
    """The three ppolicy subcommands require 'ppolicy_overlay'."""

    @patch("ldap_manager.cli.load_config")
    def test_status_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["ppolicy", "status", "jdoe"])
        _assert_capability_error(result, "ppolicy status", "ppolicy_overlay")

    @patch("ldap_manager.cli.load_config")
    def test_policy_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["ppolicy", "policy"])
        _assert_capability_error(result, "ppolicy policy", "ppolicy_overlay")

    @patch("ldap_manager.cli.load_config")
    def test_check_all_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["ppolicy", "check-all"])
        _assert_capability_error(result, "ppolicy check-all", "ppolicy_overlay")


class TestSSHKeyGate:
    """All three user ssh-key-* subcommands require 'ssh_public_key_schema'."""

    @patch("ldap_manager.cli.load_config")
    def test_list_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["user", "ssh-key-list", "jdoe"])
        _assert_capability_error(result, "user ssh-key-list", "ssh_public_key_schema")

    @patch("ldap_manager.cli.load_config")
    def test_add_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["user", "ssh-key-add", "jdoe", "ssh-ed25519 AAAA... key"])
        _assert_capability_error(result, "user ssh-key-add", "ssh_public_key_schema")

    @patch("ldap_manager.cli.load_config")
    def test_remove_rejects_generic(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["user", "ssh-key-remove", "jdoe", "0"])
        _assert_capability_error(result, "user ssh-key-remove", "ssh_public_key_schema")


class TestOpenLDAPPasses:
    """Sanity check: the default openldap backend has all capabilities.

    These tests must NOT trip the gate. We intercept the manager classes
    so the commands don't try to run slapcat / systemctl / open an LDAP
    connection during the test — the gate check is what we're measuring.
    """

    @patch("ldap_manager.cli.BackupManager")
    @patch("ldap_manager.cli.load_config")
    def test_backup_list_passes_on_openldap(self, mock_load, mock_backup_mgr, runner):
        cfg = Config()  # default backend="openldap"
        mock_load.return_value = cfg
        mock_backup_mgr.return_value.list_backups.return_value = []
        result = runner.invoke(main, ["backup", "list"])
        assert result.exit_code == 0, result.output
        assert "No backups found." in result.output


class TestGateFormat:
    """The error message shape itself matters — operators parse it."""

    @patch("ldap_manager.cli.load_config")
    def test_error_has_reason_parenthetical(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["backup", "dump"])
        # The gate message wraps the reason in parentheses right after
        # the capability name. Pin this shape so future refactors don't
        # silently demote it to a bare sentence.
        assert "(needs slapcat on the LDAP host)" in result.output

    @patch("ldap_manager.cli.load_config")
    def test_error_is_two_lines(self, mock_load, runner, generic_cfg):
        mock_load.return_value = generic_cfg
        result = runner.invoke(main, ["backup", "dump"])
        # The format is deliberately two lines: the capability line and
        # the "Current backend: X" line. Joining them makes grep harder.
        lines = [ln for ln in result.output.splitlines() if ln.startswith(("Error:", "Current backend:"))]
        assert len(lines) == 2, f"expected two structured lines, got: {lines}"
