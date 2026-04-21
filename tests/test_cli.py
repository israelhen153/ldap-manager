"""Tests for ldap_manager.cli using Click's CliRunner."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ldap_manager.cli import main

from .conftest import make_ldap_entry


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestMainHelp:
    def test_help_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "QUICK START" in result.output
        assert "ENVIRONMENT VARIABLES" in result.output

    def test_user_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "--help"])
        assert result.exit_code == 0
        assert "SUBCOMMANDS" in result.output

    def test_user_list_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "list", "--help"])
        assert result.exit_code == 0
        assert "EXAMPLES" in result.output
        assert "--enabled" in result.output

    def test_user_create_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "create", "--help"])
        assert result.exit_code == 0
        assert "EXAMPLES" in result.output
        assert "uid" in result.output.lower()

    def test_user_dump_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "dump", "--help"])
        assert result.exit_code == 0
        assert "OUTPUT FORMAT" in result.output

    def test_user_disable_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "disable", "--help"])
        assert result.exit_code == 0
        assert "NOTES" in result.output

    def test_user_enable_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "enable", "--help"])
        assert result.exit_code == 0
        assert "NOTES" in result.output

    def test_user_delete_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "delete", "--help"])
        assert result.exit_code == 0
        assert "NOTES" in result.output

    def test_user_update_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "update", "--help"])
        assert result.exit_code == 0
        assert "EXAMPLES" in result.output

    def test_user_passwd_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "passwd", "--help"])
        assert result.exit_code == 0
        assert "NOTES" in result.output

    def test_backup_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["backup", "--help"])
        assert result.exit_code == 0
        assert "SUBCOMMANDS" in result.output

    def test_backup_dump_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["backup", "dump", "--help"])
        assert result.exit_code == 0
        assert "EXAMPLES" in result.output

    def test_backup_restore_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["backup", "restore", "--help"])
        assert result.exit_code == 0
        assert "EXIT CODES" in result.output

    def test_batch_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["batch", "--help"])
        assert result.exit_code == 0
        assert "Examples" in result.output

    def test_passwd_all_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["passwd-all", "--help"])
        assert result.exit_code == 0
        assert "OUTPUT FILE" in result.output
        assert "EXAMPLES" in result.output
        # Hardening must be documented, not just implemented.
        assert "--confirm-plaintext" in result.output
        assert "liability" in result.output
        assert "0600" in result.output
        assert "world-readable" in result.output or "parent directory" in result.output

    def test_user_search_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["user", "search", "--help"])
        assert result.exit_code == 0
        assert "EXAMPLES" in result.output
        assert "--filter" in result.output

    def test_group_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["group", "--help"])
        assert result.exit_code == 0
        assert "SUBCOMMANDS" in result.output

    def test_group_list_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["group", "list", "--help"])
        assert result.exit_code == 0
        assert "--json" in result.output

    def test_group_add_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["group", "add", "--help"])
        assert result.exit_code == 0
        assert "NOTES" in result.output

    def test_group_members_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["group", "members", "--help"])
        assert result.exit_code == 0

    def test_group_user_groups_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["group", "user-groups", "--help"])
        assert result.exit_code == 0


class TestUserListCLI:
    @patch("ldap_manager.cli.OpenLDAPBackend")
    @patch("ldap_manager.cli.load_config")
    def test_list_empty(self, mock_cfg: MagicMock, mock_ldap: MagicMock, runner: CliRunner) -> None:
        conn = MagicMock()
        conn.search.return_value = []
        mock_ldap.return_value.__enter__ = MagicMock(return_value=conn)
        mock_ldap.return_value.__exit__ = MagicMock(return_value=False)

        from ldap_manager.config import Config

        mock_cfg.return_value = Config()

        result = runner.invoke(main, ["user", "list"])
        assert "No users found" in result.output

    @patch("ldap_manager.cli.OpenLDAPBackend")
    @patch("ldap_manager.cli.load_config")
    def test_list_json(self, mock_cfg: MagicMock, mock_ldap: MagicMock, runner: CliRunner) -> None:
        conn = MagicMock()
        conn.search.return_value = [make_ldap_entry("alice", "Alice", "A", 10001)]
        mock_ldap.return_value.__enter__ = MagicMock(return_value=conn)
        mock_ldap.return_value.__exit__ = MagicMock(return_value=False)

        from ldap_manager.config import Config

        mock_cfg.return_value = Config()

        result = runner.invoke(main, ["user", "list", "--json"])
        assert result.exit_code == 0
        assert '"alice"' in result.output


class TestUserGetCLI:
    @patch("ldap_manager.cli.OpenLDAPBackend")
    @patch("ldap_manager.cli.load_config")
    def test_get_not_found(self, mock_cfg: MagicMock, mock_ldap: MagicMock, runner: CliRunner) -> None:
        conn = MagicMock()
        conn.search.return_value = []
        mock_ldap.return_value.__enter__ = MagicMock(return_value=conn)
        mock_ldap.return_value.__exit__ = MagicMock(return_value=False)

        from ldap_manager.config import Config

        mock_cfg.return_value = Config()

        result = runner.invoke(main, ["user", "get", "nobody"])
        assert result.exit_code == 1
        assert "not found" in result.output


class TestPasswdAllCLI:
    """Coverage for the hardening behaviours on `passwd-all`."""

    @patch("ldap_manager.cli.OpenLDAPBackend")
    @patch("ldap_manager.cli.load_config")
    def test_summary_only_no_file_no_password_in_stdout(
        self, mock_cfg: MagicMock, mock_ldap: MagicMock, runner: CliRunner, tmp_path
    ) -> None:
        conn = MagicMock()
        conn.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
            make_ldap_entry("bob", "Bob", "B", 10002),
        ]
        mock_ldap.return_value.__enter__ = MagicMock(return_value=conn)
        mock_ldap.return_value.__exit__ = MagicMock(return_value=False)

        from ldap_manager.config import Config

        mock_cfg.return_value = Config()

        result = runner.invoke(main, ["passwd-all", "--yes"])
        assert result.exit_code == 0, result.output
        assert "2 users rotated" in result.output
        assert "zero passwords revealed" in result.output
        # Every modify call took a hashed password; sanity-check none of those
        # raw plaintexts leaked to stdout.
        for call in conn.modify.call_args_list:
            mods = call.args[1]
            for _, _, vals in mods:
                for v in vals:
                    assert v.decode("utf-8", errors="ignore") not in result.output

    @patch("ldap_manager.cli.OpenLDAPBackend")
    @patch("ldap_manager.cli.load_config")
    def test_output_without_confirm_plaintext_is_rejected(
        self, mock_cfg: MagicMock, mock_ldap: MagicMock, runner: CliRunner, tmp_path
    ) -> None:
        conn = MagicMock()
        conn.search.return_value = [make_ldap_entry("alice", "Alice", "A", 10001)]
        mock_ldap.return_value.__enter__ = MagicMock(return_value=conn)
        mock_ldap.return_value.__exit__ = MagicMock(return_value=False)

        from ldap_manager.config import Config

        mock_cfg.return_value = Config()

        out = tmp_path / "pw.csv"
        result = runner.invoke(main, ["passwd-all", "--yes", "--output", str(out)])
        assert result.exit_code != 0
        assert "--confirm-plaintext" in result.output
        assert not out.exists(), "output file must not be created when gate fails"
        conn.modify.assert_not_called()

    @patch("ldap_manager.cli.OpenLDAPBackend")
    @patch("ldap_manager.cli.load_config")
    def test_confirm_plaintext_without_output_is_rejected(
        self, mock_cfg: MagicMock, mock_ldap: MagicMock, runner: CliRunner
    ) -> None:
        conn = MagicMock()
        conn.search.return_value = [make_ldap_entry("alice", "Alice", "A", 10001)]
        mock_ldap.return_value.__enter__ = MagicMock(return_value=conn)
        mock_ldap.return_value.__exit__ = MagicMock(return_value=False)

        from ldap_manager.config import Config

        mock_cfg.return_value = Config()

        result = runner.invoke(main, ["passwd-all", "--yes", "--confirm-plaintext"])
        assert result.exit_code != 0
        assert "--confirm-plaintext requires --output" in result.output
        conn.modify.assert_not_called()

    @patch("ldap_manager.cli.OpenLDAPBackend")
    @patch("ldap_manager.cli.load_config")
    def test_world_readable_parent_dir_exits_nonzero(
        self, mock_cfg: MagicMock, mock_ldap: MagicMock, runner: CliRunner, tmp_path
    ) -> None:
        """A world-readable parent dir must be refused before any LDAP write."""
        conn = MagicMock()
        conn.search.return_value = [make_ldap_entry("alice", "Alice", "A", 10001)]
        mock_ldap.return_value.__enter__ = MagicMock(return_value=conn)
        mock_ldap.return_value.__exit__ = MagicMock(return_value=False)

        from ldap_manager.config import Config

        mock_cfg.return_value = Config()

        wide = tmp_path / "wide"
        wide.mkdir()
        wide.chmod(0o755)
        out = wide / "pw.csv"

        result = runner.invoke(
            main,
            [
                "passwd-all",
                "--yes",
                "--output",
                str(out),
                "--confirm-plaintext",
            ],
        )
        assert result.exit_code != 0
        assert "world-readable" in result.output
        assert str(wide) in result.output
        assert not out.exists()
        conn.modify.assert_not_called()

    @patch("ldap_manager.cli.OpenLDAPBackend")
    @patch("ldap_manager.cli.load_config")
    def test_length_flag_threads_through_to_bulk_reset(
        self, mock_cfg: MagicMock, mock_ldap: MagicMock, runner: CliRunner, tmp_path
    ) -> None:
        """--length N must change the length of passwords written to the manifest."""
        import csv

        conn = MagicMock()
        conn.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
            make_ldap_entry("bob", "Bob", "B", 10002),
        ]
        mock_ldap.return_value.__enter__ = MagicMock(return_value=conn)
        mock_ldap.return_value.__exit__ = MagicMock(return_value=False)

        from ldap_manager.config import Config

        mock_cfg.return_value = Config()

        out = tmp_path / "pw.csv"
        result = runner.invoke(
            main,
            [
                "passwd-all",
                "--yes",
                "--dry-run",
                "--output",
                str(out),
                "--confirm-plaintext",
                "--length",
                "33",
            ],
        )
        assert result.exit_code == 0, result.output
        with open(out) as f:
            rows = list(csv.reader(f))[1:]
        assert rows, "manifest should have at least one row"
        for row in rows:
            assert len(row[2]) == 33
