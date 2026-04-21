"""Tests for ldap_manager.passwords."""

from __future__ import annotations

import csv
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ldap_manager.config import Config
from ldap_manager.passwords import BulkResetResult, InsecureOutputDirError, bulk_password_reset

from .conftest import make_ldap_entry


class TestBulkReset:
    def test_dry_run_no_ldap_writes(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
            make_ldap_entry("bob", "Bob B", "B", 10002),
        ]
        output = tmp_path / "passwords.csv"
        result = bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=True)

        assert isinstance(result, BulkResetResult)
        assert result.output_path == output
        assert result.output_path.is_file()
        assert result.rotated == 2
        mock_conn.modify_s.assert_not_called()

        with open(result.output_path) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 3  # header + 2 users
        assert rows[0] == ["uid", "cn", "new_password"]

    def test_actual_reset(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
        ]
        output = tmp_path / "passwords.csv"
        result = bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=False)

        assert result.rotated == 1
        assert mock_conn.modify_s.call_count == 1

    def test_csv_permissions(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
        ]
        output = tmp_path / "passwords.csv"
        result = bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=True)
        assert result.output_path is not None
        assert oct(result.output_path.stat().st_mode)[-3:] == "600"

    def test_no_users_raises(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        mock_conn.search_s.return_value = []
        with pytest.raises(RuntimeError, match="No users found"):
            bulk_password_reset(mock_conn, cfg, output_file=tmp_path / "x.csv")

    def test_enabled_only_skips_disabled(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001, shell="/bin/bash"),
            make_ldap_entry("bob", "Bob", "B", 10002, shell="/sbin/nologin"),
        ]
        output = tmp_path / "passwords.csv"
        result = bulk_password_reset(
            mock_conn,
            cfg,
            output_file=output,
            enabled_only=True,
            dry_run=True,
        )
        assert result.rotated == 1
        assert result.output_path is not None
        with open(result.output_path) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 2  # header + alice only

    def test_summary_only_no_file_written(self, cfg: Config, mock_conn: MagicMock) -> None:
        """Without output_file the function rotates passwords and drops them."""
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
            make_ldap_entry("bob", "Bob", "B", 10002),
        ]
        result = bulk_password_reset(mock_conn, cfg, output_file=None, dry_run=False)

        assert result.output_path is None
        assert result.rotated == 2
        # Both users had modify_s called — passwords applied, just not written anywhere.
        assert mock_conn.modify_s.call_count == 2

    def test_generated_passwords_are_unique(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        """Each user must get a distinct random password, not a shared default."""
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
            make_ldap_entry("bob", "Bob", "B", 10002),
            make_ldap_entry("carol", "Carol", "C", 10003),
        ]
        output = tmp_path / "pw.csv"
        bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=True)

        with open(output) as f:
            rows = list(csv.reader(f))[1:]  # skip header
        passwords = [row[2] for row in rows]
        assert len(set(passwords)) == len(passwords), "passwords collided"

    def test_output_file_mode_is_0o600(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        """Permission must be exactly 0600 even under a permissive umask."""
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
        ]
        output = tmp_path / "pw.csv"
        # Force a wide umask — the implementation must chmod regardless.
        old_umask = os.umask(0)
        try:
            bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=True)
        finally:
            os.umask(old_umask)

        assert output.stat().st_mode & 0o777 == 0o600

    def test_world_readable_parent_is_refused(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        """If the parent dir has o+r, refuse before writing anything."""
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
        ]
        parent = tmp_path / "wide"
        parent.mkdir()
        parent.chmod(0o755)  # world-readable
        output = parent / "pw.csv"

        with pytest.raises(InsecureOutputDirError, match="world-readable"):
            bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=False)

        assert not output.exists(), "file must not be created"
        mock_conn.modify_s.assert_not_called()
