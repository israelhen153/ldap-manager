"""Tests for ldap_manager.passwords."""

from __future__ import annotations

import csv
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ldap_manager.config import Config
from ldap_manager.passwords import bulk_password_reset

from .conftest import make_ldap_entry


class TestBulkReset:
    def test_dry_run_no_ldap_writes(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
            make_ldap_entry("bob", "Bob B", "B", 10002),
        ]
        output = tmp_path / "passwords.csv"
        csv_path = bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=True)

        assert csv_path.is_file()
        mock_conn.modify_s.assert_not_called()

        with open(csv_path) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 3  # header + 2 users
        assert rows[0] == ["uid", "cn", "new_password"]

    def test_actual_reset(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
        ]
        output = tmp_path / "passwords.csv"
        bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=False)

        assert mock_conn.modify_s.call_count == 1

    def test_csv_permissions(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        mock_conn.search_s.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
        ]
        output = tmp_path / "passwords.csv"
        csv_path = bulk_password_reset(mock_conn, cfg, output_file=output, dry_run=True)
        assert oct(csv_path.stat().st_mode)[-3:] == "600"

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
        csv_path = bulk_password_reset(
            mock_conn,
            cfg,
            output_file=output,
            enabled_only=True,
            dry_run=True,
        )
        with open(csv_path) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 2  # header + alice only
