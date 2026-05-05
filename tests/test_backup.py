"""Tests for ldap_manager.backup."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ldap_manager.backup import BackupManager, DatabasePopulatedError
from ldap_manager.config import BackupConfig


@pytest.fixture
def backup_dir(tmp_path: Path) -> Path:
    d = tmp_path / "backups"
    d.mkdir()
    return d


@pytest.fixture
def bcfg(backup_dir: Path, tmp_path: Path) -> BackupConfig:
    # Create fake slapcat/slapadd binaries
    slapcat = tmp_path / "slapcat"
    slapcat.write_text("#!/bin/sh\n")
    slapcat.chmod(0o755)
    slapadd = tmp_path / "slapadd"
    slapadd.write_text("#!/bin/sh\n")
    slapadd.chmod(0o755)
    return BackupConfig(
        backup_dir=str(backup_dir),
        slapcat_bin=str(slapcat),
        slapadd_bin=str(slapadd),
        retention_count=3,
    )


class TestDump:
    @patch("ldap_manager.backup.subprocess.run")
    def test_dump_creates_backup_dir(self, mock_run: MagicMock, bcfg: BackupConfig) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"dn: dc=test\n\n", stderr=b"")
        mgr = BackupManager(bcfg, "dc=test,dc=com")
        path = mgr.dump()
        assert path.is_dir()
        assert (path / "metadata.txt").is_file()

    @patch("ldap_manager.backup.subprocess.run")
    def test_dump_with_tag(self, mock_run: MagicMock, bcfg: BackupConfig) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"dn: dc=test\n\n", stderr=b"")
        mgr = BackupManager(bcfg, "dc=test,dc=com")
        path = mgr.dump(tag="mytag")
        assert "mytag" in path.name

    @patch("ldap_manager.backup.subprocess.run")
    def test_dump_uses_base_dn(self, mock_run: MagicMock, bcfg: BackupConfig) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
        mgr = BackupManager(bcfg, "dc=test,dc=com")
        mgr.dump()
        # Check that -b was used in slapcat calls
        calls = mock_run.call_args_list
        assert any("-b" in str(c) for c in calls)
        assert any("dc=test,dc=com" in str(c) for c in calls)
        assert any("cn=config" in str(c) for c in calls)

    @patch("ldap_manager.backup.subprocess.run")
    def test_dump_slapcat_failure_raises(self, mock_run: MagicMock, bcfg: BackupConfig) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout=b"", stderr=b"slapcat error")
        mgr = BackupManager(bcfg, "dc=test,dc=com")
        with pytest.raises(RuntimeError, match="slapcat"):
            mgr.dump()

    @patch("ldap_manager.backup.subprocess.run")
    def test_retention(self, mock_run: MagicMock, bcfg: BackupConfig, backup_dir: Path) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
        mgr = BackupManager(bcfg, "dc=test,dc=com")
        # Create 5 backups, retention is 3
        for i in range(5):
            mgr.dump(tag=f"run{i}")
        dirs = [d for d in backup_dir.iterdir() if d.is_dir()]
        assert len(dirs) == 3


class TestRestore:
    @patch("ldap_manager.backup.subprocess.run")
    def test_restore_stops_slapd(self, mock_run: MagicMock, bcfg: BackupConfig, tmp_path: Path) -> None:
        backup = tmp_path / "backup"
        backup.mkdir()
        (backup / "data.ldif").write_text("dn: dc=test\n\n")
        (backup / "metadata.txt").write_text("timestamp: test\n")

        # pgrep returns 0 (slapd running), systemctl stop succeeds, slapadd succeeds, pgrep returns 1 (stopped)
        mock_run.side_effect = [
            MagicMock(returncode=0),  # pgrep: slapd running
            MagicMock(returncode=0),  # systemctl stop
            MagicMock(returncode=1),  # pgrep: slapd stopped
            MagicMock(returncode=0, stdout=b"", stderr=b""),  # slapadd
        ]

        mgr = BackupManager(bcfg, "dc=test,dc=com")
        mgr.restore(backup)

    @patch("ldap_manager.backup.subprocess.run")
    def test_restore_already_exists_raises(self, mock_run: MagicMock, bcfg: BackupConfig, tmp_path: Path) -> None:
        backup = tmp_path / "backup"
        backup.mkdir()
        (backup / "data.ldif").write_text("dn: dc=test\n\n")
        (backup / "metadata.txt").write_text("timestamp: test\n")

        mock_run.side_effect = [
            MagicMock(returncode=1),  # pgrep: slapd not running
            MagicMock(returncode=1, stdout=b"", stderr=b"already exists (68)"),  # slapadd fails
        ]

        mgr = BackupManager(bcfg, "dc=test,dc=com")
        with pytest.raises(DatabasePopulatedError, match="already has data"):
            mgr.restore(backup)

    def test_restore_missing_backup_raises(self, bcfg: BackupConfig, tmp_path: Path) -> None:
        mgr = BackupManager(bcfg, "dc=test,dc=com")
        with pytest.raises(FileNotFoundError):
            mgr.restore(tmp_path / "nonexistent")

    def test_restore_missing_ldif_raises(self, bcfg: BackupConfig, tmp_path: Path) -> None:
        backup = tmp_path / "backup"
        backup.mkdir()
        mgr = BackupManager(bcfg, "dc=test,dc=com")
        with pytest.raises(FileNotFoundError, match="data.ldif"):
            mgr.restore(backup)


class TestListBackups:
    def test_empty(self, bcfg: BackupConfig) -> None:
        mgr = BackupManager(bcfg, "dc=test,dc=com")
        assert mgr.list_backups() == []

    def test_with_backups(self, bcfg: BackupConfig, backup_dir: Path) -> None:
        d = backup_dir / "ldap_backup_20240101_120000"
        d.mkdir()
        (d / "metadata.txt").write_text("timestamp: 20240101_120000\n")
        (d / "data.ldif.gz").write_bytes(b"fake")

        mgr = BackupManager(bcfg, "dc=test,dc=com")
        backups = mgr.list_backups()
        assert len(backups) == 1
        assert backups[0]["timestamp"] == "20240101_120000"
