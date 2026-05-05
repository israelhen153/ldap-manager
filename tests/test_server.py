"""Tests for ldap_manager.server - ServerManager."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ldap_manager.config import Config
from ldap_manager.server import ServerManager, ServerStatus


@pytest.fixture
def cfg() -> Config:
    return Config()


@pytest.fixture
def mgr(cfg: Config) -> ServerManager:
    with patch.object(ServerManager, "_find_binary", return_value="/usr/sbin/slapindex"):
        return ServerManager(cfg)


class TestServerStatus:
    @patch("ldap_manager.server.subprocess.run")
    def test_status_running(self, mock_run: MagicMock, mgr: ServerManager) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=b"1234"),  # pgrep
            MagicMock(returncode=0, stderr=b"slapd 2.4.57"),  # slapd -VV
            MagicMock(returncode=0, stdout=b"olcSuffix: dc=test\nolcDatabase: mdb\n\n"),  # slapcat
        ]
        with patch("ldap_manager.server.Path") as mock_path:
            mock_path.return_value.is_file.return_value = False
            mock_path.return_value.parent.__truediv__ = lambda s, n: mock_path.return_value
            status = mgr.status()
        assert status.running is True

    @patch("ldap_manager.server.subprocess.run")
    def test_status_stopped(self, mock_run: MagicMock, mgr: ServerManager) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),  # pgrep: not running
            MagicMock(returncode=1, stderr=b""),  # slapd -VV fails
            MagicMock(returncode=1, stdout=b""),  # slapcat fails
        ]
        with patch("ldap_manager.server.Path") as mock_path:
            mock_path.return_value.is_file.return_value = False
            mock_path.return_value.parent.__truediv__ = lambda s, n: mock_path.return_value
            status = mgr.status()
        assert status.running is False
        assert status.pid is None

    def test_server_status_to_dict(self) -> None:
        status = ServerStatus(
            running=True,
            pid=1234,
            uptime_seconds=3600,
            version="slapd 2.4.57",
            listeners=["ldap:///"],
            databases=[{"suffix": "dc=test", "type": "mdb"}],
        )
        d = status.to_dict()
        assert d["running"] is True
        assert d["pid"] == 1234


class TestServerReindex:
    @patch("ldap_manager.server.subprocess.run")
    def test_reindex_slapd_running_raises(self, mock_run: MagicMock, mgr: ServerManager) -> None:
        mock_run.return_value = MagicMock(returncode=0)  # pgrep: running
        with pytest.raises(RuntimeError, match="slapd is running"):
            mgr.reindex()

    @patch("ldap_manager.server.subprocess.run")
    def test_reindex_success(self, mock_run: MagicMock, mgr: ServerManager) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=1),  # pgrep: stopped
            MagicMock(returncode=0),  # slapindex succeeds
        ]
        with patch("ldap_manager.server.Path") as mock_path:
            mock_path.return_value.is_file.return_value = True
            mgr.reindex("dc=test,dc=com")

    @patch("ldap_manager.server.subprocess.run")
    def test_reindex_failure_raises(self, mock_run: MagicMock, mgr: ServerManager) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=1),  # pgrep: stopped
            MagicMock(returncode=1, stderr=b"error"),  # slapindex fails
        ]
        with patch("ldap_manager.server.Path") as mock_path:
            mock_path.return_value.is_file.return_value = True
            with pytest.raises(RuntimeError, match="slapindex failed"):
                mgr.reindex("dc=test,dc=com")


class TestServerStartStop:
    @patch("ldap_manager.server.time.sleep")
    @patch("ldap_manager.server.subprocess.run")
    def test_stop_already_stopped(self, mock_run: MagicMock, mock_sleep: MagicMock, mgr: ServerManager) -> None:
        mock_run.return_value = MagicMock(returncode=1)  # pgrep: not running
        mgr.stop()
        # Should not call systemctl
        assert mock_run.call_count == 1

    @patch("ldap_manager.server.time.sleep")
    @patch("ldap_manager.server.subprocess.run")
    def test_start_already_running(self, mock_run: MagicMock, mock_sleep: MagicMock, mgr: ServerManager) -> None:
        mock_run.return_value = MagicMock(returncode=0)  # pgrep: running
        mgr.start()
        assert mock_run.call_count == 1

    @patch("ldap_manager.server.time.sleep")
    @patch("ldap_manager.server.subprocess.run")
    def test_stop_success(self, mock_run: MagicMock, mock_sleep: MagicMock, mgr: ServerManager) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=0),  # pgrep: running
            MagicMock(returncode=0),  # systemctl stop
            MagicMock(returncode=1),  # verify: stopped
        ]
        mgr.stop()

    @patch("ldap_manager.server.time.sleep")
    @patch("ldap_manager.server.subprocess.run")
    def test_start_success(self, mock_run: MagicMock, mock_sleep: MagicMock, mgr: ServerManager) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=1),  # pgrep: not running
            MagicMock(returncode=0),  # systemctl start
            MagicMock(returncode=0),  # verify: running
        ]
        mgr.start()
