"""Server-level operations: status, reindex, start/stop/restart.

Operations that manage the slapd daemon itself rather than directory data.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config

log = logging.getLogger(__name__)


@dataclass
class ServerStatus:
    """Snapshot of slapd server state."""

    running: bool
    pid: int | None
    uptime_seconds: int | None
    version: str
    listeners: list[str]
    databases: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "pid": self.pid,
            "uptime_seconds": self.uptime_seconds,
            "version": self.version,
            "listeners": self.listeners,
            "databases": self.databases,
        }


class ServerManager:
    """Manage the slapd daemon."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._bcfg = cfg.backup
        self._slapindex_bin = self._find_binary("slapindex")

    def _find_binary(self, name: str) -> str:
        """Locate an OpenLDAP binary, preferring slapcat's directory."""
        slapcat_dir = Path(self._bcfg.slapcat_bin).parent
        candidate = slapcat_dir / name
        if candidate.is_file():
            return str(candidate)
        # Fallback: common locations
        for d in ("/usr/sbin", "/usr/local/sbin", "/usr/local/openldap/sbin"):
            p = Path(d) / name
            if p.is_file():
                return str(p)
        return name  # hope it's on PATH

    # ── STATUS ─────────────────────────────────────────────────────
    def status(self) -> ServerStatus:
        """Get current slapd server status."""
        running = False
        pid = None
        uptime_seconds = None

        # Check PID
        result = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True, timeout=5)
        if result.returncode == 0:
            running = True
            try:
                pid = int(result.stdout.decode().strip().split("\n")[0])
            except (ValueError, IndexError):
                pass

        # Get uptime from /proc if we have a PID
        if pid:
            try:
                stat_file = Path(f"/proc/{pid}/stat")
                if stat_file.is_file():
                    boot_time = float(Path("/proc/uptime").read_text().split()[0])
                    proc_start = float(stat_file.read_text().split()[21]) / os.sysconf("SC_CLK_TCK")
                    uptime_seconds = int(boot_time - proc_start)
            except (OSError, ValueError, IndexError):
                pass

        # Get version
        version = self._get_version()

        # Get listeners from process args
        listeners = self._get_listeners(pid)

        # Get database info from cn=config
        databases = self._get_databases()

        return ServerStatus(
            running=running,
            pid=pid,
            uptime_seconds=uptime_seconds,
            version=version,
            listeners=listeners,
            databases=databases,
        )

    def _get_version(self) -> str:
        """Get OpenLDAP version from slapd."""
        slapd_bin = Path(self._bcfg.slapcat_bin).parent / "slapd"
        if not slapd_bin.is_file():
            # Try common locations
            for p in ("/usr/sbin/slapd", "/usr/local/sbin/slapd", "/usr/local/openldap/libexec/slapd"):
                if Path(p).is_file():
                    slapd_bin = Path(p)
                    break

        try:
            result = subprocess.run(
                [str(slapd_bin), "-VV"],
                capture_output=True,
                timeout=5,
            )
            # slapd -VV writes to stderr
            output = result.stderr.decode("utf-8", errors="replace")
            for line in output.splitlines():
                if "slapd" in line.lower():
                    return line.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass

        return "unknown"

    def _get_listeners(self, pid: int | None) -> list[str]:
        """Extract listener URIs from slapd process cmdline."""
        if not pid:
            return []
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", errors="replace")
            args = cmdline.split("\0")
            listeners = []
            for i, arg in enumerate(args):
                if arg == "-h" and i + 1 < len(args):
                    listeners.extend(args[i + 1].split())
            return listeners
        except OSError:
            return []

    def _get_databases(self) -> list[dict[str, str]]:
        """Get database info via slapcat on cn=config."""
        try:
            result = subprocess.run(
                [self._bcfg.slapcat_bin, "-b", "cn=config", "-a", "(objectClass=olcDatabaseConfig)"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            databases: list[dict[str, str]] = []
            current: dict[str, str] = {}
            for line in result.stdout.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line and current:
                    if current.get("suffix"):
                        databases.append(current)
                    current = {}
                elif line.startswith("olcSuffix:"):
                    current["suffix"] = line.split(":", 1)[1].strip()
                elif line.startswith("olcDatabase:"):
                    current["type"] = line.split(":", 1)[1].strip()
                elif line.startswith("olcDbDirectory:"):
                    current["directory"] = line.split(":", 1)[1].strip()

            if current and current.get("suffix"):
                databases.append(current)

            return databases

        except (OSError, subprocess.TimeoutExpired):
            return []

    # ── REINDEX ────────────────────────────────────────────────────
    def reindex(self, suffix: str | None = None, *, auto_restart: bool = False) -> None:
        """Rebuild indexes. Requires slapd to be stopped.

        Args:
            suffix: Database suffix to reindex. Default: base_dn from config.
            auto_restart: If True, stop slapd before and start after.
        """
        if suffix is None:
            suffix = self._cfg.ldap.base_dn

        # Verify slapd is stopped
        check = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True)
        slapd_was_running = check.returncode == 0

        if slapd_was_running and not auto_restart:
            raise RuntimeError("slapd is running. Stop it first, or use --auto:\n  ldap-manager server reindex --auto\n")

        if slapd_was_running and auto_restart:
            log.info("Stopping slapd for reindex")
            self.stop()

        slapindex = self._slapindex_bin
        if not Path(slapindex).is_file():
            raise FileNotFoundError(f"slapindex not found at {slapindex}. Is openldap-servers installed?")

        cmd = [slapindex, "-b", suffix]
        log.info("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=600)
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"slapindex failed (rc={result.returncode}): {stderr}")
        finally:
            if slapd_was_running and auto_restart:
                log.info("Starting slapd after reindex")
                self.start()

        log.info("Reindex completed for %s", suffix)

    # ── START / STOP / RESTART ─────────────────────────────────────
    def stop(self) -> None:
        """Stop slapd."""
        check = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True)
        if check.returncode != 0:
            log.info("slapd is already stopped")
            return

        result = subprocess.run(["systemctl", "stop", "slapd"], capture_output=True, timeout=30)
        if result.returncode != 0:
            result = subprocess.run(["service", "slapd", "stop"], capture_output=True, timeout=30)

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"Failed to stop slapd: {stderr}")

        # Wait for it to actually die
        for _ in range(10):
            time.sleep(0.5)
            verify = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True)
            if verify.returncode != 0:
                log.info("slapd stopped")
                return

        raise RuntimeError("slapd did not stop within 5 seconds")

    def start(self) -> None:
        """Start slapd."""
        check = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True)
        if check.returncode == 0:
            log.info("slapd is already running")
            return

        result = subprocess.run(["systemctl", "start", "slapd"], capture_output=True, timeout=30)
        if result.returncode != 0:
            result = subprocess.run(["service", "slapd", "start"], capture_output=True, timeout=30)

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"Failed to start slapd: {stderr}")

        time.sleep(1)
        verify = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True)
        if verify.returncode != 0:
            raise RuntimeError("slapd did not start — check logs: journalctl -u slapd")

        log.info("slapd started")

    def restart(self) -> None:
        """Restart slapd."""
        self.stop()
        self.start()
