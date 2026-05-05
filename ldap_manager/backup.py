"""LDAP database dump and restore.

Uses slapcat/slapadd for full-fidelity backup including:
  - All entries (data DB)
  - cn=config (server configuration, ACLs, overlays, schemas)
  - Operational attributes

This is intentionally NOT using LDAP protocol (ldapsearch/ldapadd) for backup.
Protocol-level export is lossy: it misses cn=config, overlays, schema
customizations, and operational attributes that slapcat preserves. If you
disagree, go run `ldapsearch -b cn=config` and compare it to `slapcat -n0`.
"""

from __future__ import annotations

import gzip
import logging
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from .config import BackupConfig

log = logging.getLogger(__name__)


class DatabasePopulatedError(RuntimeError):
    """Raised when slapadd fails because the database already has entries."""


class BackupManager:
    """Dump and restore the LDAP database using server-side tools."""

    def __init__(self, cfg: BackupConfig, base_dn: str) -> None:
        self._cfg = cfg
        self._base_dn = base_dn
        self._backup_dir = Path(cfg.backup_dir)

    # ── DUMP ───────────────────────────────────────────────────────
    def dump(self, *, compress: bool = True, tag: str = "") -> Path:
        """Full dump of LDAP data + config databases.

        Returns the path to the backup directory containing:
          - data.ldif(.gz)    — main database (base_dn suffix)
          - config.ldif(.gz)  — cn=config database

        Args:
            compress: gzip the LDIF files
            tag: optional tag appended to the backup directory name
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        dir_name = f"ldap_backup_{timestamp}"
        if tag:
            dir_name += f"_{tag}"

        backup_path = self._backup_dir / dir_name
        backup_path.mkdir(parents=True, exist_ok=True)

        # Dump data db using base DN suffix, config db using cn=config
        self._slapcat(backup_path / "data.ldif", base_dn=self._base_dn, compress=compress)
        self._slapcat(backup_path / "config.ldif", base_dn="cn=config", compress=compress)

        # Write metadata
        meta = backup_path / "metadata.txt"
        meta.write_text(
            f"timestamp: {timestamp}\n"
            f"compressed: {compress}\n"
            f"tag: {tag}\n"
            f"base_dn: {self._base_dn}\n"
            f"hostname: {os.uname().nodename}\n"
        )

        self._enforce_retention()
        log.info("Backup completed: %s", backup_path)
        return backup_path

    def _slapcat(self, output: Path, *, base_dn: str, compress: bool) -> None:
        """Run slapcat for a specific database identified by its suffix."""
        slapcat = self._cfg.slapcat_bin

        if not Path(slapcat).is_file():
            raise FileNotFoundError(
                f"slapcat not found at {slapcat}. "
                "Is OpenLDAP server package installed? "
                "Set backup.slapcat_bin in config if it's elsewhere."
            )

        cmd = [slapcat, "-b", base_dn]
        log.debug("Running: %s", " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=600,  # 10 min timeout for large directories
        )

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"slapcat -b {base_dn} failed (rc={result.returncode}): {stderr}")

        data = result.stdout

        if compress:
            output = output.with_suffix(output.suffix + ".gz")
            with gzip.open(output, "wb") as f:
                f.write(data)
        else:
            output.write_bytes(data)

        size_mb = output.stat().st_size / (1024 * 1024)
        log.info("Dumped %s -> %s (%.2f MB)", base_dn, output, size_mb)

    # ── RESTORE ────────────────────────────────────────────────────
    def restore(self, backup_path: str | Path, *, restore_config: bool = False) -> None:
        """Restore LDAP database from a backup directory.

        WARNING: This is a destructive operation. The current database content
        will be replaced. This method will stop slapd before restoring.

        Args:
            backup_path: Path to backup directory (from dump())
            restore_config: Also restore cn=config (dangerous — can break server)
        """
        backup_path = Path(backup_path)
        if not backup_path.is_dir():
            raise FileNotFoundError(f"Backup directory not found: {backup_path}")

        # Find the data LDIF
        data_ldif = self._find_ldif(backup_path, "data")
        if data_ldif is None:
            raise FileNotFoundError(f"No data.ldif found in {backup_path}")

        # Stop slapd — required for slapadd to work safely
        self._stop_slapd()

        log.warning("Restoring data database from %s", data_ldif)
        self._slapadd(data_ldif, base_dn=self._base_dn)

        if restore_config:
            config_ldif = self._find_ldif(backup_path, "config")
            if config_ldif is None:
                raise FileNotFoundError(f"No config.ldif found in {backup_path}")
            log.warning("Restoring config database from %s", config_ldif)
            self._slapadd(config_ldif, base_dn="cn=config")

        log.info("Restore completed from %s", backup_path)

    def _slapadd(self, ldif_path: Path, *, base_dn: str) -> None:
        """Run slapadd to import an LDIF into a database."""
        slapadd = self._cfg.slapadd_bin

        if not Path(slapadd).is_file():
            raise FileNotFoundError(f"slapadd not found at {slapadd}")

        # Decompress if needed
        if ldif_path.suffix == ".gz":
            decompressed = ldif_path.with_suffix("")
            with gzip.open(ldif_path, "rb") as fin, open(decompressed, "wb") as fout:
                shutil.copyfileobj(fin, fout)
            ldif_path = decompressed

        cmd = [slapadd, "-b", base_dn, "-l", str(ldif_path)]
        log.debug("Running: %s", " ".join(cmd))

        result = subprocess.run(cmd, capture_output=True, timeout=600)

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")

            # Detect "already exists" — means the DB already has entries.
            # slapadd emits variations like:
            #   "already exists", "txn_aborted", "duplicate key",
            #   "MDB_KEYEXIST", "entry already exists"
            already_exists_hints = (
                "already exists",
                "mdb_keyexist",
                "duplicate key",
                "txn_aborted",
            )
            if any(hint in stderr.lower() for hint in already_exists_hints):
                raise DatabasePopulatedError(
                    f"This server's database ({base_dn}) already has data in it. "
                    f"slapadd cannot import into a non-empty database.\n\n"
                    f"If you want to replace the existing data, you need to wipe the "
                    f"database files first:\n"
                    f"  1. Make sure slapd is stopped\n"
                    f"  2. Remove the MDB file:  rm /var/lib/ldap/data.mdb /var/lib/ldap/lock.mdb\n"
                    f"     (check your actual DB path in cn=config — olcDbDirectory)\n"
                    f"  3. Re-run this restore command\n\n"
                    f"Original error: {stderr.strip()}"
                )

            raise RuntimeError(f"slapadd -b {base_dn} failed (rc={result.returncode}): {stderr}")

        log.info("Imported %s into %s", ldif_path, base_dn)

    def _find_ldif(self, backup_dir: Path, prefix: str) -> Path | None:
        """Find an LDIF file (possibly gzipped) in a backup directory."""
        for suffix in (".ldif.gz", ".ldif"):
            candidate = backup_dir / f"{prefix}{suffix}"
            if candidate.is_file():
                return candidate
        return None

    def _stop_slapd(self) -> None:
        """Stop slapd service if it's running. Verifies it's actually dead."""
        # Check if it's running at all
        check = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True)
        if check.returncode != 0:
            log.info("slapd is not running, proceeding with restore")
            return

        log.warning("slapd is running — stopping it for restore")

        # Try systemctl first (systemd), fall back to service (sysv)
        stop_result = subprocess.run(
            ["systemctl", "stop", "slapd"],
            capture_output=True,
            timeout=30,
        )

        if stop_result.returncode != 0:
            log.debug("systemctl stop failed, trying 'service slapd stop'")
            stop_result = subprocess.run(
                ["service", "slapd", "stop"],
                capture_output=True,
                timeout=30,
            )

        if stop_result.returncode != 0:
            stderr = stop_result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"Failed to stop slapd. Stop it manually before restoring.\nError: {stderr.strip()}")

        # Give it a moment and verify it's actually dead
        for _ in range(5):
            time.sleep(1)
            verify = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True)
            if verify.returncode != 0:
                log.info("slapd stopped successfully")
                return

        # Still alive — force kill as last resort
        log.warning("slapd did not stop gracefully, sending SIGKILL")
        subprocess.run(["pkill", "-9", "-x", "slapd"], capture_output=True)
        time.sleep(2)

        final = subprocess.run(["pgrep", "-x", "slapd"], capture_output=True)
        if final.returncode == 0:
            raise RuntimeError(
                "slapd is still running after SIGKILL. Something is very wrong. Investigate manually before attempting restore."
            )

    # ── RETENTION ──────────────────────────────────────────────────
    def _enforce_retention(self) -> None:
        """Remove oldest backups beyond retention_count."""
        if self._cfg.retention_count <= 0:
            return

        if not self._backup_dir.is_dir():
            return

        backups = sorted(
            [d for d in self._backup_dir.iterdir() if d.is_dir() and d.name.startswith("ldap_backup_")],
            key=lambda d: d.name,
            reverse=True,
        )

        for old_backup in backups[self._cfg.retention_count :]:
            log.info("Removing old backup: %s", old_backup)
            shutil.rmtree(old_backup)

    # ── LIST ───────────────────────────────────────────────────────
    def list_backups(self) -> list[dict[str, str]]:
        """List available backups with metadata."""
        if not self._backup_dir.is_dir():
            return []

        results = []
        for d in sorted(self._backup_dir.iterdir(), reverse=True):
            if not d.is_dir() or not d.name.startswith("ldap_backup_"):
                continue

            meta_file = d / "metadata.txt"
            meta = {}
            if meta_file.is_file():
                for line in meta_file.read_text().splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        meta[k.strip()] = v.strip()

            # Calculate total size
            size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
            meta["path"] = str(d)
            meta["size_mb"] = f"{size / (1024 * 1024):.2f}"
            results.append(meta)

        return results
