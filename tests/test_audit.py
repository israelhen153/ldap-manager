"""Tests for ldap_manager.audit - AuditLogger."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ldap_manager.audit import AuditLogger


@pytest.fixture
def logger(tmp_path: Path) -> AuditLogger:
    return AuditLogger(tmp_path / "audit.jsonl")


class TestAuditLog:
    def test_log_creates_entry(self, logger: AuditLogger) -> None:
        logger.log("user.create", "uid=jdoe,ou=People,dc=test")
        lines = logger.path.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["action"] == "user.create"
        assert entry["target"] == "uid=jdoe,ou=People,dc=test"
        assert entry["success"] is True
        assert "timestamp" in entry

    def test_log_with_details(self, logger: AuditLogger) -> None:
        logger.log("user.update", "uid=jdoe", details={"attrs": ["mail", "cn"]})
        entry = json.loads(logger.path.read_text().strip())
        assert entry["details"] == {"attrs": ["mail", "cn"]}

    def test_log_with_error(self, logger: AuditLogger) -> None:
        logger.log("user.delete", "uid=jdoe", success=False, error="NOT_FOUND")
        entry = json.loads(logger.path.read_text().strip())
        assert entry["success"] is False
        assert entry["error"] == "NOT_FOUND"

    def test_log_appends(self, logger: AuditLogger) -> None:
        logger.log("user.create", "uid=alice")
        logger.log("user.create", "uid=bob")
        lines = logger.path.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_disabled_logger_does_not_write(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        lgr = AuditLogger(log_path)
        lgr._enabled = False
        lgr.log("user.create", "uid=jdoe")
        assert not log_path.exists() or log_path.read_text() == ""


class TestAuditQuery:
    def test_query_returns_all(self, logger: AuditLogger) -> None:
        logger.log("user.create", "uid=alice")
        logger.log("group.create", "cn=devops")
        results = logger.query()
        assert len(results) == 2

    def test_query_newest_first(self, logger: AuditLogger) -> None:
        logger.log("user.create", "uid=first")
        logger.log("user.create", "uid=second")
        results = logger.query()
        assert "second" in results[0]["target"]

    def test_query_filter_by_action(self, logger: AuditLogger) -> None:
        logger.log("user.create", "uid=alice")
        logger.log("group.create", "cn=devops")
        results = logger.query(action="user")
        assert len(results) == 1
        assert results[0]["action"] == "user.create"

    def test_query_filter_by_target(self, logger: AuditLogger) -> None:
        logger.log("user.create", "uid=alice")
        logger.log("user.create", "uid=bob")
        results = logger.query(target="alice")
        assert len(results) == 1

    def test_query_limit(self, logger: AuditLogger) -> None:
        for i in range(10):
            logger.log("user.create", f"uid=user{i}")
        results = logger.query(limit=3)
        assert len(results) == 3

    def test_query_empty_log(self, tmp_path: Path) -> None:
        lgr = AuditLogger(tmp_path / "empty.jsonl")
        assert lgr.query() == []


class TestAuditBackwardCompat:
    """The no-config path must behave exactly like the old logger."""

    def test_no_sinks_config_uses_single_file_sink_at_default(self) -> None:
        """With no audit.sinks in config, fall back to the historic file path.

        Ensures existing deployments that never touched `audit:` in
        their YAML keep working unchanged.
        """
        from ldap_manager.audit import (
            DEFAULT_AUDIT_LOG,
            FileSink,
            build_sinks,
        )
        from ldap_manager.config import AuditConfig

        # Default AuditConfig has empty sinks list — the "no opt-in" case.
        audit_cfg = AuditConfig()
        sinks = build_sinks(audit_cfg.sinks)

        assert len(sinks) == 1
        assert isinstance(sinks[0], FileSink)
        assert str(sinks[0].path) == DEFAULT_AUDIT_LOG

    def test_constructor_without_sinks_still_uses_file(self, tmp_path: Path) -> None:
        """AuditLogger(log_path) — the legacy signature — still builds a FileSink."""
        path = tmp_path / "legacy.jsonl"
        lgr = AuditLogger(path)
        assert lgr.path == path
        assert lgr.enabled is True
        lgr.log("user.create", "uid=jdoe")
        assert path.read_text().count("uid=jdoe") == 1
