"""Tests for ldap_manager.batch."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ldap_manager.batch import BatchResult, load_structured_file, load_uid_list, run_batch
from ldap_manager.config import Config

from .conftest import make_ldap_entry


class TestLoadUidList:
    def test_basic(self, tmp_path: Path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("alice\nbob\ncharlie\n")
        uids = load_uid_list(f)
        assert uids == ["alice", "bob", "charlie"]

    def test_comments_and_blanks(self, tmp_path: Path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("# departing employees\nalice\n\n# contractors\nbob\n\n")
        uids = load_uid_list(f)
        assert uids == ["alice", "bob"]

    def test_strips_whitespace(self, tmp_path: Path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("  alice  \n  bob\n")
        uids = load_uid_list(f)
        assert uids == ["alice", "bob"]

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_uid_list(tmp_path / "nope.txt")


class TestLoadStructuredFile:
    def test_json_array(self, tmp_path: Path) -> None:
        f = tmp_path / "users.json"
        f.write_text(json.dumps([{"uid": "alice"}, {"uid": "bob"}]))
        data = load_structured_file(f)
        assert len(data) == 2
        assert data[0]["uid"] == "alice"

    def test_json_wrapped(self, tmp_path: Path) -> None:
        f = tmp_path / "users.json"
        f.write_text(json.dumps({"users": [{"uid": "alice"}]}))
        data = load_structured_file(f)
        assert len(data) == 1

    def test_csv(self, tmp_path: Path) -> None:
        f = tmp_path / "users.csv"
        f.write_text("uid,cn,sn\nalice,Alice A,A\nbob,Bob B,B\n")
        data = load_structured_file(f)
        assert len(data) == 2
        assert data[0]["uid"] == "alice"
        assert data[1]["cn"] == "Bob B"

    def test_unsupported_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "users.xml"
        f.write_text("<users/>")
        with pytest.raises(ValueError, match="Unsupported"):
            load_structured_file(f)

    def test_json_not_array_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text(json.dumps({"uid": "alice"}))
        with pytest.raises(ValueError, match="array"):
            load_structured_file(f)


class TestBatchResult:
    def test_counts(self) -> None:
        r = BatchResult()
        r.record_success("a")
        r.record_success("b")
        r.record_failure("c", "boom")
        r.record_skip("d", "no attrs")
        assert r.total == 4
        assert r.succeeded == 2
        assert r.failed == 1
        assert r.skipped == 1

    def test_summary_includes_errors(self) -> None:
        r = BatchResult()
        r.record_failure("jdoe", "not found")
        summary = r.summary()
        assert "jdoe" in summary
        assert "not found" in summary

    def test_to_dict(self) -> None:
        r = BatchResult()
        r.record_success("a")
        r.record_failure("b", "err")
        d = r.to_dict()
        assert d["succeeded"] == 1
        assert d["failed"] == 1
        assert len(d["errors"]) == 1


class TestRunBatch:
    def test_disable_batch(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("alice\nbob\n")
        # Each disable call does a get_user search then a modify
        mock_conn.search_s.return_value = [make_ldap_entry("alice")]

        result = run_batch(mock_conn, cfg, "disable", f)
        assert result.total == 2

    def test_dry_run_no_writes(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("alice\n")
        result = run_batch(mock_conn, cfg, "disable", f, dry_run=True)
        assert result.succeeded == 1
        mock_conn.modify_s.assert_not_called()

    def test_invalid_action_raises(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("alice\n")
        with pytest.raises(ValueError, match="Invalid action"):
            run_batch(mock_conn, cfg, "nuke", f)

    def test_stop_on_error(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "users.txt"
        f.write_text("alice\nbob\ncharlie\n")
        # First call fails
        mock_conn.search_s.return_value = []  # user not found

        result = run_batch(mock_conn, cfg, "disable", f, stop_on_error=True)
        # Should stop after first failure
        assert result.failed >= 1
        assert result.total < 3

    def test_create_from_json(self, cfg: Config, mock_conn: MagicMock, tmp_path: Path) -> None:
        f = tmp_path / "new.json"
        f.write_text(json.dumps([{"uid": "newuser"}]))
        mock_conn.search_s.side_effect = [[], []]  # get_user, _next_uid
        result = run_batch(mock_conn, cfg, "create", f)
        assert result.succeeded == 1
