"""Tests for ldap_manager.audit sink implementations."""

from __future__ import annotations

import io
import json
import logging
import logging.handlers
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ldap_manager.audit import (
    AuditLogger,
    FileSink,
    HTTPSink,
    Sink,
    StdoutSink,
    SyslogSink,
)


class _RecordingSink(Sink):
    """Test helper: captures events or raises on demand."""

    def __init__(self, *, raises: Exception | None = None) -> None:
        self.events: list[dict[str, object]] = []
        self.raises = raises
        self.closed = False

    def emit(self, event: dict[str, object]) -> None:
        if self.raises is not None:
            raise self.raises
        self.events.append(event)

    def close(self) -> None:
        self.closed = True


# ── Sample event ───────────────────────────────────────────────────
def _sample() -> dict[str, object]:
    return {
        "timestamp": "2024-01-01T00:00:00+00:00",
        "action": "user.create",
        "target": "uid=jdoe,ou=People,dc=test",
        "operator": "cn=admin,dc=test",
        "success": True,
    }


# ── Sink ABC contract ──────────────────────────────────────────────
class TestSinkContract:
    def test_sink_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            Sink()  # type: ignore[abstract]

    def test_close_is_no_op_by_default(self) -> None:
        class DummySink(Sink):
            def emit(self, event: dict[str, object]) -> None:
                _ = event  # suppress unused-arg without rule import

        d = DummySink()
        # No-op default: must not raise.
        d.close()


# ── FileSink ───────────────────────────────────────────────────────
class TestFileSink:
    def test_emit_appends_json_line(self, tmp_path: Path) -> None:
        sink = FileSink(tmp_path / "audit.jsonl")
        sink.emit(_sample())
        sink.emit({**_sample(), "target": "uid=alice"})
        lines = sink.path.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["target"] == "uid=jdoe,ou=People,dc=test"
        assert json.loads(lines[1])["target"] == "uid=alice"

    def test_creates_parent_dir(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "c" / "audit.jsonl"
        sink = FileSink(nested)
        sink.emit(_sample())
        assert nested.is_file()

    def test_disabled_on_permission_error(self, tmp_path: Path) -> None:
        # Simulate a parent that cannot be created.
        with patch("ldap_manager.audit.Path.mkdir", side_effect=PermissionError):
            sink = FileSink(tmp_path / "audit.jsonl")
        assert sink.enabled is False
        # emit() becomes a no-op rather than raising.
        sink.emit(_sample())


# ── StdoutSink ─────────────────────────────────────────────────────
class TestStdoutSink:
    def test_emits_json_line_to_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        StdoutSink().emit(_sample())
        out = capsys.readouterr().out
        assert out.endswith("\n")
        parsed = json.loads(out)
        assert parsed["action"] == "user.create"


# ── SyslogSink ─────────────────────────────────────────────────────
class TestSyslogSink:
    def test_rejects_unknown_facility(self) -> None:
        with (
            pytest.raises(ValueError, match="Unknown syslog facility"),
            patch("logging.handlers.SysLogHandler"),
        ):
            SyslogSink(facility="made-up-facility")

    def test_emit_sends_json_via_handler(self) -> None:
        with patch("logging.handlers.SysLogHandler") as mock_handler_cls:
            mock_handler = MagicMock(spec=logging.Handler)
            mock_handler.level = logging.NOTSET
            mock_handler_cls.return_value = mock_handler

            sink = SyslogSink(facility="local3")
            sink.emit(_sample())

            # SysLogHandler.handle (via logger.info) should have been
            # invoked with a LogRecord whose message is our JSON blob.
            assert mock_handler.handle.called
            record = mock_handler.handle.call_args[0][0]
            payload = json.loads(record.getMessage())
            assert payload["action"] == "user.create"

    def test_close_removes_and_closes_handler(self) -> None:
        with patch("logging.handlers.SysLogHandler") as mock_handler_cls:
            mock_handler = MagicMock(spec=logging.Handler)
            mock_handler.level = logging.NOTSET
            mock_handler_cls.return_value = mock_handler
            sink = SyslogSink(facility="local3")
            sink.close()
            mock_handler.close.assert_called_once()

    def test_custom_address_tuple(self) -> None:
        with patch("logging.handlers.SysLogHandler") as mock_handler_cls:
            mock_handler = MagicMock(spec=logging.Handler)
            mock_handler.level = logging.NOTSET
            mock_handler_cls.return_value = mock_handler
            SyslogSink(facility="user", address=("127.0.0.1", 514))
            # SysLogHandler must receive both facility and address.
            kwargs = mock_handler_cls.call_args.kwargs
            assert kwargs["address"] == ("127.0.0.1", 514)


# ── HTTPSink ───────────────────────────────────────────────────────
class TestHTTPSink:
    def test_emit_posts_json_body(self) -> None:
        with patch("ldap_manager.audit.urllib_request.urlopen") as mock_open:
            mock_open.return_value.__enter__.return_value = io.BytesIO(b"")
            HTTPSink("https://example.com/audit").emit(_sample())

            assert mock_open.called
            req = mock_open.call_args[0][0]
            assert req.full_url == "https://example.com/audit"
            assert req.get_method() == "POST"
            assert req.data is not None
            body = json.loads(req.data.decode("utf-8"))
            assert body["target"] == "uid=jdoe,ou=People,dc=test"
            # Content-Type header auto-injected.
            # urllib lowercases names via header_items(); look either way.
            hdrs = {k.lower(): v for k, v in req.header_items()}
            assert hdrs.get("Content-type".lower()) == "application/json"

    def test_emit_applies_custom_headers(self) -> None:
        with patch("ldap_manager.audit.urllib_request.urlopen") as mock_open:
            mock_open.return_value.__enter__.return_value = io.BytesIO(b"")
            HTTPSink(
                "https://example.com/audit",
                headers={"Authorization": "Bearer abc"},
            ).emit(_sample())

            req = mock_open.call_args[0][0]
            hdrs = {k.lower(): v for k, v in req.header_items()}
            assert hdrs["authorization"] == "Bearer abc"
            assert hdrs["content-type"] == "application/json"

    def test_emit_uses_timeout(self) -> None:
        with patch("ldap_manager.audit.urllib_request.urlopen") as mock_open:
            mock_open.return_value.__enter__.return_value = io.BytesIO(b"")
            HTTPSink("https://example.com/audit", timeout_seconds=2.5).emit(_sample())

            _, kwargs = mock_open.call_args
            assert kwargs["timeout"] == 2.5

    def test_emit_raises_on_transport_error(self) -> None:
        # The sink itself does NOT swallow transport errors —
        # AuditLogger is responsible for that isolation.
        with (
            patch(
                "ldap_manager.audit.urllib_request.urlopen",
                side_effect=OSError("connection refused"),
            ),
            pytest.raises(OSError, match="connection refused"),
        ):
            HTTPSink("https://example.com/audit").emit(_sample())


# ── AuditLogger multi-sink fan-out ────────────────────────────────
class TestAuditLoggerFanout:
    def test_log_fans_out_to_every_sink(self, tmp_path: Path) -> None:
        a = _RecordingSink()
        b = _RecordingSink()
        lgr = AuditLogger(tmp_path / "ignored.jsonl", sinks=[a, b])
        lgr.log("user.create", "uid=jdoe")
        assert len(a.events) == 1
        assert len(b.events) == 1
        assert a.events[0]["action"] == "user.create"
        assert b.events[0]["action"] == "user.create"

    def test_failing_sink_does_not_block_later_sinks(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """CRITICAL INVARIANT: an exploding sink cannot abort the caller.

        If the first sink raises, the second must still receive the
        event, and log() must not propagate the exception.
        """
        bad = _RecordingSink(raises=RuntimeError("boom"))
        good = _RecordingSink()
        lgr = AuditLogger(tmp_path / "ignored.jsonl", sinks=[bad, good])

        # Must not raise.
        lgr.log("user.create", "uid=jdoe")

        # Downstream sink still got the event.
        assert len(good.events) == 1
        assert good.events[0]["target"] == "uid=jdoe"
        # A warning was surfaced on stderr so operators can see the drop.
        err = capsys.readouterr().err
        assert "boom" in err or "RuntimeError" in err

    def test_all_sinks_failing_does_not_raise(self, tmp_path: Path) -> None:
        bad1 = _RecordingSink(raises=RuntimeError("one"))
        bad2 = _RecordingSink(raises=OSError("two"))
        lgr = AuditLogger(tmp_path / "ignored.jsonl", sinks=[bad1, bad2])
        # Must not raise even when every sink fails.
        lgr.log("user.delete", "uid=alice")

    def test_close_closes_every_sink(self, tmp_path: Path) -> None:
        a = _RecordingSink()
        b = _RecordingSink()
        lgr = AuditLogger(tmp_path / "ignored.jsonl", sinks=[a, b])
        lgr.close()
        assert a.closed
        assert b.closed
