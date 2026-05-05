"""Tests for ldap_manager.passwords."""

from __future__ import annotations

import csv
import os
from pathlib import Path
from unittest.mock import MagicMock

import ldap
import pytest

from ldap_manager.config import Config
from ldap_manager.passwords import (
    _DETECT_CACHE,
    BulkResetResult,
    InsecureOutputDirError,
    bulk_password_reset,
    detect_hash_support,
    hash_password,
    resolve_hash_scheme,
)

from .conftest import make_ldap_entry


class TestBulkReset:
    def test_dry_run_no_ldap_writes(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
            make_ldap_entry("bob", "Bob B", "B", 10002),
        ]
        output = tmp_path / "passwords.csv"
        result = bulk_password_reset(mock_backend, cfg, output_file=output, dry_run=True)

        assert isinstance(result, BulkResetResult)
        assert result.output_path == output
        assert result.output_path.is_file()
        assert result.rotated == 2
        mock_backend.modify.assert_not_called()

        with open(result.output_path) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 3  # header + 2 users
        assert rows[0] == ["uid", "cn", "new_password"]

    def test_actual_reset(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
        ]
        output = tmp_path / "passwords.csv"
        result = bulk_password_reset(mock_backend, cfg, output_file=output, dry_run=False)

        assert result.rotated == 1
        assert mock_backend.modify.call_count == 1

    def test_csv_permissions(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice A", "A", 10001),
        ]
        output = tmp_path / "passwords.csv"
        result = bulk_password_reset(mock_backend, cfg, output_file=output, dry_run=True)
        assert result.output_path is not None
        assert oct(result.output_path.stat().st_mode)[-3:] == "600"

    def test_no_users_raises(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        mock_backend.search.return_value = []
        with pytest.raises(RuntimeError, match="No users found"):
            bulk_password_reset(mock_backend, cfg, output_file=tmp_path / "x.csv")

    def test_enabled_only_skips_disabled(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001, shell="/bin/bash"),
            make_ldap_entry("bob", "Bob", "B", 10002, shell="/sbin/nologin"),
        ]
        output = tmp_path / "passwords.csv"
        result = bulk_password_reset(
            mock_backend,
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

    def test_summary_only_no_file_written(self, cfg: Config, mock_backend: MagicMock) -> None:
        """Without output_file the function rotates passwords and drops them."""
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
            make_ldap_entry("bob", "Bob", "B", 10002),
        ]
        result = bulk_password_reset(mock_backend, cfg, output_file=None, dry_run=False)

        assert result.output_path is None
        assert result.rotated == 2
        # Both users had modify called — passwords applied, just not written anywhere.
        assert mock_backend.modify.call_count == 2

    def test_generated_passwords_are_unique(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        """Each user must get a distinct random password, not a shared default."""
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
            make_ldap_entry("bob", "Bob", "B", 10002),
            make_ldap_entry("carol", "Carol", "C", 10003),
        ]
        output = tmp_path / "pw.csv"
        bulk_password_reset(mock_backend, cfg, output_file=output, dry_run=True)

        with open(output) as f:
            rows = list(csv.reader(f))[1:]  # skip header
        passwords = [row[2] for row in rows]
        assert len(set(passwords)) == len(passwords), "passwords collided"

    def test_output_file_mode_is_0o600(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        """Permission must be exactly 0600 even under a permissive umask."""
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
        ]
        output = tmp_path / "pw.csv"
        # Force a wide umask — the implementation must chmod regardless.
        old_umask = os.umask(0)
        try:
            bulk_password_reset(mock_backend, cfg, output_file=output, dry_run=True)
        finally:
            os.umask(old_umask)

        assert output.stat().st_mode & 0o777 == 0o600

    def test_world_readable_parent_is_refused(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        """If the parent dir has o+r, refuse before writing anything."""
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
        ]
        parent = tmp_path / "wide"
        parent.mkdir()
        parent.chmod(0o755)  # world-readable
        output = parent / "pw.csv"

        with pytest.raises(InsecureOutputDirError, match="world-readable"):
            bulk_password_reset(mock_backend, cfg, output_file=output, dry_run=False)

        assert not output.exists(), "file must not be created"
        mock_backend.modify.assert_not_called()

    def test_length_parameter_controls_password_length(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        """Explicit length= must override cfg.password.generated_length."""
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
            make_ldap_entry("bob", "Bob", "B", 10002),
        ]
        output = tmp_path / "pw.csv"
        # cfg default is 20; request something very different.
        bulk_password_reset(mock_backend, cfg, output_file=output, dry_run=True, length=42)

        with open(output) as f:
            rows = list(csv.reader(f))[1:]  # skip header
        assert rows, "expected at least one row"
        for row in rows:
            assert len(row[2]) == 42, f"expected length 42, got {len(row[2])}: {row[2]!r}"

    def test_length_defaults_to_config(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        """When length is None, use cfg.password.generated_length."""
        mock_backend.search.return_value = [
            make_ldap_entry("alice", "Alice", "A", 10001),
        ]
        output = tmp_path / "pw.csv"
        bulk_password_reset(mock_backend, cfg, output_file=output, dry_run=True, length=None)

        with open(output) as f:
            rows = list(csv.reader(f))[1:]
        assert len(rows[0][2]) == cfg.password.generated_length


# ── Hash scheme detection ─────────────────────────────────────────


def _olc_entry(*tags: str) -> tuple[str, dict[str, list[bytes]]]:
    """Build a fake cn=config entry with olcPasswordHash values."""
    return (
        "olcDatabase={1}frontend,cn=config",
        {"olcPasswordHash": [t.encode() for t in tags]},
    )


class _FakeBackend:
    """Minimal stand-in for a Backend. WeakKeyDictionary needs a real
    instance; the detection cache tests use this tiny shim rather than a
    MagicMock because earlier versions of unittest.mock weren't weakly
    referenceable. Still works today; keeping the class as the canonical
    fixture for cache-coherence assertions."""

    def __init__(self, result: object) -> None:
        self._result = result
        self.calls = 0
        self.supports: frozenset[str] = frozenset()

    def search(self, *args: object, **kwargs: object) -> object:
        self.calls += 1
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class TestDetectHashSupport:
    def setup_method(self) -> None:
        _DETECT_CACHE.clear()

    def test_prefers_argon2_when_advertised(self) -> None:
        """{ARGON2} in olcPasswordHash → detect argon2id."""
        backend = _FakeBackend([_olc_entry("{ARGON2}", "{SSHA512}", "{SSHA}")])
        assert detect_hash_support(backend) == "argon2id"  # type: ignore[arg-type]

    def test_prefers_ssha512_when_no_argon2(self) -> None:
        """Without {ARGON2}, best remaining is {SSHA512}."""
        backend = _FakeBackend([_olc_entry("{SSHA512}", "{SSHA}")])
        assert detect_hash_support(backend) == "ssha512"  # type: ignore[arg-type]

    def test_falls_back_to_ssha_on_search_failure(self) -> None:
        """If the probe raises, return 'ssha' — never propagate."""
        backend = _FakeBackend(ldap.LDAPError("insufficient access"))
        assert detect_hash_support(backend) == "ssha"  # type: ignore[arg-type]

    def test_falls_back_to_ssha_on_unexpected_exception(self) -> None:
        """Non-LDAP exceptions (e.g. exhausted mock iterators) also fall back.

        We never want a probing hiccup to abort a password write, so the
        catch is deliberately broad.
        """
        backend = _FakeBackend(StopIteration())
        assert detect_hash_support(backend) == "ssha"  # type: ignore[arg-type]

    def test_falls_back_to_ssha_on_empty_probe(self) -> None:
        """No olcPasswordHash entries → default to ssha."""
        backend = _FakeBackend([])
        assert detect_hash_support(backend) == "ssha"  # type: ignore[arg-type]

    def test_accepts_argon2id_tag_variant(self) -> None:
        """OpenLDAP may surface {ARGON2ID}; treat it as argon2id."""
        backend = _FakeBackend([_olc_entry("{ARGON2ID}", "{SSHA}")])
        assert detect_hash_support(backend) == "argon2id"  # type: ignore[arg-type]

    def test_skips_argon2id_when_library_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Server claims argon2id but argon2-cffi isn't installed: skip it."""
        import ldap_manager.passwords as mod

        monkeypatch.setattr(mod, "_argon2_available", lambda: False)
        backend = _FakeBackend([_olc_entry("{ARGON2}", "{SSHA512}", "{SSHA}")])
        assert detect_hash_support(backend) == "ssha512"  # type: ignore[arg-type]

    def test_caches_result_per_connection(self) -> None:
        """Second call must not re-issue search."""
        backend = _FakeBackend([_olc_entry("{SSHA512}", "{SSHA}")])
        detect_hash_support(backend)  # type: ignore[arg-type]
        detect_hash_support(backend)  # type: ignore[arg-type]
        detect_hash_support(backend)  # type: ignore[arg-type]
        assert backend.calls == 1, "cache miss — probe ran more than once"


class TestHashPassword:
    def test_ssha_prefix(self) -> None:
        assert hash_password("foo", "ssha").startswith(b"{SSHA}")

    def test_ssha512_prefix(self) -> None:
        assert hash_password("foo", "ssha512").startswith(b"{SSHA512}")

    def test_argon2id_prefix(self) -> None:
        assert hash_password("foo", "argon2id").startswith(b"{ARGON2}")

    def test_legacy_bracketed_scheme_accepted(self) -> None:
        """Old configs carry '{SSHA}'; normalize don't reject."""
        assert hash_password("foo", "{SSHA}").startswith(b"{SSHA}")
        assert hash_password("foo", "{SSHA512}").startswith(b"{SSHA512}")

    def test_unknown_scheme_raises(self) -> None:
        with pytest.raises(ValueError, match="bcrypt"):
            hash_password("foo", "bcrypt")

    def test_ssha_reproducible_with_fixed_salt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Given a known salt, SSHA output is deterministic."""
        import ldap_manager.passwords as mod

        fixed = b"\x00" * 16
        monkeypatch.setattr(mod.os, "urandom", lambda n: fixed[:n])
        a = hash_password("hunter2", "ssha")
        b = hash_password("hunter2", "ssha")
        assert a == b  # salt was forced → output matches

    def test_ssha512_reproducible_with_fixed_salt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import ldap_manager.passwords as mod

        fixed = b"\x11" * 16
        monkeypatch.setattr(mod.os, "urandom", lambda n: fixed[:n])
        a = hash_password("hunter2", "ssha512")
        b = hash_password("hunter2", "ssha512")
        assert a == b

    def test_argon2id_body_is_opaque(self) -> None:
        """Argon2 has its own salt handling; we just check the output
        has a non-empty body past the tag and round-trips through the
        argon2 verifier."""
        from argon2 import PasswordHasher
        from argon2.low_level import Type

        out = hash_password("hunter2", "argon2id").decode("utf-8")
        assert out.startswith("{ARGON2}")
        body = out[len("{ARGON2}") :]
        # The body is the standard argon2 MCF string.
        assert body.startswith("$argon2id$")
        ph = PasswordHasher(type=Type.ID)
        assert ph.verify(body, "hunter2") is True


class TestResolveHashScheme:
    def setup_method(self) -> None:
        _DETECT_CACHE.clear()

    def test_auto_delegates_to_detect(self) -> None:
        """hash_scheme='auto' resolves to whatever the server advertises."""
        backend = _FakeBackend([_olc_entry("{SSHA512}", "{SSHA}")])
        cfg = Config()
        cfg.password.hash_scheme = "auto"
        assert resolve_hash_scheme(cfg, backend) == "ssha512"  # type: ignore[arg-type]

    def test_explicit_overrides_detection(self) -> None:
        """Concrete scheme in config overrides server advertisement."""
        # Server says argon2id; operator says ssha; operator wins.
        backend = _FakeBackend([_olc_entry("{ARGON2}", "{SSHA512}", "{SSHA}")])
        cfg = Config()
        cfg.password.hash_scheme = "ssha"
        assert resolve_hash_scheme(cfg, backend) == "ssha"  # type: ignore[arg-type]
        # Detection never ran, so the cache stays empty.
        assert backend.calls == 0

    def test_legacy_bracketed_scheme_accepted(self) -> None:
        backend = _FakeBackend([])
        cfg = Config()
        cfg.password.hash_scheme = "{SSHA512}"
        assert resolve_hash_scheme(cfg, backend) == "ssha512"  # type: ignore[arg-type]
