"""Tests for ldap_manager.ldif_ops - LDIF export/import."""

from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import MagicMock

import ldap
import pytest

from ldap_manager.backends import Backend
from ldap_manager.config import Config
from ldap_manager.ldif_ops import _needs_base64, _parse_ldif, export_ldif, import_ldif


@pytest.fixture
def cfg() -> Config:
    return Config()


@pytest.fixture
def mock_backend() -> MagicMock:
    mock = MagicMock(spec=Backend)
    mock.supports = frozenset()
    return mock


class TestNeedsBase64:
    def test_normal_text(self) -> None:
        assert _needs_base64("hello world") is False

    def test_leading_space(self) -> None:
        assert _needs_base64(" leading space") is True

    def test_leading_colon(self) -> None:
        assert _needs_base64(":starts with colon") is True

    def test_trailing_space(self) -> None:
        assert _needs_base64("trailing space ") is True

    def test_control_chars(self) -> None:
        assert _needs_base64("has\x00null") is True

    def test_empty_string(self) -> None:
        assert _needs_base64("") is False


class TestExportLdif:
    def test_export_users(self, cfg: Config, mock_backend: MagicMock) -> None:
        mock_backend.search.return_value = [
            (
                "uid=jdoe,ou=People,dc=example,dc=com",
                {
                    "uid": [b"jdoe"],
                    "cn": [b"John Doe"],
                    "objectClass": [b"posixAccount", b"inetOrgPerson"],
                },
            ),
        ]
        result = export_ldif(mock_backend, cfg)
        assert "dn: uid=jdoe" in result
        assert "uid: jdoe" in result
        assert "cn: John Doe" in result

    def test_export_binary_value(self, cfg: Config, mock_backend: MagicMock) -> None:
        binary_data = bytes(range(256))
        mock_backend.search.return_value = [
            (
                "uid=jdoe,ou=People,dc=example,dc=com",
                {
                    "userPassword": [binary_data],
                },
            ),
        ]
        result = export_ldif(mock_backend, cfg)
        assert "userPassword::" in result

    def test_export_to_file(self, cfg: Config, mock_backend: MagicMock, tmp_path: Path) -> None:
        mock_backend.search.return_value = [
            ("uid=jdoe,ou=People,dc=example,dc=com", {"uid": [b"jdoe"]}),
        ]
        out = tmp_path / "export.ldif"
        export_ldif(mock_backend, cfg, output=out)
        assert out.is_file()
        assert "uid=jdoe" in out.read_text()

    def test_export_empty(self, cfg: Config, mock_backend: MagicMock) -> None:
        mock_backend.search.return_value = []
        result = export_ldif(mock_backend, cfg)
        assert "# LDIF export" in result


class TestParseLdif:
    def test_parse_simple(self, tmp_path: Path) -> None:
        ldif = tmp_path / "test.ldif"
        ldif.write_text("dn: uid=jdoe,ou=People,dc=example,dc=com\nuid: jdoe\ncn: John Doe\nobjectClass: posixAccount\n")
        entries = _parse_ldif(ldif)
        assert len(entries) == 1
        dn, attrs = entries[0]
        assert dn == "uid=jdoe,ou=People,dc=example,dc=com"
        assert attrs["uid"] == [b"jdoe"]

    def test_parse_base64_value(self, tmp_path: Path) -> None:
        encoded = base64.b64encode(b"binary data").decode()
        ldif = tmp_path / "test.ldif"
        ldif.write_text(f"dn: uid=jdoe,ou=People,dc=example,dc=com\nuserPassword:: {encoded}\n")
        entries = _parse_ldif(ldif)
        assert entries[0][1]["userPassword"] == [b"binary data"]

    def test_parse_line_folding(self, tmp_path: Path) -> None:
        ldif = tmp_path / "test.ldif"
        ldif.write_text("dn: uid=jdoe,ou=People,dc=ple,dc=com\ndescription: This is a very long \n description that wraps\n")
        entries = _parse_ldif(ldif)
        ldif_entry = entries[0][1]["description"][0].decode()
        assert ldif_entry == "This is a very long description that wraps"

    def test_parse_no_folding_without_space(self, tmp_path: Path) -> None:
        ldif = tmp_path / "test.ldif"
        ldif.write_text("dn: uid=jdoe,ou=People,dc=example,dc=com\ndescription: first line\ndescription: second line\n\n")
        entries = _parse_ldif(ldif)
        assert len(entries[0][1]["description"]) == 2

    def test_parse_skips_comments(self, tmp_path: Path) -> None:
        ldif = tmp_path / "test.ldif"
        ldif.write_text("# This is a comment\ndn: uid=jdoe,ou=People,dc=example,dc=com\nuid: jdoe\n")
        entries = _parse_ldif(ldif)
        assert len(entries) == 1

    def test_parse_multiple_entries(self, tmp_path: Path) -> None:
        ldif = tmp_path / "test.ldif"
        ldif.write_text(
            "dn: uid=alice,ou=People,dc=example,dc=com\nuid: alice\n\ndn: uid=bob,ou=People,dc=example,dc=com\nuid: bob\n"
        )
        entries = _parse_ldif(ldif)
        assert len(entries) == 2


class TestImportLdif:
    def test_import_dry_run(self, mock_backend: MagicMock, tmp_path: Path) -> None:
        ldif = tmp_path / "import.ldif"
        ldif.write_text("dn: uid=jdoe,ou=People,dc=example,dc=com\nuid: jdoe\nobjectClass: posixAccount\n")
        counts = import_ldif(mock_backend, ldif, dry_run=True)
        assert counts["added"] == 1
        mock_backend.add.assert_not_called()

    def test_import_real(self, mock_backend: MagicMock, tmp_path: Path) -> None:
        ldif = tmp_path / "import.ldif"
        ldif.write_text("dn: uid=jdoe,ou=People,dc=example,dc=com\nuid: jdoe\n")
        counts = import_ldif(mock_backend, ldif)
        assert counts["added"] == 1
        mock_backend.add.assert_called_once()

    def test_import_already_exists(self, mock_backend: MagicMock, tmp_path: Path) -> None:
        ldif = tmp_path / "import.ldif"
        ldif.write_text("dn: uid=jdoe,ou=People,dc=example,dc=com\nuid: jdoe\n")
        mock_backend.add.side_effect = ldap.ALREADY_EXISTS
        counts = import_ldif(mock_backend, ldif)
        assert counts["skipped"] == 1

    def test_import_file_not_found(self, mock_backend: MagicMock, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            import_ldif(mock_backend, tmp_path / "nonexistent.ldif")
