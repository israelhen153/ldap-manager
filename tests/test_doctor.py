"""Tests for the doctor command.

Only tests the filesystem / config checks — LDAP checks require a
live server and are covered by the integration test suite (phase 20).
"""

import os
from pathlib import Path

import pytest

from ldap_manager.doctor import Check, _check_config_perms, _check_directory


class TestCheckDirectory:
    def test_exists_and_writable(self, tmp_path: Path) -> None:
        check = _check_directory(str(tmp_path), "test dir")
        assert check.passed

    def test_missing_is_fixable(self, tmp_path: Path) -> None:
        path = str(tmp_path / "nonexistent")
        check = _check_directory(path, "test dir")
        assert not check.passed
        assert check.fixable

    def test_fix_creates_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "newdir"
        check = _check_directory(str(target), "test dir")
        check.fix_fn()
        assert target.is_dir()
        assert oct(target.stat().st_mode)[-3:] == "700"

    def test_not_writable(self, tmp_path: Path) -> None:
        if os.getuid() == 0:
            pytest.skip("root bypasses filesystem permission checks")
        target = tmp_path / "readonly"
        target.mkdir()
        target.chmod(0o444)
        check = _check_directory(str(target), "test dir")
        assert not check.passed
        assert check.fixable
        target.chmod(0o700)  # restore for cleanup


class TestCheckConfigPerms:
    def test_secure_600(self, tmp_path: Path) -> None:
        f = tmp_path / "config.yaml"
        f.write_text("test: true")
        f.chmod(0o600)
        check = _check_config_perms(str(f))
        assert check.passed

    def test_secure_400(self, tmp_path: Path) -> None:
        f = tmp_path / "config.yaml"
        f.write_text("test: true")
        f.chmod(0o400)
        check = _check_config_perms(str(f))
        assert check.passed

    def test_too_open_is_fixable(self, tmp_path: Path) -> None:
        f = tmp_path / "config.yaml"
        f.write_text("test: true")
        f.chmod(0o644)
        check = _check_config_perms(str(f))
        assert not check.passed
        assert check.fixable

    def test_fix_sets_600(self, tmp_path: Path) -> None:
        f = tmp_path / "config.yaml"
        f.write_text("test: true")
        f.chmod(0o644)
        check = _check_config_perms(str(f))
        check.fix_fn()
        assert oct(f.stat().st_mode)[-3:] == "600"

    def test_missing_file(self) -> None:
        check = _check_config_perms("/nonexistent/config.yaml")
        assert not check.passed
        assert not check.fixable


class TestCheck:
    def test_passed(self) -> None:
        c = Check("test", True)
        assert c.passed
        assert c.detail == ""

    def test_failed(self) -> None:
        c = Check("test", False, detail="broken")
        assert not c.passed
        assert c.detail == "broken"

    def test_fixable(self) -> None:
        fixed = False

        def fix() -> None:
            nonlocal fixed
            fixed = True

        c = Check("test", False, fixable=True, fix_fn=fix)
        c.fix_fn()
        assert fixed
