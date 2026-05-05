"""Tests for the doctor command.

Only tests the filesystem / config checks — LDAP checks require a
live server and are covered by the integration test suite (phase 20).
"""

import os

from ldap_manager.doctor import Check, _check_config_perms, _check_directory


class TestCheckDirectory:
    def test_exists_and_writable(self, tmp_path):
        check = _check_directory(str(tmp_path), "test dir")
        assert check.passed

    def test_missing_is_fixable(self, tmp_path):
        path = str(tmp_path / "nonexistent")
        check = _check_directory(path, "test dir")
        assert not check.passed
        assert check.fixable

    def test_fix_creates_directory(self, tmp_path):
        path = str(tmp_path / "newdir")
        check = _check_directory(path, "test dir")
        check.fix_fn()
        assert os.path.isdir(path)
        assert oct(os.stat(path).st_mode)[-3:] == "700"

    def test_not_writable(self, tmp_path):
        path = str(tmp_path / "readonly")
        os.makedirs(path)
        os.chmod(path, 0o444)
        check = _check_directory(path, "test dir")
        assert not check.passed
        assert check.fixable
        os.chmod(path, 0o700)  # restore for cleanup


class TestCheckConfigPerms:
    def test_secure_600(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("test: true")
        os.chmod(str(f), 0o600)
        check = _check_config_perms(str(f))
        assert check.passed

    def test_secure_400(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("test: true")
        os.chmod(str(f), 0o400)
        check = _check_config_perms(str(f))
        assert check.passed

    def test_too_open_is_fixable(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("test: true")
        os.chmod(str(f), 0o644)
        check = _check_config_perms(str(f))
        assert not check.passed
        assert check.fixable

    def test_fix_sets_600(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("test: true")
        os.chmod(str(f), 0o644)
        check = _check_config_perms(str(f))
        check.fix_fn()
        assert oct(os.stat(str(f)).st_mode)[-3:] == "600"

    def test_missing_file(self):
        check = _check_config_perms("/nonexistent/config.yaml")
        assert not check.passed
        assert not check.fixable


class TestCheck:
    def test_passed(self):
        c = Check("test", True)
        assert c.passed
        assert c.detail == ""

    def test_failed(self):
        c = Check("test", False, detail="broken")
        assert not c.passed
        assert c.detail == "broken"

    def test_fixable(self):
        fixed = False
        def fix():
            nonlocal fixed
            fixed = True
        c = Check("test", False, fixable=True, fix_fn=fix)
        c.fix_fn()
        assert fixed
