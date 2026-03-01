"""Tests for ldap_manager.config."""

from __future__ import annotations

from pathlib import Path

import pytest

from ldap_manager.config import Config, UsersConfig, load_config


class TestLoadConfig:
    def test_defaults_when_no_file(self) -> None:
        cfg = load_config(None)
        assert cfg.ldap.uri == "ldap://localhost:389"
        assert cfg.users.default_shell == "/bin/bash"
        assert cfg.backup.retention_count == 10
        assert cfg.password.generated_length == 20

    def test_from_yaml_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.yaml"
        f.write_text("ldap:\n  uri: ldap://myserver:389\n  bind_dn: cn=admin,dc=foo,dc=bar\nusers:\n  uid_min: 5000\n")
        cfg = load_config(f)
        assert cfg.ldap.uri == "ldap://myserver:389"
        assert cfg.ldap.bind_dn == "cn=admin,dc=foo,dc=bar"
        assert cfg.users.uid_min == 5000

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LDAP_URI", "ldaps://secure.example.com")
        monkeypatch.setenv("LDAP_BIND_PASSWORD", "env_secret")
        cfg = load_config(None)
        assert cfg.ldap.uri == "ldaps://secure.example.com"
        assert cfg.ldap.bind_password == "env_secret"

    def test_env_boolean_coercion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LDAP_START_TLS", "true")
        cfg = load_config(None)
        assert cfg.ldap.start_tls is True

    def test_env_override_beats_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        f = tmp_path / "test.yaml"
        f.write_text("ldap:\n  uri: ldap://from-file\n")
        monkeypatch.setenv("LDAP_URI", "ldap://from-env")
        cfg = load_config(f)
        assert cfg.ldap.uri == "ldap://from-env"


class TestConfigDataclass:
    def test_defaults(self) -> None:
        cfg = Config()
        assert cfg.ldap.timeout == 10
        assert cfg.users.object_classes == ["inetOrgPerson", "posixAccount", "shadowAccount"]

    def test_users_config_new_fields(self) -> None:
        u = UsersConfig(mail_domain="corp.com", generate_password_on_create=True)
        assert u.mail_domain == "corp.com"
        assert u.generate_password_on_create is True
        assert u.default_password == "123456"

    def test_dot_access(self, cfg: Config) -> None:
        assert cfg.ldap.uri == "ldap://localhost"
        assert cfg.users.disabled_shell == "/sbin/nologin"
        assert cfg.backup.slapcat_bin == "/usr/sbin/slapcat"
