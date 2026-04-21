"""Tests for ldap_manager.config."""

from __future__ import annotations

from pathlib import Path

import pytest

from ldap_manager.backends.schemas import get_schema_profile
from ldap_manager.config import Config, SchemaConfig, UsersConfig, load_config


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
        # Item 6: default is now 'auto', not '{SSHA}'.
        assert cfg.password.hash_scheme == "auto"

    def test_users_config_new_fields(self) -> None:
        u = UsersConfig(mail_domain="corp.com", generate_password_on_create=True)
        assert u.mail_domain == "corp.com"
        assert u.generate_password_on_create is True
        assert u.default_password == "123456"

    def test_dot_access(self, cfg: Config) -> None:
        assert cfg.ldap.uri == "ldap://localhost"
        assert cfg.users.disabled_shell == "/sbin/nologin"
        assert cfg.backup.slapcat_bin == "/usr/sbin/slapcat"


class TestSchemaConfigDefaults:
    """SchemaConfig defaults = OpenLDAP POSIX profile (historical behaviour)."""

    def test_defaults_are_openldap_posix(self) -> None:
        s = SchemaConfig()
        assert s.user_id_attr == "uid"
        assert s.user_object_class == "inetOrgPerson"
        assert s.disable_mechanism == "login_shell"
        assert s.group_membership_attr == "memberUid"

    def test_top_level_backend_default_is_openldap(self) -> None:
        cfg = Config()
        assert cfg.backend == "openldap"
        # Round-trip through load_config (no file, no env) stays on default.
        fresh = load_config(None)
        assert fresh.backend == "openldap"

    def test_backend_and_schema_round_trip_from_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "ad.yaml"
        f.write_text(
            "backend: generic\n"
            "schema:\n"
            "  user_id_attr: sAMAccountName\n"
            "  user_object_class: user\n"
            "  disable_mechanism: uac_bit\n"
            "  group_membership_attr: member\n"
        )
        cfg = load_config(f)
        assert cfg.backend == "generic"
        assert cfg.schema.user_id_attr == "sAMAccountName"
        assert cfg.schema.user_object_class == "user"
        assert cfg.schema.disable_mechanism == "uac_bit"
        assert cfg.schema.group_membership_attr == "member"


class TestSchemaProfiles:
    """One profile per directory flavour — contract test per row."""

    def test_openldap_posix_profile(self) -> None:
        schema, supports = get_schema_profile("openldap_posix")
        assert schema.user_id_attr == "uid"
        assert schema.user_object_class == "inetOrgPerson"
        assert schema.disable_mechanism == "login_shell"
        assert schema.group_membership_attr == "memberUid"
        # openldap_posix publishes the OpenLDAP-specific markers MINUS
        # ``backup`` and ``server_ops`` — those need local binaries the
        # generic backend can't exec.
        assert supports == frozenset(
            {
                "ppolicy_overlay",
                "cn_config_probe",
                "password_hash_client",
                "ssh_public_key_schema",
                "posix_accounts",
            }
        )
        assert "backup" not in supports
        assert "server_ops" not in supports

    def test_active_directory_profile(self) -> None:
        schema, supports = get_schema_profile("active_directory")
        assert schema.user_id_attr == "sAMAccountName"
        assert schema.user_object_class == "user"
        assert schema.disable_mechanism == "uac_bit"
        assert schema.group_membership_attr == "member"
        # AD lacks every OpenLDAP-specific capability in our set.
        assert supports == frozenset()

    def test_389ds_profile(self) -> None:
        schema, supports = get_schema_profile("389ds")
        assert schema.user_id_attr == "uid"
        assert schema.user_object_class == "inetOrgPerson"
        assert schema.disable_mechanism == "login_shell"
        assert schema.group_membership_attr == "member"  # groupOfNames, not memberUid
        assert supports == frozenset(
            {
                "cn_config_probe",
                "password_hash_client",
                "posix_accounts",
            }
        )
        # 389ds has no openldap ppolicy overlay, no openssh-lpk by default.
        assert "ppolicy_overlay" not in supports
        assert "ssh_public_key_schema" not in supports

    def test_unknown_profile_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown schema profile"):
            get_schema_profile("freeipa")

    def test_profile_returns_fresh_instance(self) -> None:
        """Mutating one caller's profile must not leak into another's."""
        a, _ = get_schema_profile("active_directory")
        b, _ = get_schema_profile("active_directory")
        assert a is not b
        a.user_id_attr = "mutated"
        assert b.user_id_attr == "sAMAccountName"

    def test_profile_attaches_supports_to_schema(self) -> None:
        """GenericBackend reads ``schema.supports``; profile must set it."""
        schema, supports = get_schema_profile("openldap_posix")
        assert getattr(schema, "supports", None) == supports
