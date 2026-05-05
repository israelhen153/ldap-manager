"""Tests for ldap_manager.backends.generic.GenericBackend.

These tests patch ``ldap3.Connection`` at the module level where
``GenericBackend`` imports it, so no real network traffic is attempted
and the unit under test is exactly the translation layer: scope
mapping, MOD_ → MODIFY_ mapping, entry extraction, and StartTLS
conditional.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import ldap
import ldap3
import pytest
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from ldap_manager.backends.generic import _MOD_MAP, _SCOPE_MAP, GenericBackend
from ldap_manager.config import LDAPConfig, SchemaConfig

# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def ldap_cfg() -> LDAPConfig:
    return LDAPConfig(
        uri="ldap://localhost:389",
        bind_dn="cn=admin,dc=test,dc=com",
        bind_password="secret",
        base_dn="dc=test,dc=com",
        users_ou="ou=People,dc=test,dc=com",
        groups_ou="ou=Groups,dc=test,dc=com",
        start_tls=False,
        timeout=5,
    )


@pytest.fixture
def ldaps_cfg() -> LDAPConfig:
    return LDAPConfig(
        uri="ldaps://secure.example.com:636",
        bind_dn="cn=admin,dc=test,dc=com",
        bind_password="secret",
        base_dn="dc=test,dc=com",
        users_ou="ou=People,dc=test,dc=com",
        groups_ou="ou=Groups,dc=test,dc=com",
        start_tls=True,
        timeout=5,
    )


@pytest.fixture
def starttls_cfg() -> LDAPConfig:
    return LDAPConfig(
        uri="ldap://starttls.example.com:389",
        bind_dn="cn=admin,dc=test,dc=com",
        bind_password="secret",
        base_dn="dc=test,dc=com",
        users_ou="ou=People,dc=test,dc=com",
        groups_ou="ou=Groups,dc=test,dc=com",
        start_tls=True,
        timeout=5,
    )


# ── Translation tables ─────────────────────────────────────────────


class TestTranslationMaps:
    """The maps are load-bearing — tests pin the contract."""

    def test_scope_map_covers_all_three_python_ldap_scopes(self) -> None:
        assert _SCOPE_MAP[ldap.SCOPE_BASE] == ldap3.BASE
        assert _SCOPE_MAP[ldap.SCOPE_ONELEVEL] == ldap3.LEVEL
        assert _SCOPE_MAP[ldap.SCOPE_SUBTREE] == ldap3.SUBTREE

    def test_mod_map_covers_add_replace_delete(self) -> None:
        assert _MOD_MAP[ldap.MOD_ADD] == MODIFY_ADD
        assert _MOD_MAP[ldap.MOD_REPLACE] == MODIFY_REPLACE
        assert _MOD_MAP[ldap.MOD_DELETE] == MODIFY_DELETE


# ── Lifecycle / connect ────────────────────────────────────────────


class TestConnect:
    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_connect_binds_without_starttls(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        mock_server.assert_called_once_with(ldap_cfg.uri, connect_timeout=ldap_cfg.timeout)
        mock_conn.open.assert_called_once()
        mock_conn.start_tls.assert_not_called()
        mock_conn.bind.assert_called_once()

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_starttls_only_on_ldap_scheme(
        self, mock_server: MagicMock, mock_conn_cls: MagicMock, starttls_cfg: LDAPConfig
    ) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(starttls_cfg)
        backend.bind()
        mock_conn.open.assert_called_once()
        mock_conn.start_tls.assert_called_once()
        mock_conn.bind.assert_called_once()
        # StartTLS must come between open() and bind().
        call_order = [c[0] for c in mock_conn.mock_calls if c[0] in ("open", "start_tls", "bind")]
        assert call_order == ["open", "start_tls", "bind"]

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_no_starttls_on_ldaps_scheme(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldaps_cfg: LDAPConfig) -> None:
        # ldaps:// already encrypted — StartTLS would be a protocol error.
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldaps_cfg)
        backend.bind()
        mock_conn.start_tls.assert_not_called()

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_bind_is_idempotent(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn_cls.return_value = MagicMock()
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        backend.bind()
        assert mock_conn_cls.call_count == 1

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_context_manager_binds_and_closes(
        self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig
    ) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        with GenericBackend(ldap_cfg) as backend:
            assert backend is not None
        mock_conn.unbind.assert_called_once()


# ── Search ─────────────────────────────────────────────────────────


class TestSearch:
    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_search_translates_scope_subtree(
        self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig
    ) -> None:
        mock_conn = MagicMock()
        mock_conn.response = []
        mock_conn_cls.return_value = mock_conn

        backend = GenericBackend(ldap_cfg)
        backend.bind()
        backend.search("dc=test,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)", ["uid"])

        mock_conn.search.assert_called_once_with(
            search_base="dc=test,dc=com",
            search_filter="(objectClass=*)",
            search_scope=ldap3.SUBTREE,
            attributes=["uid"],
        )

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_search_translates_scope_base_and_onelevel(
        self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig
    ) -> None:
        mock_conn = MagicMock()
        mock_conn.response = []
        mock_conn_cls.return_value = mock_conn

        backend = GenericBackend(ldap_cfg)
        backend.bind()
        backend.search("dc=test,dc=com", ldap.SCOPE_BASE, "(objectClass=*)")
        assert mock_conn.search.call_args.kwargs["search_scope"] == ldap3.BASE

        backend.search("dc=test,dc=com", ldap.SCOPE_ONELEVEL, "(objectClass=*)")
        assert mock_conn.search.call_args.kwargs["search_scope"] == ldap3.LEVEL

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_search_none_attrs_requests_all(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.response = []
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        backend.search("dc=test,dc=com", ldap.SCOPE_SUBTREE, "(uid=*)", None)
        assert mock_conn.search.call_args.kwargs["attributes"] == ldap3.ALL_ATTRIBUTES

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_search_filters_out_referrals_and_extracts_raw_attributes(
        self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig
    ) -> None:
        """Only searchResEntry records come back; bytes come from raw_attributes."""
        mock_conn = MagicMock()
        mock_conn.response = [
            {
                "type": "searchResEntry",
                "dn": "uid=alice,ou=People,dc=test,dc=com",
                "attributes": {"uid": ["alice"]},  # decoded — we must NOT use this
                "raw_attributes": {"uid": [b"alice"], "cn": [b"Alice Example"]},
            },
            {
                "type": "searchResRef",  # must be skipped
                "uri": ["ldap://other.example.com/"],
            },
            {
                "type": "searchResEntry",
                "dn": "uid=bob,ou=People,dc=test,dc=com",
                "raw_attributes": {"uid": [b"bob"]},
            },
        ]
        mock_conn_cls.return_value = mock_conn

        backend = GenericBackend(ldap_cfg)
        backend.bind()
        results = backend.search("dc=test,dc=com", ldap.SCOPE_SUBTREE, "(uid=*)")

        assert len(results) == 2
        dn0, attrs0 = results[0]
        assert dn0 == "uid=alice,ou=People,dc=test,dc=com"
        assert attrs0 == {"uid": [b"alice"], "cn": [b"Alice Example"]}
        dn1, attrs1 = results[1]
        assert dn1 == "uid=bob,ou=People,dc=test,dc=com"
        assert attrs1 == {"uid": [b"bob"]}

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_search_handles_empty_response(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.response = None  # ldap3 leaves this None before first search sometimes
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        assert backend.search("dc=test,dc=com", ldap.SCOPE_SUBTREE, "(uid=foo)") == []


# ── Add ────────────────────────────────────────────────────────────


class TestAdd:
    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_add_converts_tuple_list_to_dict(
        self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig
    ) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()

        modlist = [
            ("objectClass", [b"inetOrgPerson", b"posixAccount"]),
            ("uid", [b"alice"]),
            ("cn", [b"Alice"]),
        ]
        backend.add("uid=alice,ou=People,dc=test,dc=com", modlist)

        mock_conn.add.assert_called_once()
        call_args = mock_conn.add.call_args
        assert call_args.args[0] == "uid=alice,ou=People,dc=test,dc=com"
        assert call_args.kwargs["attributes"] == {
            "objectClass": [b"inetOrgPerson", b"posixAccount"],
            "uid": [b"alice"],
            "cn": [b"Alice"],
        }

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_add_accepts_dict_directly(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()

        attrs = {"objectClass": [b"inetOrgPerson"], "uid": [b"bob"]}
        backend.add("uid=bob,ou=People,dc=test,dc=com", attrs)
        assert mock_conn.add.call_args.kwargs["attributes"] == attrs


# ── Modify ─────────────────────────────────────────────────────────


class TestModify:
    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_modify_maps_all_three_ops(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()

        changes: list[tuple[int, str, list[bytes] | None]] = [
            (ldap.MOD_REPLACE, "mail", [b"new@test.com"]),
            (ldap.MOD_ADD, "memberUid", [b"carol"]),
            (ldap.MOD_DELETE, "description", None),
        ]
        backend.modify("uid=alice,ou=People,dc=test,dc=com", changes)

        mock_conn.modify.assert_called_once()
        dn_arg, grouped = mock_conn.modify.call_args.args
        assert dn_arg == "uid=alice,ou=People,dc=test,dc=com"
        assert grouped == {
            "mail": [(MODIFY_REPLACE, [b"new@test.com"])],
            "memberUid": [(MODIFY_ADD, [b"carol"])],
            "description": [(MODIFY_DELETE, [])],
        }

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_modify_groups_multiple_ops_on_same_attr(
        self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig
    ) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()

        # Stage A's modules sometimes emit delete-then-add on the same
        # attribute (password rotation, key rotation). Order must survive
        # the grouping so the server applies it correctly.
        changes: list[tuple[int, str, list[bytes] | None]] = [
            (ldap.MOD_DELETE, "sshPublicKey", [b"old-key"]),
            (ldap.MOD_ADD, "sshPublicKey", [b"new-key"]),
        ]
        backend.modify("uid=alice,ou=People,dc=test,dc=com", changes)

        _, grouped = mock_conn.modify.call_args.args
        assert grouped == {
            "sshPublicKey": [
                (MODIFY_DELETE, [b"old-key"]),
                (MODIFY_ADD, [b"new-key"]),
            ]
        }


# ── Delete ─────────────────────────────────────────────────────────


class TestDelete:
    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_delete_passes_dn_verbatim(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        backend.delete("uid=alice,ou=People,dc=test,dc=com")
        mock_conn.delete.assert_called_once_with("uid=alice,ou=People,dc=test,dc=com")


# ── Compare ────────────────────────────────────────────────────────


class TestCompare:
    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_compare_returns_backing_bool(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.compare.return_value = True
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        assert backend.compare("uid=alice,ou=People,dc=test,dc=com", "uid", "alice") is True
        mock_conn.compare.assert_called_once_with("uid=alice,ou=People,dc=test,dc=com", "uid", "alice")

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_compare_returns_false_without_raising(
        self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig
    ) -> None:
        mock_conn = MagicMock()
        mock_conn.compare.return_value = False
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        assert backend.compare("uid=alice,ou=People,dc=test,dc=com", "uid", "bob") is False


# ── Close ──────────────────────────────────────────────────────────


class TestClose:
    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_close_swallows_ldapexception(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn = MagicMock()
        mock_conn.unbind.side_effect = LDAPException("server gone")
        mock_conn_cls.return_value = mock_conn
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        # Must not raise.
        backend.close()
        assert backend._conn is None

    @patch("ldap_manager.backends.generic.Connection")
    @patch("ldap_manager.backends.generic.Server")
    def test_close_is_safe_twice(self, mock_server: MagicMock, mock_conn_cls: MagicMock, ldap_cfg: LDAPConfig) -> None:
        mock_conn_cls.return_value = MagicMock()
        backend = GenericBackend(ldap_cfg)
        backend.bind()
        backend.close()
        backend.close()  # idempotent


# ── Schema / capabilities ──────────────────────────────────────────


class TestSchemaWiring:
    def test_no_schema_supports_is_empty(self, ldap_cfg: LDAPConfig) -> None:
        backend = GenericBackend(ldap_cfg)
        assert backend.supports == frozenset()

    def test_schema_with_supports_seeds_instance(self, ldap_cfg: LDAPConfig) -> None:
        schema = SchemaConfig()
        # Attach supports to the schema instance — the profiles module
        # returns schema + supports together; here we simulate the
        # final wired object.
        schema.supports = frozenset({"posix_accounts", "cn_config_probe"})  # type: ignore[attr-defined]
        backend = GenericBackend(ldap_cfg, schema=schema)
        assert backend.supports == frozenset({"posix_accounts", "cn_config_probe"})

    def test_schema_without_supports_leaves_default(self, ldap_cfg: LDAPConfig) -> None:
        schema = SchemaConfig()
        backend = GenericBackend(ldap_cfg, schema=schema)
        assert backend.supports == frozenset()
