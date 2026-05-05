"""Tests for ldap_manager.backends.build_backend dispatch.

``build_backend`` is the single choke point that decides which Backend
class to instantiate, so these tests are short and focused: each known
value maps to the right class, each unknown value raises.
"""

from __future__ import annotations

import pytest

from ldap_manager.backends import GenericBackend, OpenLDAPBackend, build_backend
from ldap_manager.config import Config, SchemaConfig


class TestBuildBackend:
    def test_openldap_returns_openldap_backend(self) -> None:
        cfg = Config()
        cfg.backend = "openldap"
        backend = build_backend(cfg)
        assert isinstance(backend, OpenLDAPBackend)

    def test_generic_returns_generic_backend(self) -> None:
        cfg = Config()
        cfg.backend = "generic"
        backend = build_backend(cfg)
        assert isinstance(backend, GenericBackend)

    def test_generic_threads_schema_through(self) -> None:
        cfg = Config()
        cfg.backend = "generic"
        cfg.schema = SchemaConfig(user_id_attr="sAMAccountName")
        backend = build_backend(cfg)
        assert isinstance(backend, GenericBackend)
        # The backend keeps the schema so future calls that care about
        # directory-specific attribute names can reach it.
        assert backend._schema is cfg.schema

    def test_default_config_uses_openldap(self) -> None:
        # Default ``Config()`` has ``backend="openldap"`` — every
        # existing deployment gets the historical backend with no
        # change to config.
        cfg = Config()
        assert cfg.backend == "openldap"
        assert isinstance(build_backend(cfg), OpenLDAPBackend)

    def test_unknown_backend_raises_with_choices(self) -> None:
        cfg = Config()
        cfg.backend = "freeipa"
        with pytest.raises(ValueError, match="Unknown backend") as exc:
            build_backend(cfg)
        # Message must mention every valid choice so the typo is easy
        # to correct without reading the source.
        msg = str(exc.value)
        assert "openldap" in msg
        assert "generic" in msg

    def test_empty_backend_raises(self) -> None:
        cfg = Config()
        cfg.backend = ""
        with pytest.raises(ValueError, match="Unknown backend"):
            build_backend(cfg)
