"""python-ldap backed implementation of :class:`Backend`.

Wraps a single ``ldap.ldapobject.LDAPObject`` and exposes it through the
Protocol's verb names (``search`` not ``search_s``, etc.). The class
handles bind, TLS, and cleanup the same way the old
``LDAPConnection`` did — the body of :meth:`bind` is the old
``_connect`` verbatim.

Context-manager semantics:
  * ``__enter__`` binds and returns ``self`` (the backend instance).
    Callers get a Backend, not a raw LDAPObject.
  * ``__exit__`` calls :meth:`close`, which swallows LDAPError on
    ``unbind_s`` — disconnect failures during cleanup shouldn't mask
    the original exception.
"""

from __future__ import annotations

import logging
from types import TracebackType
from typing import TYPE_CHECKING

import ldap
from ldap.ldapobject import LDAPObject

if TYPE_CHECKING:
    from ..config import LDAPConfig
    from .base import Entry

log = logging.getLogger(__name__)


class OpenLDAPBackend:
    """Backend implementation targeting OpenLDAP via python-ldap."""

    #: Capability markers. Stage A fills in what the current codebase
    #: actually exercises against OpenLDAP. Stage B / ldap3 backend will
    #: publish a narrower set and consumers will gate on membership.
    supports: frozenset[str] = frozenset(
        {
            "backup",
            "server_ops",
            "ppolicy_overlay",
            "cn_config_probe",
            "password_hash_client",
            "ssh_public_key_schema",
            "posix_accounts",
        }
    )

    def __init__(self, cfg: LDAPConfig) -> None:
        self._cfg = cfg
        self._conn: LDAPObject | None = None

    # ── Context manager ────────────────────────────────────────────
    def __enter__(self) -> OpenLDAPBackend:
        self.bind()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    # ── Backend Protocol ───────────────────────────────────────────
    def bind(self) -> None:
        if self._conn is not None:
            return
        self._conn = self._connect()

    def search(
        self,
        base: str,
        scope: int,
        filterstr: str,
        attrs: list[str] | None = None,
    ) -> list[Entry]:
        assert self._conn is not None, "bind() not called"
        results: list[Entry] = self._conn.search_s(base, scope, filterstr, attrs)
        return results

    def add(
        self,
        dn: str,
        attrs: list[tuple[str, list[bytes]]] | dict[str, list[bytes]],
    ) -> None:
        assert self._conn is not None, "bind() not called"
        self._conn.add_s(dn, attrs)

    def modify(
        self,
        dn: str,
        changes: list[tuple[int, str, list[bytes] | None]],
    ) -> None:
        assert self._conn is not None, "bind() not called"
        self._conn.modify_s(dn, changes)

    def delete(self, dn: str) -> None:
        assert self._conn is not None, "bind() not called"
        self._conn.delete_s(dn)

    def compare(self, dn: str, attr: str, value: str) -> bool:
        # Stage B fills this in — no module in the codebase calls
        # compare_s today, and the return semantics for ldap3 vs
        # python-ldap differ enough that speculating here would bake
        # in a contract we haven't tested.
        raise NotImplementedError("compare() is not yet implemented")

    def close(self) -> None:
        if self._conn is None:
            return
        try:
            self._conn.unbind_s()
        except ldap.LDAPError:
            pass
        self._conn = None

    # ── Internal ───────────────────────────────────────────────────
    def _connect(self) -> LDAPObject:
        log.debug("Connecting to %s", self._cfg.uri)

        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        if self._cfg.tls_cacert:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self._cfg.tls_cacert)

        conn = ldap.initialize(self._cfg.uri)
        conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, self._cfg.timeout)
        conn.set_option(ldap.OPT_REFERRALS, 0)

        if self._cfg.start_tls and self._cfg.uri.startswith("ldap://"):
            log.debug("Initiating StartTLS")
            conn.start_tls_s()

        conn.simple_bind_s(self._cfg.bind_dn, self._cfg.bind_password)
        log.debug("Bound as %s", self._cfg.bind_dn)
        return conn
