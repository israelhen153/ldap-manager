"""LDAP connection management.

Provides a context-managed connection that handles bind, TLS, and cleanup.
"""

from __future__ import annotations

import logging
from types import TracebackType

import ldap
from ldap.ldapobject import LDAPObject

from .config import LDAPConfig

log = logging.getLogger(__name__)


class LDAPConnection:
    """Context-managed LDAP connection.

    Usage:
        with LDAPConnection(cfg) as conn:
            conn.search_s(...)
    """

    def __init__(self, cfg: LDAPConfig) -> None:
        self._cfg = cfg
        self._conn: LDAPObject | None = None

    # ── Context manager ────────────────────────────────────────────
    def __enter__(self) -> LDAPObject:
        self._conn = self._connect()
        return self._conn

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._conn is not None:
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
