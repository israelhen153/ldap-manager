"""ldap3-backed implementation of :class:`Backend`.

Wraps a single :class:`ldap3.Connection` and speaks the Protocol's verb
names the same way :class:`~ldap_manager.backends.openldap.OpenLDAPBackend`
does, so consumers can swap backends with no code change.

Why ldap3 as an alternate backend:
  * Pure-Python — no libldap / C build, so it runs where python-ldap
    can't (Windows without Visual Studio, slim containers).
  * First-class Active Directory support (syntax for controls,
    ``userAccountControl`` friendliness).
  * 389ds and other vendors behave identically through ldap3.

Semantic translation layer (the whole reason this file is non-trivial):

  * Scopes: python-ldap's ``ldap.SCOPE_*`` ints (0, 1, 2) become
    ldap3's ``BASE`` / ``LEVEL`` / ``SUBTREE`` constants via
    :data:`_SCOPE_MAP`.
  * Modifications: Stage A's Protocol takes ``list[tuple[int, str,
    values]]`` where ``int`` is ``ldap.MOD_{ADD,REPLACE,DELETE}``. ldap3
    wants ``dict[attr, list[(MODIFY_*, values)]]``. :meth:`modify`
    groups by attribute and maps the op constants.
  * Results: :meth:`search` filters out referrals (``type !=
    'searchResEntry'``) and uses ``raw_attributes`` — the bytes dict —
    to keep the :data:`~ldap_manager.backends.base.Entry` contract.
  * Adds: our Protocol accepts both ``list[(attr, values)]`` and
    ``dict``; ldap3 only takes the dict shape. :meth:`add` normalises.

Capability set: empty by default. A :class:`~ldap_manager.config.SchemaConfig`
(via Stage B schema profiles) can seed ``supports`` through the
``schema`` kwarg. That way AD deployments publish no overlap with the
OpenLDAP-specific markers (``ppolicy_overlay``, ``password_hash_client``,
etc.) and capability-gated call sites short-circuit cleanly.

StartTLS mirrors OpenLDAPBackend's policy: only fire when the URI is
``ldap://`` and ``start_tls`` is set. ``ldaps://`` already ships TLS.
"""

from __future__ import annotations

import logging
from types import TracebackType
from typing import TYPE_CHECKING

import ldap  # for MOD_* / SCOPE_* constants — translation source of truth
import ldap3
from ldap3 import (
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
    SIMPLE,
    Connection,
    Server,
)
from ldap3.core.exceptions import LDAPException

if TYPE_CHECKING:
    from ..config import LDAPConfig, SchemaConfig
    from .base import Entry

log = logging.getLogger(__name__)


# ── Scope + op translation tables ──────────────────────────────────
#
# Keep these module-level so tests can assert on the mapping directly
# and the hot path doesn't rebuild a dict on each call.
_SCOPE_MAP: dict[int, int] = {
    ldap.SCOPE_BASE: ldap3.BASE,
    ldap.SCOPE_ONELEVEL: ldap3.LEVEL,
    ldap.SCOPE_SUBTREE: ldap3.SUBTREE,
}

_MOD_MAP: dict[int, str] = {
    ldap.MOD_ADD: MODIFY_ADD,
    ldap.MOD_REPLACE: MODIFY_REPLACE,
    ldap.MOD_DELETE: MODIFY_DELETE,
}


class GenericBackend:
    """Backend implementation targeting any RFC-4511 server via ldap3.

    Works against OpenLDAP, Active Directory, and 389ds. Capability
    markers are seeded from a :class:`SchemaConfig`'s companion profile
    (see :mod:`ldap_manager.backends.schemas`); without one the backend
    advertises nothing, and capability-gated call sites will refuse.
    """

    #: Populated in ``__init__`` from the schema profile, if any.
    supports: frozenset[str] = frozenset()

    def __init__(self, cfg: LDAPConfig, schema: SchemaConfig | None = None) -> None:
        self._cfg = cfg
        self._schema = schema
        self._conn: Connection | None = None
        # Instance-level shadow so different instances can carry
        # different capability sets (driven by their schema profile)
        # without mutating the class attribute. ``supports`` isn't a
        # SchemaConfig field — the profile loader attaches it
        # dynamically in :mod:`ldap_manager.backends.schemas`, which is
        # why we reach for it via ``getattr``.
        profile_supports = getattr(schema, "supports", None)
        if profile_supports is not None:
            self.supports = profile_supports

    # ── Context manager ────────────────────────────────────────────
    def __enter__(self) -> GenericBackend:
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
        ldap3_scope = _SCOPE_MAP[scope]
        # ldap3 uses ``ALL_ATTRIBUTES`` sentinel for "fetch everything";
        # passing ``None`` means the same thing in modern ldap3 but the
        # explicit sentinel is clearer and keeps behaviour stable across
        # minor versions.
        search_attrs = attrs if attrs is not None else ldap3.ALL_ATTRIBUTES
        self._conn.search(
            search_base=base,
            search_filter=filterstr,
            search_scope=ldap3_scope,
            attributes=search_attrs,
        )
        # ``conn.response`` contains mixed entry types — entries,
        # referrals, search-result-done markers. Only ``searchResEntry``
        # carries data we want.
        results: list[Entry] = []
        for rec in self._conn.response or []:
            if rec.get("type") != "searchResEntry":
                continue
            dn = rec.get("dn")
            # ``raw_attributes`` is ``dict[str, list[bytes]]`` — the exact
            # shape our ``Entry`` contract promises. ``attributes`` is
            # decoded and would break downstream consumers that decode
            # themselves.
            raw = rec.get("raw_attributes") or {}
            results.append((dn, raw))
        return results

    def add(
        self,
        dn: str,
        attrs: list[tuple[str, list[bytes]]] | dict[str, list[bytes]],
    ) -> None:
        assert self._conn is not None, "bind() not called"
        # Normalise to dict — ldap3 doesn't accept the modlist shape.
        if isinstance(attrs, list):
            attrs_dict: dict[str, list[bytes]] = dict(attrs)
        else:
            attrs_dict = attrs
        self._conn.add(dn, attributes=attrs_dict)

    def modify(
        self,
        dn: str,
        changes: list[tuple[int, str, list[bytes] | None]],
    ) -> None:
        assert self._conn is not None, "bind() not called"
        # Group by attribute: ldap3 expects ``{attr: [(op, values), ...]}``.
        # Multiple ops on the same attribute in the same call are legal
        # and the server applies them in order.
        grouped: dict[str, list[tuple[str, list[bytes]]]] = {}
        for op_int, attr, values in changes:
            op_str = _MOD_MAP[op_int]
            # ldap3 accepts ``[]`` for "delete entire attribute"; our
            # Protocol allows ``None`` for the same semantics.
            payload = values if values is not None else []
            grouped.setdefault(attr, []).append((op_str, payload))
        self._conn.modify(dn, grouped)

    def delete(self, dn: str) -> None:
        assert self._conn is not None, "bind() not called"
        self._conn.delete(dn)

    def compare(self, dn: str, attr: str, value: str) -> bool:
        assert self._conn is not None, "bind() not called"
        # ldap3.Connection.compare returns bool directly; no raise unless
        # the connection was built with ``raise_exceptions=True``. We
        # don't set that flag, so this is safe.
        return bool(self._conn.compare(dn, attr, value))

    def close(self) -> None:
        if self._conn is None:
            return
        try:
            self._conn.unbind()
        except LDAPException:
            # Same rationale as OpenLDAPBackend.close: disconnect
            # failures during cleanup must not mask the original error.
            pass
        self._conn = None

    # ── Internal ───────────────────────────────────────────────────
    def _connect(self) -> Connection:
        log.debug("Connecting to %s via ldap3", self._cfg.uri)
        server = Server(self._cfg.uri, connect_timeout=self._cfg.timeout)
        conn = Connection(
            server,
            user=self._cfg.bind_dn,
            password=self._cfg.bind_password,
            authentication=SIMPLE,
            auto_bind=False,
            receive_timeout=self._cfg.timeout,
        )
        conn.open()
        if self._cfg.start_tls and self._cfg.uri.startswith("ldap://"):
            log.debug("Initiating StartTLS")
            conn.start_tls()
        conn.bind()
        log.debug("Bound as %s", self._cfg.bind_dn)
        return conn
