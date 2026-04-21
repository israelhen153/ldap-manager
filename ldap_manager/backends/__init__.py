"""Pluggable LDAP backends.

Every backend implements the :class:`Backend` Protocol from
:mod:`ldap_manager.backends.base`. :class:`~ldap_manager.backends.openldap.OpenLDAPBackend`
drives python-ldap for OpenLDAP-only deployments;
:class:`~ldap_manager.backends.generic.GenericBackend` drives ldap3 and
works against any RFC-4511 directory (AD, 389ds, OpenLDAP).

:func:`build_backend` is the single dispatch point. Every call site in
the codebase goes through it so adding a new backend only requires one
clause here — no grep for ``OpenLDAPBackend(`` across the tree.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Backend, Entry
from .generic import GenericBackend
from .openldap import OpenLDAPBackend

if TYPE_CHECKING:
    from ..config import Config


def build_backend(cfg: Config) -> OpenLDAPBackend | GenericBackend:
    """Construct a :class:`Backend` for ``cfg.backend``.

    Returns the concrete class (not the :class:`Backend` Protocol) so
    ``with build_backend(cfg) as backend:`` keeps ``__enter__`` /
    ``__exit__`` visible to type checkers — the Protocol itself omits
    context-manager methods to stay minimal, and widening it would
    ripple through every Backend consumer.

    Values:
      * ``"openldap"`` — python-ldap, the historical default. Required
        for capabilities that exec local binaries (slapcat/slapadd).
      * ``"generic"`` — ldap3, fed with ``cfg.schema``. Works against
        any RFC-4511 directory.

    Any other value raises :class:`ValueError` listing the valid
    choices; this is the one place the dispatch happens, so a typo in
    config can't silently fall through to a default backend.
    """
    backend_name = cfg.backend
    if backend_name == "openldap":
        return OpenLDAPBackend(cfg.ldap)
    if backend_name == "generic":
        return GenericBackend(cfg.ldap, schema=cfg.schema)
    valid = ["openldap", "generic"]
    raise ValueError(f"Unknown backend: {backend_name!r}. Valid: {valid}")


__all__ = ["Backend", "Entry", "GenericBackend", "OpenLDAPBackend", "build_backend"]
