"""Pluggable LDAP backends.

Every backend implements the :class:`Backend` Protocol from
:mod:`ldap_manager.backends.base`. :class:`~ldap_manager.backends.openldap.OpenLDAPBackend`
is the production implementation; additional backends (e.g. ldap3) can be
added without touching consumers.
"""

from __future__ import annotations

from .base import Backend, Entry
from .openldap import OpenLDAPBackend

__all__ = ["Backend", "Entry", "OpenLDAPBackend"]
