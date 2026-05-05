"""Deprecated compatibility shim: re-exports ``OpenLDAPBackend`` as ``LDAPConnection``.

Internal call sites all target ``OpenLDAPBackend`` directly now. This
module stays in place for external callers who imported
``from ldap_manager.connection import LDAPConnection``; it may be
removed in a future release. No new code should reference it.
"""

from __future__ import annotations

from .backends.openldap import OpenLDAPBackend as LDAPConnection

__all__ = ["LDAPConnection"]
