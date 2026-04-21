"""Transitional shim: ``LDAPConnection`` is now an alias for
:class:`~ldap_manager.backends.openldap.OpenLDAPBackend`.

The Backend Protocol work moved the connection + operation surface into
``ldap_manager/backends/``. CLI code and tests still import
``LDAPConnection`` from this module — that will keep working because the
alias preserves the class name. The final cleanup commit in Stage A
will rename the import site in ``cli.py`` directly; this shim stays
around until every caller has moved.

Do not add new code here. New backends live under ``backends/``.
"""

from __future__ import annotations

from .backends.openldap import OpenLDAPBackend as LDAPConnection

__all__ = ["LDAPConnection"]
