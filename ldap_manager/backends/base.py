"""Backend Protocol — the narrow seam between ldap-manager and a concrete
LDAP client library.

Why a Protocol and not an ABC:
  * Duck typing. Mocks (MagicMock(spec=Backend)) and third-party objects
    satisfy the Protocol by shape, without inheriting a base class.
  * ``@runtime_checkable`` keeps ``isinstance(x, Backend)`` available for
    the handful of places where we need to short-circuit on capability.

The method surface is deliberately small: bind/search/add/modify/delete,
plus compare for future auth-backed workflows. Everything higher-level
(hash schemes, user-lifecycle, bulk operations) lives in consumers that
take a ``Backend`` by-value and never reach past the Protocol.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# ──────────────────────────────────────────────────────────────────────
# Entry tuple shape
#
# python-ldap returns (dn, attrs) tuples, where dn can be None for
# referrals. Existing defensive code in this codebase already handles
# the None case — keep it in the type so we don't silently lose that
# contract.
# ──────────────────────────────────────────────────────────────────────
Entry = tuple[str | None, dict[str, list[bytes]]]


@runtime_checkable
class Backend(Protocol):
    """Abstract LDAP backend.

    Implementations are context-managed: ``__enter__`` should bind and
    return ``self`` (the backend, NOT a raw connection object); consumers
    receive the Backend and call its methods directly.

    ``supports`` is a set of capability markers so call sites that need
    a feature (e.g. ``ppolicy_overlay``) can gate themselves — populated
    by each concrete backend.
    """

    #: Capability markers. Concrete backends populate this on the class.
    supports: frozenset[str]

    def bind(self) -> None:
        """Open the underlying connection and bind. Idempotent per instance."""
        ...

    def search(
        self,
        base: str,
        scope: int,
        filterstr: str,
        attrs: list[str] | None = None,
    ) -> list[Entry]:
        """Return a list of (dn, attrs) tuples.

        ``filterstr`` is named to avoid shadowing the ``filter`` builtin.
        ``attrs=None`` means "fetch everything" (ldif_ops relies on this).
        """
        ...

    def add(
        self,
        dn: str,
        attrs: list[tuple[str, list[bytes]]] | dict[str, list[bytes]],
    ) -> None:
        """Add an entry.

        Accepts both the list-of-tuples shape that ``ldap.modlist.addModlist``
        returns and the plain dict shape some callers build directly.
        """
        ...

    def modify(
        self,
        dn: str,
        changes: list[tuple[int, str, list[bytes] | None]],
    ) -> None:
        """Apply a list of (op, attr, values) tuples.

        ``op`` is one of the ``ldap.MOD_*`` integers. Values may be
        ``None`` for a full-attribute delete.
        """
        ...

    def delete(self, dn: str) -> None:
        """Delete an entry."""
        ...

    def compare(self, dn: str, attr: str, value: str) -> bool:
        """Compare ``attr`` on ``dn`` against ``value``.

        No call sites use this today; kept in the Protocol so future
        auth flows don't have to widen the interface.
        """
        ...

    def close(self) -> None:
        """Unbind and release resources. Must be safe to call twice."""
        ...
