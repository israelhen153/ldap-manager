"""Directory-schema profiles.

Bundles a :class:`~ldap_manager.config.SchemaConfig` with the capability
markers a :class:`~ldap_manager.backends.generic.GenericBackend` should
publish for a given directory flavour. Picking a profile is all most
users need to do to retarget ldap-manager at Active Directory or
389ds — the profile fills in the attribute / object-class names AND
the ``supports`` frozenset that gates feature-specific call sites.

Design notes:

  * The :class:`SchemaConfig` dataclass has no ``supports`` field of
    its own. We attach it as an instance attribute here because
    capability sets belong to the *profile* (a shipping-defaults
    concept), not to user-editable config.
  * Profiles are deliberately tiny and declared at module scope so
    they're cheap to look up and easy to audit. Adding a new profile
    means: define it, add one test, ship.
  * :func:`get_schema_profile` returns ``(SchemaConfig, supports)`` so
    the factory can pass both into the backend without relying on
    attribute smuggling. The backend *also* looks at
    ``schema.supports`` defensively — belt-and-braces for callers that
    mutate the profile after construction.

Capability markers used below (and in :class:`OpenLDAPBackend`):

  * ``backup`` — local slapcat/slapadd execution. Never true for
    ldap3 — the generic backend has no way to run server binaries.
  * ``server_ops`` — local server restart/reload. Same reason.
  * ``ppolicy_overlay`` — OpenLDAP ``ppolicy`` overlay
    (``pwdChangedTime``, ``pwdAccountLockedTime``…).
  * ``cn_config_probe`` — ``cn=config`` is queryable for
    ``olcPasswordHash`` etc.
  * ``password_hash_client`` — client computes ``{SSHA}`` / ``{ARGON2}``
    so the server never sees plaintext. OpenLDAP and 389ds both
    accept pre-hashed ``userPassword``; AD rejects them.
  * ``ssh_public_key_schema`` — the ``openssh-lpk`` / ``ldapPublicKey``
    schema with ``sshPublicKey`` attribute.
  * ``posix_accounts`` — ``posixAccount`` object class / ``uidNumber`` /
    ``gidNumber`` workflows.
"""

from __future__ import annotations

from dataclasses import replace

from ..config import SchemaConfig


def _profile(schema: SchemaConfig, supports: frozenset[str]) -> SchemaConfig:
    """Clone ``schema`` and tag it with a ``supports`` frozenset.

    Using :func:`dataclasses.replace` keeps the profile immutable from
    the caller's perspective: :func:`get_schema_profile` always hands
    back a fresh instance, so mutating one profile doesn't contaminate
    another.
    """
    fresh = replace(schema)
    # Dynamic attribute — SchemaConfig's dataclass doesn't declare
    # ``supports``; see the module docstring for the rationale.
    fresh.supports = supports  # type: ignore[attr-defined]
    return fresh


# ── Profile catalogue ──────────────────────────────────────────────

_OPENLDAP_POSIX = SchemaConfig(
    user_id_attr="uid",
    user_object_class="inetOrgPerson",
    disable_mechanism="login_shell",
    group_membership_attr="memberUid",
)

_OPENLDAP_POSIX_SUPPORTS: frozenset[str] = frozenset(
    {
        "ppolicy_overlay",
        "cn_config_probe",
        "password_hash_client",
        "ssh_public_key_schema",
        "posix_accounts",
    }
)
# NOTE: this is OpenLDAPBackend.supports minus ``backup`` and
# ``server_ops``, because those rely on local binaries (slapcat,
# slapadd, systemctl) that the generic backend cannot invoke.

_ACTIVE_DIRECTORY = SchemaConfig(
    user_id_attr="sAMAccountName",
    user_object_class="user",
    disable_mechanism="uac_bit",
    group_membership_attr="member",
)

_ACTIVE_DIRECTORY_SUPPORTS: frozenset[str] = frozenset()
# AD's password rules, account control, and group model differ enough
# from POSIX that none of our capability markers translate cleanly. If
# AD-specific markers are added later (e.g. ``uac_disable``,
# ``ad_password_policy``), list them here.

_389DS = SchemaConfig(
    user_id_attr="uid",
    user_object_class="inetOrgPerson",
    disable_mechanism="login_shell",
    group_membership_attr="member",  # 389ds uses groupOfNames by default
)

_389DS_SUPPORTS: frozenset[str] = frozenset(
    {
        "cn_config_probe",
        "password_hash_client",
        "posix_accounts",
    }
)
# 389ds has cn=config and accepts pre-hashed userPassword. No ppolicy
# overlay (it has its own native password-policy plugin), no openssh-lpk
# by default.


_PROFILES: dict[str, tuple[SchemaConfig, frozenset[str]]] = {
    "openldap_posix": (_OPENLDAP_POSIX, _OPENLDAP_POSIX_SUPPORTS),
    "active_directory": (_ACTIVE_DIRECTORY, _ACTIVE_DIRECTORY_SUPPORTS),
    "389ds": (_389DS, _389DS_SUPPORTS),
}


def get_schema_profile(name: str) -> tuple[SchemaConfig, frozenset[str]]:
    """Return ``(SchemaConfig, supports)`` for the named profile.

    Each call returns a fresh :class:`SchemaConfig` instance (so callers
    can mutate it safely) with ``supports`` already attached as an
    instance attribute — :class:`GenericBackend` reads it from there.
    """
    if name not in _PROFILES:
        valid = sorted(_PROFILES)
        raise ValueError(f"Unknown schema profile: {name!r}. Valid: {valid}")
    base, supports = _PROFILES[name]
    return _profile(base, supports), supports


__all__ = ["get_schema_profile"]
