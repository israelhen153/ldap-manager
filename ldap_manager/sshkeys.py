"""SSH public key management via LDAP.

Manages the sshPublicKey attribute from the ldapPublicKey objectClass.
Requires the openssh-lpk schema to be loaded on the server.
"""

from __future__ import annotations

import logging

import ldap

from .backends import Backend
from .config import Config

log = logging.getLogger(__name__)

SSH_ATTR = "sshPublicKey"
SSH_OBJECTCLASS = "ldapPublicKey"


class SSHKeyManager:
    """Manage SSH public keys stored in LDAP."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._lcfg = cfg.ldap

    def _get_user_dn(self, backend: Backend, uid: str) -> str:
        """Resolve uid to DN, raising if not found."""
        results = backend.search(
            self._lcfg.users_ou,
            ldap.SCOPE_SUBTREE,
            f"(&(objectClass=posixAccount)(uid={uid}))",
            ["dn", "objectClass"],
        )
        if not results or results[0][0] is None:
            raise ValueError(f"User '{uid}' not found")
        dn = results[0][0]
        assert isinstance(dn, str)
        return dn

    def _ensure_objectclass(self, backend: Backend, dn: str) -> None:
        """Add ldapPublicKey objectClass if not already present."""
        results = backend.search(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["objectClass"])
        if not results:
            return

        ocs = [v.decode("utf-8") for v in results[0][1].get("objectClass", [])]
        if SSH_OBJECTCLASS not in ocs:
            backend.modify(dn, [(ldap.MOD_ADD, "objectClass", [SSH_OBJECTCLASS.encode()])])
            log.info("Added %s objectClass to %s", SSH_OBJECTCLASS, dn)

    def list_keys(self, backend: Backend, uid: str) -> list[str]:
        """List all SSH public keys for a user.

        Returns list of public key strings.
        """
        dn = self._get_user_dn(backend, uid)

        results = backend.search(dn, ldap.SCOPE_BASE, "(objectClass=*)", [SSH_ATTR])
        if not results:
            return []

        keys = results[0][1].get(SSH_ATTR, [])
        return [k.decode("utf-8") for k in keys]

    def add_key(self, backend: Backend, uid: str, key: str) -> None:
        """Add an SSH public key to a user.

        Args:
            uid: User ID
            key: Full SSH public key string (e.g. "ssh-rsa AAAA... comment")
        """
        key = key.strip()
        if not key:
            raise ValueError("Empty key")

        # Basic validation
        parts = key.split()
        if len(parts) < 2:
            raise ValueError("Invalid SSH key format. Expected: <type> <key-data> [comment]")
        valid_types = (
            "ssh-rsa",
            "ssh-ed25519",
            "ssh-dss",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        )
        if parts[0] not in valid_types:
            raise ValueError(f"Unknown key type '{parts[0]}'. Expected one of: {', '.join(valid_types)}")

        dn = self._get_user_dn(backend, uid)

        # Check for duplicate
        existing = self.list_keys(backend, uid)
        for ek in existing:
            # Compare key data (ignore comment differences)
            if ek.split()[1] == parts[1]:
                log.warning("Key already exists for user %s (skipping)", uid)
                return

        self._ensure_objectclass(backend, dn)
        backend.modify(dn, [(ldap.MOD_ADD, SSH_ATTR, [key.encode()])])
        log.info("Added SSH key to user %s (%s...)", uid, key[:40])

    def remove_key(self, backend: Backend, uid: str, key_index: int) -> str:
        """Remove an SSH key by index (0-based).

        Returns the removed key string.
        """
        keys = self.list_keys(backend, uid)
        if not keys:
            raise ValueError(f"User '{uid}' has no SSH keys")

        if key_index < 0 or key_index >= len(keys):
            raise ValueError(f"Key index {key_index} out of range. User has {len(keys)} key(s) (0-{len(keys) - 1})")

        key_to_remove = keys[key_index]
        dn = self._get_user_dn(backend, uid)
        backend.modify(dn, [(ldap.MOD_DELETE, SSH_ATTR, [key_to_remove.encode()])])
        log.info("Removed SSH key %d from user %s", key_index, uid)
        return key_to_remove

    def remove_all_keys(self, backend: Backend, uid: str) -> int:
        """Remove all SSH keys from a user. Returns count removed."""
        keys = self.list_keys(backend, uid)
        if not keys:
            return 0

        dn = self._get_user_dn(backend, uid)
        backend.modify(dn, [(ldap.MOD_DELETE, SSH_ATTR, None)])
        log.info("Removed all %d SSH keys from user %s", len(keys), uid)
        return len(keys)
