"""CLI interface for ldap-manager.

Usage:
    ldap-manager user list
    ldap-manager user create jdoe --cn "John Doe" --sn Doe --mail john@example.com
    ldap-manager user get jdoe
    ldap-manager user update jdoe --set mail=newemail@example.com
    ldap-manager user delete jdoe
    ldap-manager user disable jdoe
    ldap-manager user enable jdoe
    ldap-manager user passwd jdoe
    ldap-manager backup dump
    ldap-manager backup restore /var/backups/ldap/ldap_backup_20240101_120000
    ldap-manager backup list
    ldap-manager passwd-all [--include-disabled] [--dry-run]
"""

from __future__ import annotations

import getpass
import logging
import os
import sys
from pathlib import Path
from typing import Any

import click

from .backup import BackupManager, DatabasePopulatedError
from .batch import load_structured_file as load_batch_file
from .batch import run_batch
from .config import load_config
from .connection import LDAPConnection
from .groups import GroupManager
from .passwords import bulk_password_reset
from .users import UserManager


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        filename="/var/log/ldap.log",
        level=level,
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _json_out(data: Any) -> None:
    """Print data as formatted JSON."""
    import json
    from dataclasses import asdict, is_dataclass

    if is_dataclass(data) and not isinstance(data, type):
        data = asdict(data)
    elif isinstance(data, list) and data and is_dataclass(data[0]):
        data = [asdict(item) for item in data]

    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


# ── Root group ─────────────────────────────────────────────────────


@click.group()
@click.option("-c", "--config", "config_path", default=None, help="Path to config YAML file")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option("--debug", is_flag=True, hidden=True, help="Show full tracebacks on errors")
@click.pass_context
def main(ctx: click.Context, config_path: str | None, verbose: bool, debug: bool) -> None:
    """LDAP server management CLI.

    \b
    QUICK START
        1. Copy config.example.yaml to ~/.ldap-manager.yaml
        2. Edit with your LDAP server details
        3. Run: ldap-manager user list

    \b
    EXAMPLES
        ldap-manager user list
        ldap-manager user create jdoe
        ldap-manager -c /etc/ldap-manager/config.yaml user list
        ldap-manager -v backup dump --tag pre-migration
        ldap-manager passwd-all --dry-run

    \b
    ENVIRONMENT VARIABLES
        LDAP_URI              Server URI (overrides config)
        LDAP_BIND_DN          Bind DN (overrides config)
        LDAP_BIND_PASSWORD    Bind password (overrides config)
        LDAP_BASE_DN          Base DN (overrides config)
    """
    _setup_logging(verbose or debug)
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config_path)

    if debug or os.environ.get("LDAP_MANAGER_DEBUG"):
        ctx.obj["debug"] = True


# ── User commands ──────────────────────────────────────────────────


@main.group()
@click.pass_context
def user(ctx: click.Context) -> None:
    """User CRUD operations.

    \b
    SUBCOMMANDS
        list      List users (table or JSON output)
        get       Show full details for one user
        dump      Export all users as JSON (all LDAP attributes)
        create    Create a new user (only uid required with config defaults)
        update    Modify user attributes
        delete    Remove a user entry
        enable    Restore default login shell
        disable   Set shell to /sbin/nologin
        passwd    Change a single user's password

    \b
    EXAMPLES
        ldap-manager user list --enabled
        ldap-manager user create jdoe
        ldap-manager user disable jdoe
        ldap-manager user dump -o users.json
    """


@user.command("list")
@click.option("--enabled", is_flag=True, help="Show only enabled users")
@click.option("--disabled", is_flag=True, help="Show only disabled users")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def user_list(ctx: click.Context, enabled: bool, disabled: bool, as_json: bool) -> None:
    """List all users in the directory.

    \b
    EXAMPLES
        # Table output of all users
        ldap-manager user list

        # Only enabled users
        ldap-manager user list --enabled

        # JSON output, pipe to jq
        ldap-manager user list --json | jq '.[].uid'

        # Count disabled users
        ldap-manager user list --disabled --json | jq length

    \b
    EXIT CODES
        0    Success (even if no users found)
    """
    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        users = mgr.list_users(conn, enabled_only=enabled, disabled_only=disabled)

    if as_json:
        import json
        from dataclasses import asdict

        click.echo(json.dumps([asdict(u) for u in users], indent=2))
        return

    if not users:
        click.echo("No users found.")
        return

    # Table output
    header = f"{'UID':<20} {'CN':<30} {'UID#':<8} {'SHELL':<20} {'STATUS':<10}"
    click.echo(header)
    click.echo("─" * len(header))
    for u in users:
        status = click.style("enabled", fg="green") if u.enabled else click.style("disabled", fg="red")
        click.echo(f"{u.uid:<20} {u.cn:<30} {u.uid_number:<8} {u.login_shell:<20} {status}")

    click.echo(f"\nTotal: {len(users)} users")


@user.command("search")
@click.option("--filter", "-f", "ldap_filter", default=None, help="Raw LDAP filter, e.g. '(description=contractor*)'.")
@click.option("--uid", default=None, help="Wildcard match on uid, e.g. 'j*'.")
@click.option("--cn", default=None, help="Wildcard match on cn, e.g. '*Smith*'.")
@click.option("--mail", default=None, help="Wildcard match on mail, e.g. '*@contractors.com'.")
@click.option("--gid", type=int, default=None, help="Exact match on gidNumber.")
@click.option("--shell", default=None, help="Exact match on loginShell.")
@click.option("--enabled", is_flag=True, help="Only enabled users.")
@click.option("--disabled", is_flag=True, help="Only disabled users.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def user_search(
    ctx: click.Context,
    ldap_filter: str | None,
    uid: str | None,
    cn: str | None,
    mail: str | None,
    gid: int | None,
    shell: str | None,
    enabled: bool,
    disabled: bool,
    as_json: bool,
) -> None:
    """Search users with LDAP filters and/or shorthand fields.

    All conditions are ANDed together. Shorthand fields support LDAP
    wildcards (*). Use --filter for arbitrary LDAP filter expressions.

    \b
    EXAMPLES
        # Find all users in GID 20000
        ldap-manager user search --gid 20000

        # Wildcard on mail domain
        ldap-manager user search --mail '*@contractors.com'

        # Wildcard on uid
        ldap-manager user search --uid 'j*'

        # Raw LDAP filter
        ldap-manager user search --filter '(description=*temporary*)'

        # Combine: enabled users in GID 10000 with mail matching a domain
        ldap-manager user search --gid 10000 --mail '*@corp.com' --enabled

        # Complex raw filter (OR logic)
        ldap-manager user search --filter '(|(gidNumber=10000)(gidNumber=20000))'

        # JSON output for scripting
        ldap-manager user search --gid 10000 --json | jq '.[].uid'

    \b
    NOTES
        All shorthand fields (--uid, --cn, --mail, --gid, --shell) and --filter
        are ANDed together. For OR logic, use --filter with LDAP OR syntax.
        Wildcards: * matches any string, e.g. 'j*' matches jdoe, jane, etc.
    """
    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    try:
        with LDAPConnection(cfg.ldap) as conn:
            users = mgr.search_users(
                conn,
                ldap_filter=ldap_filter,
                uid=uid,
                cn=cn,
                mail=mail,
                gid=gid,
                shell=shell,
                enabled_only=enabled,
                disabled_only=disabled,
            )
    except ValueError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    if as_json:
        _json_out(users)
        return

    if not users:
        click.echo("No users found matching criteria.")
        return

    header = f"{'UID':<20} {'CN':<30} {'MAIL':<35} {'GID':<8} {'STATUS':<10}"
    click.echo(header)
    click.echo("─" * len(header))
    for u in users:
        status = click.style("enabled", fg="green") if u.enabled else click.style("disabled", fg="red")
        click.echo(f"{u.uid:<20} {u.cn:<30} {u.mail:<35} {u.gid_number:<8} {status}")

    click.echo(f"\nFound: {len(users)} users")


@user.command("dump")
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
@click.option("--enabled", is_flag=True, help="Only enabled users")
@click.option("--disabled", is_flag=True, help="Only disabled users")
@click.option("--attrs", default=None, help="Comma-separated list of attributes to include (default: all)")
@click.option("--compact", is_flag=True, help="Compact JSON (no indentation)")
@click.option("--with-metadata", is_flag=True, help="Wrap output with timestamp, count, config metadata")
@click.pass_context
def user_dump(
    ctx: click.Context,
    output: str | None,
    enabled: bool,
    disabled: bool,
    attrs: str | None,
    compact: bool,
    with_metadata: bool,
) -> None:
    """Dump all users as JSON for post-processing.

    Exports ALL LDAP attributes per user (not just the curated subset).
    Binary attributes (passwords, photos) are base64-encoded.

    Examples:

        ldap-manager user dump -o users.json

        ldap-manager user dump --enabled --attrs uid,mail,cn

        ldap-manager user dump --with-metadata | jq '.users[] | .uid'

    \b
    OUTPUT FORMAT
        Default: JSON array of user objects.
        With --with-metadata: wrapped in {"metadata": {...}, "users": [...]}.
        With --compact: no indentation.

    """
    import json
    from datetime import datetime, timezone

    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)
    payload: Any = None


    extra_attrs = None
    if attrs:
        extra_attrs = [a.strip() for a in attrs.split(",") if a.strip()]

    with LDAPConnection(cfg.ldap) as conn:
        users = mgr.dump_users(
            conn,
            enabled_only=enabled,
            disabled_only=disabled,
            extra_attrs=extra_attrs,
        )

    if with_metadata:
        payload = {
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": cfg.ldap.uri,
                "base_dn": cfg.ldap.users_ou,
                "total_users": len(users),
                "filter": "enabled" if enabled else "disabled" if disabled else "all",
            },
            "users": users,
        }
    else:
        payload = users

    indent = None if compact else 2
    json_str = json.dumps(payload, indent=indent, ensure_ascii=False, sort_keys=False)

    if output:
        from pathlib import Path

        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_str + "\n", encoding="utf-8")
        click.echo(f"Dumped {len(users)} users to {out_path}", err=True)
    else:
        click.echo(json_str)


@user.command("get")
@click.argument("uid")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def user_get(ctx: click.Context, uid: str, as_json: bool) -> None:
    """Show full details for a single user.

    \b
    EXAMPLES
        ldap-manager user get jdoe
        ldap-manager user get jdoe --json
        ldap-manager user get admin --json | jq '.mail'

    \b
    EXIT CODES
        0    User found and displayed
        1    User not found
    """
    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        u = mgr.get_user(conn, uid)

    if u is None:
        click.echo(f"User '{uid}' not found.", err=True)
        sys.exit(1)

    if as_json:
        _json_out(u)
        return

    click.echo(f"DN:             {u.dn}")
    click.echo(f"UID:            {u.uid}")
    click.echo(f"CN:             {u.cn}")
    click.echo(f"SN:             {u.sn}")
    click.echo(f"Given Name:     {u.given_name}")
    click.echo(f"Mail:           {u.mail}")
    click.echo(f"UID Number:     {u.uid_number}")
    click.echo(f"GID Number:     {u.gid_number}")
    click.echo(f"Home Directory: {u.home_directory}")
    click.echo(f"Login Shell:    {u.login_shell}")
    status = click.style("enabled", fg="green") if u.enabled else click.style("disabled", fg="red")
    click.echo(f"Status:         {status}")


@user.command("create")
@click.argument("uid")
@click.option("--cn", default=None, help="Full name (defaults to uid)")
@click.option("--sn", default=None, help="Surname (defaults to uid)")
@click.option("--given-name", default="", help="Given name")
@click.option("--mail", default="", help="Email (defaults to uid@mail_domain from config)")
@click.option("--uid-number", type=int, default=None, help="UID number (auto-assigned if omitted)")
@click.option("--gid-number", type=int, default=None, help="GID number (uses default from config)")
@click.option("--home", default=None, help="Home directory path")
@click.option("--shell", default=None, help="Login shell")
@click.option("--password", is_flag=True, help="Prompt for password (overrides config auto-generation)")
@click.pass_context
def user_create(
    ctx: click.Context,
    uid: str,
    cn: str | None,
    sn: str | None,
    given_name: str,
    mail: str,
    uid_number: int | None,
    gid_number: int | None,
    home: str | None,
    shell: str | None,
    password: bool,
) -> None:
    """Create a new user.

    Only uid is required — everything else comes from config.

    \b
    With a config that has mail_domain and generate_password_on_create:
        ldap-manager user create jdoe
        # → creates jdoe with mail=jdoe@example.com, prints generated password

    \b
    Override anything on the CLI:
        ldap-manager user create jdoe --cn "John Doe" --sn Doe --mail custom@mail.com

    \b
    EXAMPLES
        ldap-manager user create jdoe

        ldap-manager user create jdoe --cn "John Doe" --mail john@example.com

        ldap-manager user create jdoe --gid 5000 --shell /bin/zsh

        ldap-manager user create jdoe --password "S3cret!" --no-generate

    \b
    NOTES
        UID number is auto-assigned from the range in config.
        Mail is auto-derived from uid@mail_domain if mail_domain is set.
        Home directory defaults to home_prefix/uid.
    """
    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    pw = None
    if password:
        pw = getpass.getpass("Enter password: ")
        pw_confirm = getpass.getpass("Confirm password: ")
        if pw != pw_confirm:
            click.echo("Passwords do not match.", err=True)
            sys.exit(1)

    with LDAPConnection(cfg.ldap) as conn:
        dn, generated_pw = mgr.create_user(
            conn,
            uid,
            cn,
            sn,
            given_name=given_name,
            mail=mail,
            uid_number=uid_number,
            gid_number=gid_number,
            home_directory=home,
            login_shell=shell,
        )

    click.echo(f"Created user: {dn}")
    if generated_pw:
        click.echo(f"Password: {generated_pw}")


@user.command("update")
@click.argument("uid")
@click.option("--set", "attrs", multiple=True, help="attr=value pairs (repeatable)")
@click.pass_context
def user_update(ctx: click.Context, uid: str, attrs: tuple[str, ...]) -> None:
    """Modify attributes on an existing user.

    Use --set key=value (repeatable) to change any LDAP attribute.

    \b
    EXAMPLES
        # Change email
        ldap-manager user update jdoe --set mail=newemail@example.com

        # Change multiple attributes at once
        ldap-manager user update jdoe --set mail=new@ex.com --set loginShell=/bin/zsh

        # Change GID
        ldap-manager user update jdoe --set gidNumber=20000

    \b
    NOTES
        Attribute names are LDAP attribute names (case-sensitive).
        Common attributes: mail, cn, sn, givenName, loginShell, gidNumber.
    """
    if not attrs:
        click.echo("Nothing to update. Use --set attr=value.", err=True)
        sys.exit(1)

    parsed = {}
    for a in attrs:
        if "=" not in a:
            click.echo(f"Invalid format: '{a}'. Expected attr=value.", err=True)
            sys.exit(1)
        key, val = a.split("=", 1)
        parsed[key] = val

    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        mgr.update_user(conn, uid, **parsed)

    click.echo(f"Updated user '{uid}': {list(parsed.keys())}")


@user.command("delete")
@click.argument("uid")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
@click.option("--json", "as_json", is_flag=True, help="Output deleted user info as JSON.")
@click.pass_context
def user_delete(ctx: click.Context, uid: str, yes: bool, as_json: bool) -> None:
    """Delete a user entry from the directory.

    \b
    EXAMPLES
        ldap-manager user delete jdoe
        ldap-manager user delete jdoe --yes
        ldap-manager user delete jdoe --yes --json

    \b
    NOTES
        This is permanent. Consider 'user disable' instead for soft removal.
        The entry is deleted immediately — there is no undo.
    """
    if not yes:
        if not click.confirm(f"Delete user '{uid}'? This cannot be undone"):
            click.echo("Aborted.")
            return

    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        user = mgr.get_user(conn, uid)
        mgr.delete_user(conn, uid)

    if as_json and user:
        _json_out({"action": "deleted", "user": user})
    else:
        click.echo(f"Deleted user '{uid}'.")


@user.command("disable")
@click.argument("uid")
@click.option("--json", "as_json", is_flag=True, help="Output result as JSON.")
@click.pass_context
def user_disable(ctx: click.Context, uid: str, as_json: bool) -> None:
    """Disable a user by setting their login shell to /sbin/nologin.

    \b
    EXAMPLES
        ldap-manager user disable jdoe
        ldap-manager user disable jdoe --json

    \b
    NOTES
        The disabled shell is configurable via users.disabled_shell in config.
        Use 'user enable' to reverse this operation.
        Already-disabled users produce a warning but no error.
    """
    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        mgr.disable_user(conn, uid)
        user = mgr.get_user(conn, uid)

    if as_json and user:
        _json_out({"action": "disabled", "user": user})
    else:
        click.echo(f"User '{uid}' disabled.")


@user.command("enable")
@click.argument("uid")
@click.option("--json", "as_json", is_flag=True, help="Output result as JSON.")
@click.pass_context
def user_enable(ctx: click.Context, uid: str, as_json: bool) -> None:
    """Re-enable a user by restoring their default login shell.

    \b
    EXAMPLES
        ldap-manager user enable jdoe
        ldap-manager user enable jdoe --json

    \b
    NOTES
        Restores shell to users.default_shell from config (default: /bin/bash).
        Already-enabled users produce a warning but no error.
    """
    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        mgr.enable_user(conn, uid)
        user = mgr.get_user(conn, uid)

    if as_json and user:
        _json_out({"action": "enabled", "user": user})
    else:
        click.echo(f"User '{uid}' enabled.")


@user.command("passwd")
@click.argument("uid")
@click.pass_context
def user_passwd(ctx: click.Context, uid: str) -> None:
    """Change a single user's password (interactive prompt).

    \b
    EXAMPLES
        ldap-manager user passwd jdoe
        ldap-manager user passwd admin

    \b
    NOTES
        Password is prompted interactively (not echoed).
        For bulk password changes, use 'passwd-all' instead.
        Password is hashed with SSHA before storing.
    """
    pw = getpass.getpass("New password: ")
    pw_confirm = getpass.getpass("Confirm password: ")
    if pw != pw_confirm:
        click.echo("Passwords do not match.", err=True)
        sys.exit(1)

    cfg = ctx.obj["config"]
    mgr = UserManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        mgr.set_password(conn, uid, pw)

    click.echo(f"Password changed for '{uid}'.")


# ── Batch commands ─────────────────────────────────────────────────


@main.command("batch")
@click.argument("action", type=click.Choice(["create", "update", "delete", "enable", "disable"]))
@click.argument("file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Validate and log but don't modify LDAP")
@click.option("--stop-on-error", is_flag=True, help="Abort on first failure")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@click.option("--report", default=None, help="Write JSON result report to this file")
@click.pass_context
def batch_cmd(
    ctx: click.Context,
    action: str,
    file: str,
    dry_run: bool,
    stop_on_error: bool,
    yes: bool,
    report: str | None,
) -> None:
    """Run a batch action against a file of users.

    \b
    For enable/disable/delete — file is a plain text uid list:
        jdoe
        asmith
        # this is a comment, ignored
        bwilson

    \b
    For create/update — file must be .json or .csv with user data:
        [{"uid": "jdoe", "cn": "John Doe", "sn": "Doe", "mail": "j@ex.com"}, ...]

    \b
    Examples:
        ldap-manager batch disable users_to_disable.txt
        ldap-manager batch enable reactivate.txt
        ldap-manager batch delete terminated.txt --yes
        ldap-manager batch create new_hires.json --dry-run
        ldap-manager batch update changes.csv --report result.json
    """
    import json
    from pathlib import Path

    # Peek at file to show count
    file_path = Path(file)
    if action in ("create", "update"):
        entries = load_batch_file(file_path)
        count = len(entries)
    else:
        with open(file_path, encoding="utf-8") as f:
            count = sum(1 for ln in f if ln.strip() and not ln.strip().startswith("#"))

    click.echo(f"Action: {action.upper()}  Users: {count}  File: {file}")
    if dry_run:
        click.echo("(dry run — no changes will be made)")

    if not yes and not dry_run:
        if not click.confirm("Proceed?"):
            click.echo("Aborted.")
            return

    cfg = ctx.obj["config"]

    with LDAPConnection(cfg.ldap) as conn:
        result = run_batch(
            conn,
            cfg,
            action,
            file_path,
            dry_run=dry_run,
            stop_on_error=stop_on_error,
        )

    click.echo(result.summary())

    if report:
        report_path = Path(report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
        click.echo(f"Report written to: {report_path}")

    if result.failed > 0:
        sys.exit(1)


# ── Backup commands ────────────────────────────────────────────────


@main.group()
@click.pass_context
def backup(ctx: click.Context) -> None:
    """Backup and restore the LDAP database.

    Uses slapcat/slapadd for full-fidelity backup including cn=config,
    ACLs, overlays, schemas, and operational attributes.

    \b
    SUBCOMMANDS
        dump      Full dump of data + config databases
        restore   Restore from a backup directory (stops slapd automatically)
        list      Show available backups with metadata

    \b
    EXAMPLES
        ldap-manager backup dump
        ldap-manager backup dump --tag pre-migration
        ldap-manager backup list
        ldap-manager backup restore /var/backups/ldap/ldap_backup_20240101_120000
    """


@backup.command("dump")
@click.option("--no-compress", is_flag=True, help="Don't gzip the LDIF files")
@click.option("--tag", default="", help="Optional tag for the backup directory name")
@click.pass_context
def backup_dump(ctx: click.Context, no_compress: bool, tag: str) -> None:
    """Dump full LDAP database (data + cn=config).

    Creates a backup directory under backup.backup_dir containing:
      - data.ldif.gz    Main database entries
      - config.ldif.gz  cn=config (server configuration, ACLs, overlays)
      - metadata.txt    Timestamp, hostname, tag

    \b
    EXAMPLES
        # Standard backup
        ldap-manager backup dump

        # Tag for identification
        ldap-manager backup dump --tag pre-migration
        ldap-manager backup dump --tag weekly-sunday

        # Uncompressed (for debugging or diffing)
        ldap-manager backup dump --no-compress

    \b
    NOTES
        Old backups are pruned based on backup.retention_count in config.
        slapd does NOT need to be stopped for dump (slapcat reads safely).
    """
    cfg = ctx.obj["config"]
    mgr = BackupManager(cfg.backup, cfg.ldap.base_dn)

    path = mgr.dump(compress=not no_compress, tag=tag)
    click.echo(f"Backup saved to: {path}")


@backup.command("restore")
@click.argument("backup_path")
@click.option("--with-config", is_flag=True, help="Also restore cn=config (dangerous)")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@click.pass_context
def backup_restore(ctx: click.Context, backup_path: str, with_config: bool, yes: bool) -> None:
    """Restore LDAP database from a backup directory.

    slapd is stopped automatically before restore and restarted after,
    regardless of success or failure.

    \b
    EXAMPLES
        # Restore data only (most common)
        ldap-manager backup restore /var/backups/ldap/ldap_backup_20240101_120000

        # Skip confirmation
        ldap-manager backup restore /var/backups/ldap/ldap_backup_20240101_120000 --yes

        # Restore data AND cn=config (dangerous — can break server)
        ldap-manager backup restore /path/to/backup --with-config --yes

    \b
    NOTES
        If the database already has data, you will see a "server looks fully
        populated" error. You must wipe the MDB files manually before retrying.
        slapd is always restarted even on failure.

    \b
    EXIT CODES
        0    Restore succeeded, slapd restarted
        1    Restore failed (slapd still restarted)
    """
    if not yes:
        msg = "This will REPLACE the current LDAP database. "
        if with_config:
            msg += "INCLUDING cn=config (server configuration). "
        msg += "slapd will be stopped if running. Continue?"
        if not click.confirm(msg):
            click.echo("Aborted.")
            return

    cfg = ctx.obj["config"]
    mgr = BackupManager(cfg.backup, cfg.ldap.base_dn)

    try:
        mgr.restore(backup_path, restore_config=with_config)
    except DatabasePopulatedError:
        click.echo(
            "\n"
            "Hey, this server looks fully populated — the database already has data in it.\n"
            "slapadd can't import into a non-empty database.\n"
            "\n"
            "To do a full restore you need to wipe the existing DB files first:\n"
            "\n"
            "  1. Make sure slapd is stopped\n"
            "  2. Find your DB path:  slapcat -b cn=config | grep olcDbDirectory\n"
            "  3. Remove the MDB files:  rm <path>/data.mdb <path>/lock.mdb\n"
            "  4. Re-run this restore command\n",
            err=True,
        )
        _restart_slapd("Restarting slapd since restore was aborted...")
        sys.exit(1)
    except Exception as exc:
        click.echo(f"\nRestore failed: {exc}", err=True)
        _restart_slapd("Restarting slapd since restore failed...")
        sys.exit(1)

    click.echo("Restore completed.")
    _restart_slapd("Starting slapd...")


def _restart_slapd(msg: str) -> None:
    """Attempt to start slapd, warn if it fails."""
    import subprocess

    click.echo(msg)
    result = subprocess.run(["systemctl", "start", "slapd"], capture_output=True)
    if result.returncode == 0:
        click.echo("slapd started.")
    else:
        stderr = result.stderr.decode("utf-8", errors="replace")
        click.echo(f"WARNING: Failed to start slapd: {stderr.strip()}", err=True)
        click.echo("Start it manually: systemctl start slapd", err=True)


@backup.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def backup_list(ctx: click.Context, as_json: bool) -> None:
    """List available backups with metadata.

    \b
    EXAMPLES
        ldap-manager backup list
        ldap-manager backup list --json
        ldap-manager backup list --json | jq '.[0].path'

    \b
    OUTPUT
        Shows path, timestamp, size, and tag for each backup directory
        found under backup.backup_dir (sorted newest first).
    """
    cfg = ctx.obj["config"]
    mgr = BackupManager(cfg.backup, cfg.ldap.base_dn)

    backups = mgr.list_backups()
    if not backups:
        if as_json:
            _json_out([])
        else:
            click.echo("No backups found.")
        return

    if as_json:
        _json_out(backups)
        return

    for b in backups:
        click.echo(f"  {b.get('path', 'unknown')}")
        click.echo(f"    Time: {b.get('timestamp', '?')}  Size: {b.get('size_mb', '?')} MB")
        if b.get("tag"):
            click.echo(f"    Tag: {b['tag']}")


# ── Global password reset ──────────────────────────────────────────


@main.command("passwd-all")
@click.option("--include-disabled", is_flag=True, help="Also reset disabled users")
@click.option("--output", default=None, help="Output CSV path (default from config)")
@click.option("--length", type=int, default=None, help="Generated password length")
@click.option("--dry-run", is_flag=True, help="Generate CSV but don't modify LDAP")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@click.pass_context
def passwd_all(
    ctx: click.Context,
    include_disabled: bool,
    output: str | None,
    length: int | None,
    dry_run: bool,
    yes: bool,
) -> None:
    """Reset ALL user passwords and output a CSV manifest.

    Generates a unique random password per user, applies it to LDAP,
    and writes uid,cn,new_password to a CSV file (chmod 600).

    \b
    EXAMPLES
        # Reset all enabled users, write CSV
        ldap-manager passwd-all

        # Dry run — generate CSV without touching LDAP
        ldap-manager passwd-all --dry-run

        # Include disabled users
        ldap-manager passwd-all --include-disabled

        # Custom output path and password length
        ldap-manager passwd-all --output /secure/passwords.csv --length 24

        # Non-interactive (skip confirmation)
        ldap-manager passwd-all --yes

    \b
    OUTPUT FILE
        Default: password.bulk_output_file from config (/tmp/ldap_passwords.csv)
        Format:  uid,cn,new_password
        Perms:   0600 (owner read/write only)

    \b
    NOTES
        Distribute passwords securely and delete the CSV immediately after.
        Use --dry-run first to verify the user list.
    """
    if not yes and not dry_run:
        if not click.confirm("This will reset passwords for ALL users. New passwords will be written to a CSV file. Continue?"):
            click.echo("Aborted.")
            return

    cfg = ctx.obj["config"]

    with LDAPConnection(cfg.ldap) as conn:
        csv_path = bulk_password_reset(
            conn,
            cfg,
            enabled_only=not include_disabled,
            output_file=output,
            dry_run=dry_run,
        )

    prefix = "[DRY RUN] " if dry_run else ""
    click.echo(f"{prefix}Password manifest written to: {csv_path}")
    if not dry_run:
        click.echo("IMPORTANT: Distribute passwords securely and delete the CSV.")


# ── Group commands ─────────────────────────────────────────────────


@main.group()
@click.pass_context
def group(ctx: click.Context) -> None:
    """Group management — create, delete, list, and manage membership.

    \b
    SUBCOMMANDS
        list      List all groups
        get       Show group details and members
        create    Create a new group
        delete    Remove a group
        add       Add a user to a group
        remove    Remove a user from a group
        members   List members of a group
        user-groups   Show which groups a user belongs to

    \b
    EXAMPLES
        ldap-manager group list
        ldap-manager group add developers jdoe
        ldap-manager group members developers
        ldap-manager group user-groups jdoe
    """


@group.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def group_list(ctx: click.Context, as_json: bool) -> None:
    """List all groups in the directory.

    \b
    EXAMPLES
        ldap-manager group list
        ldap-manager group list --json
        ldap-manager group list --json | jq '.[].cn'
    """
    cfg = ctx.obj["config"]
    mgr = GroupManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        groups = mgr.list_groups(conn)

    if as_json:
        _json_out([g.to_dict() for g in groups])
        return

    if not groups:
        click.echo("No groups found.")
        return

    header = f"{'CN':<25} {'GID':<8} {'TYPE':<15} {'MEMBERS':<8}"
    click.echo(header)
    click.echo("─" * len(header))
    for g in groups:
        gtype = "posixGroup" if g.is_posix else "groupOfNames"
        click.echo(f"{g.cn:<25} {g.gid_number:<8} {gtype:<15} {len(g.members):<8}")

    click.echo(f"\nTotal: {len(groups)} groups")


@group.command("get")
@click.argument("cn")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def group_get(ctx: click.Context, cn: str, as_json: bool) -> None:
    """Show details for a single group including its members.

    \b
    EXAMPLES
        ldap-manager group get developers
        ldap-manager group get developers --json
    """
    cfg = ctx.obj["config"]
    mgr = GroupManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        g = mgr.get_group(conn, cn)

    if g is None:
        click.echo(f"Group '{cn}' not found.", err=True)
        sys.exit(1)

    if as_json:
        _json_out(g.to_dict())
        return

    click.echo(f"DN:          {g.dn}")
    click.echo(f"CN:          {g.cn}")
    click.echo(f"GID Number:  {g.gid_number}")
    click.echo(f"Description: {g.description}")
    click.echo(f"Type:        {'posixGroup' if g.is_posix else 'groupOfNames'}")
    click.echo(f"Members ({len(g.members)}):")
    for m in sorted(g.members):
        click.echo(f"  {m}")


@group.command("create")
@click.argument("cn")
@click.argument("gid_number", type=int)
@click.option("--description", "-d", default="", help="Group description.")
@click.option("--group-of-names", is_flag=True, help="Create as groupOfNames instead of posixGroup.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def group_create(ctx: click.Context, cn: str, gid_number: int, description: str, group_of_names: bool, as_json: bool) -> None:
    """Create a new group.

    \b
    EXAMPLES
        # posixGroup (default)
        ldap-manager group create developers 20000

        # With description
        ldap-manager group create contractors 20001 -d "External contractors"

        # groupOfNames style
        ldap-manager group create admins 20002 --group-of-names
    """
    cfg = ctx.obj["config"]
    mgr = GroupManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        dn = mgr.create_group(conn, cn, gid_number, description=description, posix=not group_of_names)

    if as_json:
        _json_out({"action": "created", "dn": dn, "cn": cn, "gid_number": gid_number})
    else:
        click.echo(f"Created group: {dn}")


@group.command("delete")
@click.argument("cn")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
@click.pass_context
def group_delete(ctx: click.Context, cn: str, yes: bool) -> None:
    """Delete a group.

    \b
    EXAMPLES
        ldap-manager group delete old_team
        ldap-manager group delete old_team --yes
    """
    if not yes:
        if not click.confirm(f"Delete group '{cn}'? This cannot be undone"):
            click.echo("Aborted.")
            return

    cfg = ctx.obj["config"]
    mgr = GroupManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        mgr.delete_group(conn, cn)

    click.echo(f"Deleted group '{cn}'.")


@group.command("add")
@click.argument("group_cn")
@click.argument("uid")
@click.pass_context
def group_add_member(ctx: click.Context, group_cn: str, uid: str) -> None:
    """Add a user to a group.

    \b
    EXAMPLES
        ldap-manager group add developers jdoe
        ldap-manager group add admins root

    \b
    NOTES
        Auto-detects group type (posixGroup vs groupOfNames) and uses
        the correct member attribute (memberUid vs member DN).
        Adding an existing member produces a warning but no error.
    """
    cfg = ctx.obj["config"]
    mgr = GroupManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        mgr.add_member(conn, group_cn, uid)

    click.echo(f"Added '{uid}' to group '{group_cn}'.")


@group.command("remove")
@click.argument("group_cn")
@click.argument("uid")
@click.pass_context
def group_remove_member(ctx: click.Context, group_cn: str, uid: str) -> None:
    """Remove a user from a group.

    \b
    EXAMPLES
        ldap-manager group remove developers jdoe

    \b
    NOTES
        Raises an error if the user is not a member.
    """
    cfg = ctx.obj["config"]
    mgr = GroupManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        mgr.remove_member(conn, group_cn, uid)

    click.echo(f"Removed '{uid}' from group '{group_cn}'.")


@group.command("members")
@click.argument("cn")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def group_members(ctx: click.Context, cn: str, as_json: bool) -> None:
    """List members of a group.

    \b
    EXAMPLES
        ldap-manager group members developers
        ldap-manager group members developers --json
    """
    cfg = ctx.obj["config"]
    mgr = GroupManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        g = mgr.get_group(conn, cn)

    if g is None:
        click.echo(f"Group '{cn}' not found.", err=True)
        sys.exit(1)

    if as_json:
        _json_out({"group": cn, "type": "posixGroup" if g.is_posix else "groupOfNames", "members": sorted(g.members)})
        return

    if not g.members:
        click.echo(f"Group '{cn}' has no members.")
        return

    for m in sorted(g.members):
        click.echo(m)


@group.command("user-groups")
@click.argument("uid")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def group_user_groups(ctx: click.Context, uid: str, as_json: bool) -> None:
    """Show all groups a user belongs to.

    \b
    EXAMPLES
        ldap-manager group user-groups jdoe
        ldap-manager group user-groups jdoe --json
    """
    cfg = ctx.obj["config"]
    mgr = GroupManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        groups = mgr.get_user_groups(conn, uid)

    if as_json:
        _json_out({"uid": uid, "groups": [g.to_dict() for g in groups]})
        return

    if not groups:
        click.echo(f"User '{uid}' is not a member of any groups.")
        return

    for g in groups:
        click.echo(f"  {g.cn} (gid={g.gid_number})")


# ── Server commands ────────────────────────────────────────────────


@main.group()
@click.pass_context
def server(ctx: click.Context) -> None:
    """Server management — status, reindex, start/stop.

    \b
    SUBCOMMANDS
        status    Show slapd status (PID, uptime, databases)
        reindex   Rebuild indexes (requires slapd stopped)
        start     Start slapd
        stop      Stop slapd
        restart   Restart slapd

    \b
    EXAMPLES
        ldap-manager server status
        ldap-manager server reindex
    """


@server.command("status")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def server_status(ctx: click.Context, as_json: bool) -> None:
    """Show slapd server status.

    \b
    EXAMPLES
        ldap-manager server status
        ldap-manager server status --json
    """
    from .server import ServerManager

    cfg = ctx.obj["config"]
    mgr = ServerManager(cfg)
    st = mgr.status()

    if as_json:
        _json_out(st.to_dict())
        return

    status_str = click.style("RUNNING", fg="green") if st.running else click.style("STOPPED", fg="red")
    click.echo(f"Status:    {status_str}")
    if st.pid:
        click.echo(f"PID:       {st.pid}")
    if st.uptime_seconds is not None:
        hours, rem = divmod(st.uptime_seconds, 3600)
        mins, secs = divmod(rem, 60)
        click.echo(f"Uptime:    {hours}h {mins}m {secs}s")
    click.echo(f"Version:   {st.version}")
    if st.listeners:
        click.echo(f"Listeners: {', '.join(st.listeners)}")
    if st.databases:
        click.echo("Databases:")
        for db in st.databases:
            click.echo(f"  {db.get('suffix', '?')} ({db.get('type', '?')}) -> {db.get('directory', '?')}")


@server.command("reindex")
@click.option("--suffix", default=None, help="Database suffix to reindex (default: base_dn)")
@click.option("--auto", "auto_restart", is_flag=True, help="Automatically stop/start slapd.")
@click.pass_context
def server_reindex(ctx: click.Context, suffix: str | None, auto_restart: bool) -> None:
    """Rebuild database indexes. Requires slapd to be stopped.

    \b
    EXAMPLES
        # Automatic — stops slapd, reindexes, starts slapd
        ldap-manager server reindex --auto

        # Manual control
        ldap-manager server stop
        ldap-manager server reindex
        ldap-manager server start

    \b
    NOTES
        Run after adding new olcDbIndex entries in cn=config.
        Without --auto, slapd must already be stopped.
    """
    from .server import ServerManager

    cfg = ctx.obj["config"]
    mgr = ServerManager(cfg)
    mgr.reindex(suffix=suffix, auto_restart=auto_restart)
    click.echo("Reindex completed.")


@server.command("start")
@click.pass_context
def server_start(ctx: click.Context) -> None:
    """Start slapd."""
    from .server import ServerManager

    cfg = ctx.obj["config"]
    ServerManager(cfg).start()
    click.echo("slapd started.")


@server.command("stop")
@click.pass_context
def server_stop(ctx: click.Context) -> None:
    """Stop slapd."""
    from .server import ServerManager

    cfg = ctx.obj["config"]
    ServerManager(cfg).stop()
    click.echo("slapd stopped.")


@server.command("restart")
@click.pass_context
def server_restart(ctx: click.Context) -> None:
    """Restart slapd."""
    from .server import ServerManager

    cfg = ctx.obj["config"]
    ServerManager(cfg).restart()
    click.echo("slapd restarted.")


# ── SSH key commands ───────────────────────────────────────────────


@user.command("ssh-key-list")
@click.argument("uid")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def user_ssh_key_list(ctx: click.Context, uid: str, as_json: bool) -> None:
    """List SSH public keys for a user.

    \b
    EXAMPLES
        ldap-manager user ssh-key-list jdoe
        ldap-manager user ssh-key-list jdoe --json

    \b
    NOTES
        Requires the openssh-lpk schema on the server.
    """
    from .sshkeys import SSHKeyManager

    cfg = ctx.obj["config"]
    mgr = SSHKeyManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        keys = mgr.list_keys(conn, uid)

    if as_json:
        _json_out({"uid": uid, "keys": keys, "count": len(keys)})
        return

    if not keys:
        click.echo(f"User '{uid}' has no SSH keys.")
        return

    for i, key in enumerate(keys):
        parts = key.split()
        comment = parts[2] if len(parts) > 2 else ""
        click.echo(f"  [{i}] {parts[0]} ...{parts[1][-20:]} {comment}")


@user.command("ssh-key-add")
@click.argument("uid")
@click.argument("key_or_file")
@click.pass_context
def user_ssh_key_add(ctx: click.Context, uid: str, key_or_file: str) -> None:
    """Add an SSH public key to a user.

    KEY_OR_FILE can be a key string or a path to a .pub file.

    \b
    EXAMPLES
        # From file
        ldap-manager user ssh-key-add jdoe ~/.ssh/id_rsa.pub

        # Inline key
        ldap-manager user ssh-key-add jdoe "ssh-ed25519 AAAA... comment"

    \b
    NOTES
        Duplicates (same key data) are silently skipped.
        Requires openssh-lpk schema on the server.
    """
    from .sshkeys import SSHKeyManager

    # If it looks like a file path, read it
    key = key_or_file
    key_path = Path(key_or_file).expanduser()
    if key_path.is_file():
        key = key_path.read_text().strip()

    cfg = ctx.obj["config"]
    mgr = SSHKeyManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        mgr.add_key(conn, uid, key)

    click.echo(f"Added SSH key to user '{uid}'.")


@user.command("ssh-key-remove")
@click.argument("uid")
@click.argument("index", type=int)
@click.pass_context
def user_ssh_key_remove(ctx: click.Context, uid: str, index: int) -> None:
    """Remove an SSH key by index. Use ssh-key-list to see indexes.

    \b
    EXAMPLES
        ldap-manager user ssh-key-list jdoe    # find the index
        ldap-manager user ssh-key-remove jdoe 0
    """
    from .sshkeys import SSHKeyManager

    cfg = ctx.obj["config"]
    mgr = SSHKeyManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        removed = mgr.remove_key(conn, uid, index)

    click.echo(f"Removed key [{index}]: {removed[:60]}...")


# ── LDIF export/import ─────────────────────────────────────────────


@user.command("export")
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
@click.option("--format", "fmt", type=click.Choice(["ldif", "json"]), default="ldif", help="Output format.")
@click.option("--enabled", is_flag=True, help="Only enabled users.")
@click.option("--disabled", is_flag=True, help="Only disabled users.")
@click.option("--scope", type=click.Choice(["users", "groups", "all"]), default="users", help="What to export.")
@click.pass_context
def user_export(ctx: click.Context, output: str | None, fmt: str, enabled: bool, disabled: bool, scope: str) -> None:
    """Export users/groups as LDIF or JSON.

    \b
    EXAMPLES
        # LDIF to stdout
        ldap-manager user export

        # LDIF to file
        ldap-manager user export -o users.ldif

        # JSON format
        ldap-manager user export --format json -o users.json

        # Export everything
        ldap-manager user export --scope all -o full.ldif

        # Only enabled users as LDIF, pipe to another server
        ldap-manager user export --enabled | ssh other-server ldapadd -x -D cn=admin...

    \b
    NOTES
        LDIF output is RFC 2849 compliant and can be used with ldapadd.
        Binary attributes are base64-encoded.
    """
    cfg = ctx.obj["config"]

    if fmt == "ldif":
        from .ldif_ops import export_ldif

        out_path = Path(output) if output else None
        with LDAPConnection(cfg.ldap) as conn:
            ldif_str = export_ldif(
                conn,
                cfg,
                output=out_path,
                enabled_only=enabled,
                disabled_only=disabled,
                scope=scope,
            )

        if not output:
            click.echo(ldif_str)
        else:
            click.echo(f"Exported to {output}", err=True)

    else:
        # JSON — reuse existing dump
        mgr = UserManager(cfg)
        with LDAPConnection(cfg.ldap) as conn:
            users = mgr.dump_users(conn, enabled_only=enabled, disabled_only=disabled)
        _json_out(users)


@main.command("import")
@click.argument("ldif_file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Parse and validate only.")
@click.option("--stop-on-error", is_flag=True, help="Abort on first error.")
@click.pass_context
def ldif_import(ctx: click.Context, ldif_file: str, dry_run: bool, stop_on_error: bool) -> None:
    """Import entries from an LDIF file.

    \b
    EXAMPLES
        ldap-manager import users.ldif --dry-run
        ldap-manager import users.ldif
        ldap-manager import full_export.ldif --stop-on-error

    \b
    NOTES
        Existing entries are skipped (not updated).
        Use --dry-run first to verify the file parses correctly.
    """
    from .ldif_ops import import_ldif

    cfg = ctx.obj["config"]

    with LDAPConnection(cfg.ldap) as conn:
        counts = import_ldif(
            conn,
            Path(ldif_file),
            dry_run=dry_run,
            stop_on_error=stop_on_error,
        )

    prefix = "[DRY RUN] " if dry_run else ""
    click.echo(f"{prefix}Added: {counts['added']}, Skipped: {counts['skipped']}, Errors: {counts['errors']}")


# ── Tree / OU commands ─────────────────────────────────────────────


@main.group()
@click.pass_context
def tree(ctx: click.Context) -> None:
    """Directory tree and OU management.

    \b
    SUBCOMMANDS
        show      Visualize the DIT tree
        list-ous  List all organizational units
        create-ou Create a new OU
        delete-ou Delete an OU

    \b
    EXAMPLES
        ldap-manager tree show
        ldap-manager tree create-ou Contractors
    """


@tree.command("show")
@click.option("--base", default=None, help="Base DN to start from (default: config base_dn)")
@click.option("--depth", type=int, default=3, help="Max depth to traverse.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def tree_show(ctx: click.Context, base: str | None, depth: int, as_json: bool) -> None:
    """Visualize the directory information tree.

    \b
    EXAMPLES
        ldap-manager tree show
        ldap-manager tree show --depth 5
        ldap-manager tree show --base ou=People,dc=example,dc=com
        ldap-manager tree show --json
    """
    from .tree import TreeManager

    cfg = ctx.obj["config"]
    mgr = TreeManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        entries = mgr.tree(conn, base_dn=base, max_depth=depth)

    if as_json:
        _json_out(entries)
        return

    for entry in entries:
        indent = "  " * entry["depth"]
        dn = entry["dn"]
        # Show just the RDN for readability
        rdn = dn.split(",")[0]
        ocs = ", ".join(entry.get("object_classes", []))
        click.echo(f"{indent}{rdn}  [{ocs}]")


@tree.command("list-ous")
@click.option("--base", default=None, help="Base DN to search under.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def tree_list_ous(ctx: click.Context, base: str | None, as_json: bool) -> None:
    """List all organizational units.

    \b
    EXAMPLES
        ldap-manager tree list-ous
        ldap-manager tree list-ous --json
    """
    from .tree import TreeManager

    cfg = ctx.obj["config"]
    mgr = TreeManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        ous = mgr.list_ous(conn, base_dn=base)

    if as_json:
        _json_out([o.to_dict() for o in ous])
        return

    if not ous:
        click.echo("No OUs found.")
        return

    for o in ous:
        desc = f"  ({o.description})" if o.description else ""
        click.echo(f"  {o.dn}  [{o.children_count} children]{desc}")


@tree.command("create-ou")
@click.argument("ou_name")
@click.option("--parent", default=None, help="Parent DN (default: base_dn)")
@click.option("--description", "-d", default="", help="OU description.")
@click.pass_context
def tree_create_ou(ctx: click.Context, ou_name: str, parent: str | None, description: str) -> None:
    """Create an organizational unit.

    \b
    EXAMPLES
        ldap-manager tree create-ou Contractors
        ldap-manager tree create-ou ServiceAccounts --parent ou=People,dc=example,dc=com
        ldap-manager tree create-ou Vendors -d "External vendor accounts"
    """
    from .tree import TreeManager

    cfg = ctx.obj["config"]
    mgr = TreeManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        dn = mgr.create_ou(conn, ou_name, parent_dn=parent, description=description)

    click.echo(f"Created OU: {dn}")


@tree.command("delete-ou")
@click.argument("dn")
@click.option("--recursive", is_flag=True, help="Delete all children first.")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
@click.pass_context
def tree_delete_ou(ctx: click.Context, dn: str, recursive: bool, yes: bool) -> None:
    """Delete an organizational unit.

    \b
    EXAMPLES
        ldap-manager tree delete-ou ou=Old,dc=example,dc=com
        ldap-manager tree delete-ou ou=Old,dc=example,dc=com --recursive --yes

    \b
    NOTES
        Without --recursive, fails if the OU has children.
        With --recursive, deletes everything underneath.
    """
    from .tree import TreeManager

    if not yes:
        msg = f"Delete OU '{dn}'"
        if recursive:
            msg += " and ALL entries underneath"
        if not click.confirm(f"{msg}? This cannot be undone"):
            click.echo("Aborted.")
            return

    cfg = ctx.obj["config"]
    mgr = TreeManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        count = mgr.delete_ou(conn, dn, recursive=recursive)

    click.echo(f"Deleted {count} entries.")


# ── Password policy commands ───────────────────────────────────────


@main.group("ppolicy")
@click.pass_context
def ppolicy(ctx: click.Context) -> None:
    """Password policy status and information.

    \b
    SUBCOMMANDS
        status    Password status for a user (expiry, lockout)
        policy    Show the active password policy configuration
        check-all List all users with password issues

    \b
    EXAMPLES
        ldap-manager ppolicy status jdoe
        ldap-manager ppolicy policy
        ldap-manager ppolicy check-all --locked
    """


@ppolicy.command("status")
@click.argument("uid")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def ppolicy_status(ctx: click.Context, uid: str, as_json: bool) -> None:
    """Show password policy status for a user.

    \b
    EXAMPLES
        ldap-manager ppolicy status jdoe
        ldap-manager ppolicy status jdoe --json

    \b
    NOTES
        Requires the ppolicy overlay to be loaded on the server.
        Shows: last change, expiry, lockout, failure count.
    """
    from .ppolicy import PPasswordManager

    cfg = ctx.obj["config"]
    mgr = PPasswordManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        st = mgr.get_user_status(conn, uid)

    if st is None:
        click.echo(f"User '{uid}' not found.", err=True)
        sys.exit(1)

    if as_json:
        _json_out(st.to_dict())
        return

    lock_str = click.style("LOCKED", fg="red") if st.locked else click.style("OK", fg="green")
    click.echo(f"User:           {st.uid}")
    click.echo(f"Account:        {lock_str}")
    click.echo(f"Last changed:   {st.changed_time or 'unknown'}")
    click.echo(f"Expires:        {st.expires or 'n/a (no maxAge policy)'}")
    click.echo(f"Failed logins:  {st.failure_count}")
    click.echo(f"Must change:    {'yes' if st.must_change else 'no'}")
    if st.policy_dn:
        click.echo(f"Policy:         {st.policy_dn}")


@ppolicy.command("policy")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def ppolicy_config(ctx: click.Context, as_json: bool) -> None:
    """Show the active password policy configuration.

    \b
    EXAMPLES
        ldap-manager ppolicy policy
        ldap-manager ppolicy policy --json
    """
    from .ppolicy import PPasswordManager

    cfg = ctx.obj["config"]
    mgr = PPasswordManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        pol = mgr.get_policy(conn)

    if pol is None:
        click.echo("No password policy found. Is the ppolicy overlay loaded?")
        return

    if as_json:
        _json_out(pol.to_dict())
        return

    click.echo(f"Policy DN:          {pol.dn}")
    click.echo(f"Max age:            {pol.max_age or 'unlimited'} seconds")
    click.echo(f"Min age:            {pol.min_age or 0} seconds")
    click.echo(f"Min length:         {pol.min_length or 'not set'}")
    click.echo(f"Max failures:       {pol.max_failure or 'unlimited'}")
    click.echo(f"Lockout:            {'enabled' if pol.lockout else 'disabled'}")
    click.echo(f"Lockout duration:   {pol.lockout_duration or 'forever'} seconds")
    click.echo(f"Grace logins:       {pol.grace_limit or 0}")
    click.echo(f"Must change:        {'yes' if pol.must_change else 'no'}")
    click.echo(f"History:            {pol.in_history or 0} passwords")


@ppolicy.command("check-all")
@click.option("--expired", is_flag=True, help="Only show expired passwords.")
@click.option("--locked", is_flag=True, help="Only show locked accounts.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def ppolicy_check_all(ctx: click.Context, expired: bool, locked: bool, as_json: bool) -> None:
    """List all users with password policy status.

    \b
    EXAMPLES
        ldap-manager ppolicy check-all
        ldap-manager ppolicy check-all --locked
        ldap-manager ppolicy check-all --expired --json
    """
    from .ppolicy import PPasswordManager

    cfg = ctx.obj["config"]
    mgr = PPasswordManager(cfg)

    with LDAPConnection(cfg.ldap) as conn:
        statuses = mgr.check_all_users(conn, expired_only=expired, locked_only=locked)

    if as_json:
        _json_out([s.to_dict() for s in statuses])
        return

    if not statuses:
        click.echo("No users found matching criteria.")
        return

    for s in statuses:
        lock = click.style("LOCKED", fg="red") if s.locked else "ok"
        click.echo(f"  {s.uid:<20} {lock:<10} changed={s.changed_time or '?':<20} failures={s.failure_count}")


# ── Audit commands ─────────────────────────────────────────────────


@main.group()
@click.pass_context
def audit(ctx: click.Context) -> None:
    """Audit log — view modification history.

    \b
    SUBCOMMANDS
        log       Query the audit log
        status    Show audit log location and status

    \b
    EXAMPLES
        ldap-manager audit log
        ldap-manager audit log --action user.create --limit 20
    """


@audit.command("log")
@click.option("--action", default=None, help="Filter by action prefix (e.g. 'user', 'group.add_member').")
@click.option("--target", default=None, help="Filter by target substring.")
@click.option("--since", default=None, help="Only entries after this ISO timestamp.")
@click.option("--limit", type=int, default=50, help="Max entries to show.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def audit_log(ctx: click.Context, action: str | None, target: str | None, since: str | None, limit: int, as_json: bool) -> None:
    """Query the audit log.

    \b
    EXAMPLES
        ldap-manager audit log
        ldap-manager audit log --action user.create
        ldap-manager audit log --target jdoe --limit 10
        ldap-manager audit log --since 2024-01-01T00:00:00Z --json
    """
    from .audit import AuditLogger

    logger = AuditLogger()
    entries = logger.query(action=action, target=target, since=since, limit=limit)

    if as_json:
        _json_out(entries)
        return

    if not entries:
        click.echo("No audit entries found.")
        return

    for e in entries:
        ts = e.get("timestamp", "?")[:19]
        act = e.get("action", "?")
        tgt = e.get("target", "?")
        ok = "✓" if e.get("success", True) else "✗"
        click.echo(f"  {ts}  {ok} {act:<25} {tgt}")


@audit.command("status")
@click.pass_context
def audit_status(ctx: click.Context) -> None:
    """Show audit log location and status."""
    from .audit import AuditLogger

    logger = AuditLogger()
    click.echo(f"Log file: {logger.path}")
    click.echo(f"Enabled:  {logger.enabled}")

    if logger.path.is_file():
        size_kb = logger.path.stat().st_size / 1024
        with logger.path.open() as f:
            lines = sum(1 for _ in f)
        click.echo(f"Size:     {size_kb:.1f} KB")
        click.echo(f"Entries:  {lines}")


if __name__ == "__main__":
    main(standalone_mode=not os.environ.get("LDAP_MANAGER_DEBUG"))
