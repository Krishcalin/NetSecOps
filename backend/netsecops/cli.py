"""``netsecops-cli`` — operational commands (FR-ADM-02).

Covers key generation, the bootstrap administrator, audit-chain verification, master-key
rotation and health checks. Device-facing commands (``audit-commands``, SRS §8.1 item 7)
arrive with the adapters in Phase 1.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from netsecops.core.config import get_settings
from netsecops.core.crypto import generate_master_key
from netsecops.core.logging import configure_logging
from netsecops.core.rbac import Permission, Role
from netsecops.core.security import generate_password

app = typer.Typer(
    name="netsecops-cli",
    help="NetSecOps operational CLI.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


# ────────────────────────────── key management ──────────────────────────────


@app.command("generate-master-key")
def cmd_generate_master_key() -> None:
    """Generate a credential-vault master key (FR-CRED-02).

    Store it in a secret manager and back it up separately from the database. Losing it
    means losing every stored device credential.
    """
    console.print(generate_master_key())


@app.command("generate-secret-key")
def cmd_generate_secret_key() -> None:
    """Generate a JWT signing key. Rotating it invalidates every live session."""
    import secrets

    console.print(secrets.token_urlsafe(64))


# ───────────────────────────── user bootstrap ───────────────────────────────


@app.command("create-admin")
def cmd_create_admin(
    username: Annotated[str, typer.Option(prompt=True)],
    email: Annotated[str, typer.Option(prompt=True)],
    password: Annotated[
        str | None,
        typer.Option(
            help="Leave unset to have one generated and printed once.",
            hide_input=True,
        ),
    ] = None,
    full_name: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Create the initial Super Admin (SRS §9 bootstrap)."""
    configure_logging()
    generated = password is None
    secret = password or generate_password()

    async def _run() -> None:
        from netsecops.db.session import session_scope
        from netsecops.services.users import UserService

        async with session_scope() as session:
            service = UserService(session)
            if await service.get_by_username(username) is not None:
                err_console.print(f"[red]A user named '{username}' already exists.[/red]")
                raise typer.Exit(code=1)

            await service.create(
                username=username,
                email=email,
                password=secret,
                full_name=full_name,
                roles={Role.SUPER_ADMIN},
                must_change_password=generated,
            )

    asyncio.run(_run())

    console.print(f"[green]Created Super Admin:[/green] {username}")
    if generated:
        console.print(f"[yellow]Generated password:[/yellow] {secret}")
        console.print("[dim]Shown once. You will be asked to change it at first sign-in.[/dim]")


@app.command("reset-password")
def cmd_reset_password(
    username: Annotated[str, typer.Argument()],
    password: Annotated[str | None, typer.Option(hide_input=True)] = None,
) -> None:
    """Reset a user's password out-of-band (break-glass recovery)."""
    configure_logging()
    generated = password is None
    secret = password or generate_password()

    async def _run() -> None:
        from netsecops.core.rbac import Principal, Scope
        from netsecops.db.session import session_scope
        from netsecops.services.auth import AuthService
        from netsecops.services.users import UserService

        async with session_scope() as session:
            user = await UserService(session).get_by_username(username)
            if user is None:
                err_console.print(f"[red]No such user: {username}[/red]")
                raise typer.Exit(code=1)

            actor = Principal(
                id=user.id, username="cli", roles=frozenset({Role.SUPER_ADMIN}), scope=Scope.all()
            )
            await AuthService(session).set_password(user, secret, actor=actor, reason="reset")
            user.must_change_password = True

    asyncio.run(_run())
    console.print(f"[green]Password reset for:[/green] {username}")
    if generated:
        console.print(f"[yellow]New password:[/yellow] {secret}")


@app.command("reset-mfa")
def cmd_reset_mfa(
    username: Annotated[str, typer.Argument()],
) -> None:
    """Clear a user's MFA enrolment out-of-band (break-glass recovery).

    Disabling MFA through the API needs an authenticated session, which is exactly
    what a lost authenticator denies you — so this path exists for an operator with
    server access. The user signs in with their password alone afterwards, and can
    re-enrol from their profile.

    The action is recorded in the audit log like any other MFA change (FR-AUD-01).
    """
    configure_logging()

    async def _run() -> None:
        from netsecops.core.rbac import Principal, Scope
        from netsecops.db.session import session_scope
        from netsecops.services.auth import AuthService
        from netsecops.services.users import UserService

        async with session_scope() as session:
            user = await UserService(session).get_by_username(username)
            if user is None:
                err_console.print(f"[red]No such user: {username}[/red]")
                raise typer.Exit(code=1)

            if not user.mfa_enabled and user.mfa_secret is None:
                console.print(f"[yellow]MFA is not enabled for {username}; nothing to do.[/yellow]")
                return

            actor = Principal(
                id=user.id, username="cli", roles=frozenset({Role.SUPER_ADMIN}), scope=Scope.all()
            )
            await AuthService(session).disable_mfa(user, actor)

    asyncio.run(_run())
    console.print(f"[green]MFA cleared for:[/green] {username}")
    console.print("[dim]They can sign in with their password and re-enrol from Profile.[/dim]")


@app.command("audit-commands")
def cmd_audit_commands(
    platform: Annotated[
        str | None, typer.Option(help="Limit to one platform; omit for all")
    ] = None,
) -> None:
    """Print the effective read-only allow-list per adapter (SRS §8.1 item 7).

    This is the transparency mechanism: a customer's security reviewer can read exactly
    what NetSecOps is permitted to send to their equipment before approving onboarding.
    Nothing outside this list ever reaches a device — the conformance tests in CI fail
    the build otherwise.
    """
    from netsecops.adapters.policies import POLICIES

    selected = {platform: POLICIES[platform]} if platform else POLICIES
    if platform and platform not in POLICIES:
        err_console.print(f"[red]No policy for platform '{platform}'.[/red]")
        err_console.print(f"Known platforms: {', '.join(sorted(POLICIES))}")
        raise typer.Exit(code=1)

    for name in sorted(selected):
        policy = selected[name]
        console.print(f"\n[bold cyan]{name}[/bold cyan]")

        if policy.commands:
            console.print("  [dim]commands[/dim]")
            for rule in policy.commands:
                marker = " [yellow](session-only)[/yellow]" if rule.session_only else ""
                console.print(f"    {rule.pattern}{marker}")
                if rule.note:
                    console.print(f"      [dim]{rule.note}[/dim]")

        if policy.http:
            console.print("  [dim]HTTP[/dim]")
            for http_rule in policy.http:
                console.print(f"    {http_rule.method} {http_rule.path_prefix}")
                if http_rule.reason:
                    console.print(f"      [dim]{http_rule.reason}[/dim]")

        if policy.forbid_pipe:
            console.print("  [dim]piping command output is forbidden on this platform[/dim]")

    console.print(
        "\n[dim]Anything not listed above is rejected before transmission "
        "and recorded as a critical audit event.[/dim]"
    )


# ──────────────────────────────── audit ─────────────────────────────────────


@app.command("verify-audit-chain")
def cmd_verify_audit_chain(
    org_id: Annotated[int, typer.Option(help="Organisation id (DATA-04)")] = 1,
) -> None:
    """Replay the audit hash chain and report any tampering (FR-AUD-02)."""
    configure_logging()

    async def _run() -> None:
        from netsecops.db.session import session_scope
        from netsecops.services.audit import AuditService

        async with session_scope() as session:
            result = await AuditService(session).verify_chain(org_id)

        if result.valid:
            console.print(f"[green]Audit chain intact[/green] — {result.total:,} records verified.")
        else:
            err_console.print(
                f"[red]AUDIT CHAIN BROKEN[/red] at record id {result.first_invalid_id}\n"
                f"{result.reason}\n"
                f"Records inspected before the break: {result.total:,}"
            )
            raise typer.Exit(code=2)

    asyncio.run(_run())


# ───────────────────────────── key rotation ─────────────────────────────────


@app.command("rotate-master-key")
def cmd_rotate_master_key(
    confirm: Annotated[bool, typer.Option("--confirm", help="Required to proceed")] = False,
) -> None:
    """Re-wrap every stored secret under the current master key (FR-CRED-02).

    Set the *new* key in the environment first; the old one must remain reachable by the
    configured provider until the re-wrap completes.
    """
    if not confirm:
        err_console.print(
            "[yellow]Re-run with --confirm.[/yellow] Ensure the database is backed up "
            "and the previous master key is retained until this completes."
        )
        raise typer.Exit(code=1)

    configure_logging()

    async def _run() -> None:
        from sqlalchemy import select

        from netsecops.core.crypto import build_vault
        from netsecops.db.models.user import MFASecret
        from netsecops.db.session import session_scope

        vault = build_vault()
        rewrapped = 0

        async with session_scope() as session:
            rows = (await session.execute(select(MFASecret))).scalars().all()
            for row in rows:
                aad = str(row.user_id)
                row.encrypted_secret = vault.rewrap(row.encrypted_secret, aad=aad)
                if row.encrypted_recovery_codes is not None:
                    row.encrypted_recovery_codes = vault.rewrap(
                        row.encrypted_recovery_codes, aad=aad
                    )
                rewrapped += 1

        # Device credentials join this loop in Phase 1, when the vault table exists.
        console.print(f"[green]Re-wrapped {rewrapped} secret(s).[/green]")

    asyncio.run(_run())


# ──────────────────────────────── health ────────────────────────────────────


@app.command("health-check")
def cmd_health_check() -> None:
    """Verify the database is reachable and migrations are current."""
    configure_logging()

    async def _run() -> None:
        from sqlalchemy import text

        from netsecops.db.session import session_scope

        try:
            async with session_scope() as session:
                await session.execute(text("SELECT 1"))
                revision = (
                    await session.execute(text("SELECT version_num FROM alembic_version"))
                ).scalar_one_or_none()
        except Exception as exc:
            err_console.print(f"[red]Database unreachable:[/red] {exc}")
            raise typer.Exit(code=1) from exc

        console.print("[green]Database reachable.[/green]")
        console.print(f"Schema revision: [cyan]{revision or 'none — run migrations'}[/cyan]")

    asyncio.run(_run())


@app.command("show-config")
def cmd_show_config() -> None:
    """Print effective configuration with every secret masked (C-2)."""
    settings = get_settings()
    table = Table(title="NetSecOps configuration", show_lines=False)
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    secret_fields = {"secret_key", "master_key", "nvd_api_key", "database_url"}
    for name, value in settings.model_dump().items():
        rendered = "***" if name in secret_fields and value else str(value)
        table.add_row(name, rendered)

    console.print(table)


@app.command("permissions")
def cmd_permissions() -> None:
    """Print the role/permission matrix (FR-AUTH-05)."""
    table = Table(title="Role × permission matrix")
    table.add_column("Permission", style="cyan", no_wrap=True)
    for role in Role:
        table.add_column(role.value.replace("_", "\n"), justify="center")

    from netsecops.core.rbac import ROLE_PERMISSIONS

    for permission in sorted(Permission, key=lambda p: p.value):
        cells = [
            "[green]Y[/green]" if permission in ROLE_PERMISSIONS[role] else "[dim]·[/dim]"
            for role in Role
        ]
        table.add_row(permission.value, *cells)

    console.print(table)


@app.command("version")
def cmd_version() -> None:
    from netsecops import __version__

    console.print(f"NetSecOps {__version__}")
    console.print(f"Python    {sys.version.split()[0]}")
    console.print(f"Time      {datetime.now(UTC).isoformat()}")


if __name__ == "__main__":
    app()
