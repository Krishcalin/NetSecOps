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

    # Derived from the field types, not a hand-kept list. A list has to be remembered
    # every time a credential is added, and the failure mode is printing it.
    secret_fields = {
        name
        for name, field in type(settings).model_fields.items()
        if "SecretStr" in str(field.annotation)
    }
    # database_url is not a SecretStr — it is a DSN type — but it carries a password.
    secret_fields.add("database_url")

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


@app.command("scheduler")
def cmd_scheduler(
    interval: Annotated[
        float, typer.Option(help="Seconds between checks for due schedules.")
    ] = 30.0,
) -> None:
    """Run the recurring-assessment scheduler (FR-JOB-02).

    Long-running. It fires schedules whose time has come and enqueues them through the
    same path the API uses, so a scheduled collection and a manual one are the same job.

    Safe to run more than one: due schedules are claimed with `FOR UPDATE SKIP LOCKED`,
    so a second process passes over anything the first is holding. Running none means
    schedules do not fire, which the console shows as a next-run time in the past.
    """
    import asyncio

    from netsecops.workers.scheduler import run

    console.print(f"Scheduler running, checking every {interval:g}s. Ctrl-C to stop.")
    try:
        asyncio.run(run(interval=interval))
    except KeyboardInterrupt:
        console.print("Stopped.")


@app.command("worker")
def cmd_worker(
    idle: Annotated[
        float, typer.Option(help="Seconds to wait when there is nothing queued.")
    ] = 5.0,
) -> None:
    """Run the job worker (FR-JOB-05).

    Long-running. It claims queued jobs and executes them — collections, assessments,
    discovery runs, feed syncs, notification dispatch, SIEM forwarding and reports.

    `deploy/docker-compose.yml` has referenced this command since Phase 1 and it did not
    exist, so the `workers` profile could not start. That was survivable while every job
    came from an API request, which runs in-process; it stopped being survivable with the
    scheduler, which creates job rows and enqueues nothing — without a worker, every
    scheduled job sits queued for ever.

    Safe to run more than one: jobs are claimed with `FOR UPDATE SKIP LOCKED`, so a second
    process passes over what the first holds. Running none means queued jobs do not
    execute, which the console shows as a job that never leaves `queued`.
    """
    import asyncio

    from netsecops.workers.worker import run

    console.print(f"Worker running, polling every {idle:g}s when idle. Ctrl-C to stop.")
    try:
        asyncio.run(run(idle_seconds=idle))
    except KeyboardInterrupt:
        console.print("Stopped.")


# ──────────────────────────── demonstration ─────────────────────────────────


@app.command("demo-seed")
def cmd_demo_seed(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Seed even though this installation already holds devices it did not create.",
        ),
    ] = False,
) -> None:
    """Stand up a demonstration estate, so the product can be evaluated without a device.

    Four devices across three vendors, each with a configuration ingested through the
    same path an operator's upload uses and assessed by the same check engine against
    the same shipped library. Nothing is contacted and nothing is fabricated: the
    findings are the product's actual opinion of those configurations.

    It refuses to run if the inventory already holds a device it did not create, because
    demonstration devices in a real estate are reported on, counted in compliance
    percentages, and eventually collected from. `demo-purge` removes exactly what this
    created, identified by tag.
    """
    configure_logging()

    async def _run() -> None:
        from netsecops.db.session import session_scope
        from netsecops.demo import seed_demo_estate

        async with session_scope() as session:
            report = await seed_demo_estate(session, force=force)

        if report.devices == 0 and not report.notes:
            console.print("[yellow]Nothing to do.[/yellow]")
            return

        console.print(f"[green]Seeded[/green] {report.devices} device(s)")
        console.print(f"  configurations ingested  {report.snapshots}")
        console.print(f"  checks run               {report.checks_run}")
        console.print(f"  findings now open        {report.findings}")
        console.print(f"  advisories imported      {report.advisories}")
        console.print(f"  vulnerability matches    {report.vulnerability_matches}")
        for note in report.notes:
            console.print(f"  [dim]{note}[/dim]")

        console.print()
        console.print("Two path queries worth trying, under Path Analysis:")
        console.print(
            "  [bold]10.10.10.50 → 10.20.0.10 tcp/443[/bold]  "
            "every firewall permits it, and one of them may have rewritten the addresses "
            "the later ones were asked about"
        )
        console.print(
            "  [bold]10.10.10.50 → 10.20.0.10 tcp/22[/bold]   "
            "blocked, and it names the device and the rule"
        )
        console.print()
        console.print("[dim]Run `netsecops-cli demo-purge` to remove it.[/dim]")

    try:
        asyncio.run(_run())
    except Exception as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


@app.command("demo-purge")
def cmd_demo_purge() -> None:
    """Remove every device the demo seeder created, and nothing else.

    Identified by tag, so a device added by hand during the evaluation survives — this
    runs at exactly the moment somebody is onboarding their first real device, and
    deleting it then would be the worst possible time. Imported advisories are left in
    place: they are public data about the world rather than anything about this estate.
    """
    configure_logging()

    async def _run() -> None:
        from netsecops.db.session import session_scope
        from netsecops.demo import purge_demo_estate

        async with session_scope() as session:
            removed = await purge_demo_estate(session)

        console.print(f"[green]Removed[/green] {removed} demonstration device(s).")

    asyncio.run(_run())


@app.command("version")
def cmd_version() -> None:
    from netsecops import __version__

    console.print(f"NetSecOps {__version__}")
    console.print(f"Python    {sys.version.split()[0]}")
    console.print(f"Time      {datetime.now(UTC).isoformat()}")


if __name__ == "__main__":
    app()
