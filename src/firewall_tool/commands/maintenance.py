"""Reload and panic mode."""

from __future__ import annotations

import typer
from rich.console import Console

from firewall_tool.runner import FirewallCmdError, require_root, run_firewall_cmd

console = Console()
panic_app = typer.Typer(help="Panic mode drops all routed traffic.")


def reload_action(*, dry_run: bool, yes: bool) -> None:
    if not dry_run and not yes:
        typer.confirm("Reload firewalld runtime from permanent configuration?", abort=True)
    if not dry_run:
        require_root("reload firewalld")
    try:
        res = run_firewall_cmd(["--reload"], check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]Reloaded.[/green]", res.stdout.strip())


@panic_app.command("on")
def panic_on(
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    if not dry_run and not yes:
        typer.confirm(
            "Enable panic mode? This will block essentially all network traffic.",
            default=False,
            abort=True,
        )
    if not dry_run:
        require_root("enable panic mode")
    try:
        res = run_firewall_cmd(["--panic-on"], check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[red]Panic ON[/red]", res.stdout.strip())


@panic_app.command("off")
def panic_off(
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    if not dry_run and not yes:
        typer.confirm("Disable panic mode?", default=True, abort=True)
    if not dry_run:
        require_root("disable panic mode")
    try:
        res = run_firewall_cmd(["--panic-off"], check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]Panic OFF[/green]", res.stdout.strip())
