"""Status / overview commands."""

from __future__ import annotations

import typer
from rich.console import Console

from firewall_tool.formatters import parse_active_zones, print_kv
from firewall_tool.runner import FirewallCmdError, run_firewall_cmd

console = Console()
status_app = typer.Typer(
    help="Show firewalld state and default/active zones.",
    invoke_without_command=True,
)


@status_app.callback()
def status_root(
    ctx: typer.Context,
    all_zones: bool = typer.Option(
        False,
        "--all-zones",
        help="Include firewall-cmd --list-all-zones (verbose).",
    ),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    try:
        state = run_firewall_cmd(["--state"], check=True).stdout.strip()
    except FirewallCmdError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(e.code) from e

    try:
        default_zone = run_firewall_cmd(["--get-default-zone"], check=True).stdout.strip()
        active = run_firewall_cmd(["--get-active-zones"], check=True).stdout
    except FirewallCmdError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(e.code) from e

    rows = [
        ("State", state),
        ("Default zone", default_zone),
    ]
    print_kv(console, "firewalld", rows)

    az = parse_active_zones(active)
    if az:
        print_kv(console, "Active zones", [(z, d or "(no details)") for z, d in az])
    else:
        console.print("[dim]No active zones output.[/dim]")

    if all_zones:
        try:
            big = run_firewall_cmd(["--list-all-zones"], check=True).stdout
        except FirewallCmdError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(e.code) from e
        from rich.panel import Panel

        console.print(Panel(big.strip(), title="list-all-zones", expand=False))
