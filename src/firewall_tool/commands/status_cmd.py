"""Status / overview commands."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from firewall_tool.formatters import (
    parse_active_zones,
    print_firewall_cmd_error,
    print_kv,
)
from firewall_tool.runner import FirewallCmdError, is_offline, run_firewall_cmd

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
        help="Include --list-all-zones (verbose; works online and offline).",
    ),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    if is_offline():
        state = "N/A (offline mode; no D-Bus daemon state)"
    else:
        try:
            state = run_firewall_cmd(["--state"], check=True).stdout.strip()
        except FirewallCmdError as e:
            print_firewall_cmd_error(console, e)
            raise typer.Exit(e.code) from e

    try:
        default_zone = run_firewall_cmd(["--get-default-zone"], check=True).stdout.strip()
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e

    rows = [
        ("State", state),
        ("Default zone", default_zone),
    ]
    print_kv(console, "firewalld", rows)

    if is_offline():
        console.print(
            "[dim]Active zones (runtime) are not available in --offline mode; "
            "use `fwctl --offline zone show ZONE` or `fwctl --offline status --all-zones`.[/dim]"
        )
    else:
        try:
            active = run_firewall_cmd(["--get-active-zones"], check=True).stdout
        except FirewallCmdError as e:
            print_firewall_cmd_error(console, e)
            raise typer.Exit(e.code) from e

        az = parse_active_zones(active)
        if az:
            print_kv(console, "Active zones", [(z, d or "(no details)") for z, d in az])
        else:
            console.print("[dim]No active zones output.[/dim]")

    if all_zones:
        try:
            big = run_firewall_cmd(["--list-all-zones"], check=True).stdout
        except FirewallCmdError as e:
            print_firewall_cmd_error(console, e)
            raise typer.Exit(e.code) from e
        console.print(Panel(big.strip(), title="list-all-zones", expand=False))
