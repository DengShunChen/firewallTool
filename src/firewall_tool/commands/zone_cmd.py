"""Zone list/show."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from firewall_tool.formatters import (
    print_firewall_cmd_error,
    print_lines_table,
    split_space_list,
)
from firewall_tool.runner import FirewallCmdError, run_firewall_cmd

console = Console()
zone_app = typer.Typer(help="List or inspect zones.")


@zone_app.command("list")
def zone_list() -> None:
    try:
        out = run_firewall_cmd(["--get-zones"], check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    zones = split_space_list(out)
    print_lines_table(console, "Zones", zones, column_name="zone")


@zone_app.command("show")
def zone_show(
    name: str = typer.Argument(..., help="Zone name, e.g. public."),
) -> None:
    try:
        out = run_firewall_cmd(["--list-all", f"--zone={name}"], check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    console.print(Panel(out.strip(), title=f"zone: {name}", expand=False))
