"""Zone list/show."""

from __future__ import annotations

from typing import List

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
zone_app = typer.Typer(help="列出或檢視 zone。")


def _perm(permanent: bool) -> List[str]:
    return ["--permanent"] if permanent else []


@zone_app.command("list")
def zone_list(
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="讀取永久設定中的 zone 名單（等同 firewall-cmd --permanent --get-zones）。",
    ),
) -> None:
    args: List[str] = [*_perm(permanent), "--get-zones"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    zones = split_space_list(out)
    title = "Zones（permanent）" if permanent else "Zones（runtime）"
    print_lines_table(console, title, zones, column_name="zone")


@zone_app.command("show")
def zone_show(
    name: str = typer.Argument(..., help="Zone 名稱，例如 public。"),
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="顯示永久設定中該 zone 的內容。",
    ),
) -> None:
    args: List[str] = [*_perm(permanent), "--list-all", f"--zone={name}"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    sub = "permanent" if permanent else "runtime"
    console.print(Panel(out.strip(), title=f"zone: {name}（{sub}）", expand=False))
