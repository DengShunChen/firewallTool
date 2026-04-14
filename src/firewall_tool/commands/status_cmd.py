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
    help="顯示 firewalld 狀態與預設／使用中 zone。",
    invoke_without_command=True,
)


@status_app.callback()
def status_root(
    ctx: typer.Context,
    all_zones: bool = typer.Option(
        False,
        "--all-zones",
        help="一併列出 --list-all-zones（較長；線上與 offline 皆可用）。",
    ),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    if is_offline():
        state = "N/A（offline 模式；無 D-Bus daemon 狀態）"
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
        ("狀態", state),
        ("預設 zone", default_zone),
    ]
    print_kv(console, "firewalld", rows)

    if is_offline():
        console.print(
            "[dim]offline 模式下無法取得「使用中 zone」的 runtime 資訊；"
            "請改用 [bold]fwctl --offline zone show ZONE[/bold] 或 "
            "[bold]fwctl --offline status --all-zones[/bold]。[/dim]"
        )
    else:
        try:
            active = run_firewall_cmd(["--get-active-zones"], check=True).stdout
        except FirewallCmdError as e:
            print_firewall_cmd_error(console, e)
            raise typer.Exit(e.code) from e

        az = parse_active_zones(active)
        if az:
            print_kv(console, "使用中 zones", [(z, d or "（無細節）") for z, d in az])
        else:
            console.print("[dim]未取得 active zones 內容。[/dim]")

    if all_zones:
        try:
            big = run_firewall_cmd(["--list-all-zones"], check=True).stdout
        except FirewallCmdError as e:
            print_firewall_cmd_error(console, e)
            raise typer.Exit(e.code) from e
        console.print(Panel(big.strip(), title="list-all-zones", expand=False))
