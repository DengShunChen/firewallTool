"""Service and port management."""

from __future__ import annotations

from typing import List, Optional

import typer
from rich.console import Console

from firewall_tool.formatters import print_firewall_cmd_error, print_lines_table
from firewall_tool.runner import (
    FirewallCmdError,
    is_offline,
    require_root,
    run_firewall_cmd,
)

console = Console()

service_app = typer.Typer(help="檢視或變更允許的服務（service）。")
port_app = typer.Typer(help="檢視或變更允許的埠（port）。")


def _zone_args(zone: Optional[str]) -> List[str]:
    return [f"--zone={zone}"] if zone else []


def _perm(permanent: bool) -> List[str]:
    return ["--permanent"] if permanent else []


def _confirm_mut(*, dry_run: bool, yes: bool, msg: str) -> None:
    if dry_run or yes:
        return
    typer.confirm(msg, default=False, abort=True)


@service_app.command("list")
def service_list(
    zone: Optional[str] = typer.Option(None, "--zone", "-z", help="Zone 名稱。"),
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="顯示 permanent 設定，而非目前 runtime。",
    ),
) -> None:
    args: List[str] = ["--list-services", *_perm(permanent), *_zone_args(zone)]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    lines = [x for x in out.split() if x.strip()]
    title = "服務（permanent）" if permanent else "服務（runtime）"
    print_lines_table(console, title, lines, column_name="service")


@service_app.command("add")
def service_add(
    name: str = typer.Argument(..., help="服務名稱，例如 ssh。"),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run", help="只顯示將執行的 firewall-cmd 參數。"),
    yes: bool = typer.Option(False, "--yes", "-y", help="略過確認。"),
) -> None:
    scope = "permanent" if permanent else "runtime"
    z = zone or "（預設 zone）"
    _confirm_mut(
        dry_run=dry_run,
        yes=yes,
        msg=f"要在 zone [bold]{z}[/bold] 新增服務 [bold]{name}[/bold]（[bold]{scope}[/bold]）？",
    )
    if not dry_run:
        require_root("add services")
    args: List[str] = [
        f"--add-service={name}",
        *_perm(permanent),
        *_zone_args(zone),
    ]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        if not is_offline() and permanent:
            console.print(
                "[dim]若使用 --permanent，之後請 [bold]fwctl reload[/bold] 讓 runtime 套用。[/dim]"
            )
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    if permanent and not is_offline():
        console.print("[dim]若要讓 runtime 與 permanent 一致，請執行：[/dim] [bold]fwctl reload[/bold]")


@service_app.command("remove")
def service_remove(
    name: str = typer.Argument(..., help="服務名稱。"),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    scope = "permanent" if permanent else "runtime"
    z = zone or "（預設 zone）"
    _confirm_mut(
        dry_run=dry_run,
        yes=yes,
        msg=f"要從 zone [bold]{z}[/bold] 移除服務 [bold]{name}[/bold]（[bold]{scope}[/bold]）？",
    )
    if not dry_run:
        require_root("remove services")
    args: List[str] = [
        f"--remove-service={name}",
        *_perm(permanent),
        *_zone_args(zone),
    ]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    if permanent and not is_offline():
        console.print("[dim]若要讓 runtime 與 permanent 一致，請執行：[/dim] [bold]fwctl reload[/bold]")


@port_app.command("list")
def port_list(
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
) -> None:
    args: List[str] = ["--list-ports", *_perm(permanent), *_zone_args(zone)]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    parts = [p.strip() for p in out.split() if p.strip()]
    title = "埠（permanent）" if permanent else "埠（runtime）"
    print_lines_table(console, title, parts, column_name="port")


@port_app.command("add")
def port_add(
    spec: str = typer.Argument(
        ...,
        help="埠規格，例如 443/tcp 或 1000-2000/udp。",
    ),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    scope = "permanent" if permanent else "runtime"
    _confirm_mut(
        dry_run=dry_run,
        yes=yes,
        msg=f"要新增埠 [bold]{spec}[/bold]（[bold]{scope}[/bold]）？",
    )
    if not dry_run:
        require_root("add ports")
    args: List[str] = [
        f"--add-port={spec}",
        *_perm(permanent),
        *_zone_args(zone),
    ]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    if permanent and not is_offline():
        console.print("[dim]若要讓 runtime 與 permanent 一致，請執行：[/dim] [bold]fwctl reload[/bold]")


@port_app.command("remove")
def port_remove(
    spec: str = typer.Argument(..., help="埠規格，例如 443/tcp。"),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    scope = "permanent" if permanent else "runtime"
    _confirm_mut(
        dry_run=dry_run,
        yes=yes,
        msg=f"要移除埠 [bold]{spec}[/bold]（[bold]{scope}[/bold]）？",
    )
    if not dry_run:
        require_root("remove ports")
    args: List[str] = [
        f"--remove-port={spec}",
        *_perm(permanent),
        *_zone_args(zone),
    ]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    if permanent and not is_offline():
        console.print("[dim]若要讓 runtime 與 permanent 一致，請執行：[/dim] [bold]fwctl reload[/bold]")
