"""Reload and panic mode."""

from __future__ import annotations

import typer
from rich.console import Console

from firewall_tool.formatters import print_firewall_cmd_error

from firewall_tool.runner import (
    FirewallCmdError,
    is_offline,
    require_root,
    run_firewall_cmd,
)

console = Console()
panic_app = typer.Typer(help="Panic 模式會丟棄幾乎所有轉送流量。")


def reload_action(*, dry_run: bool, yes: bool) -> None:
    if is_offline():
        console.print(
            "[red]offline 模式下無法 reload（無 runtime daemon）。"
            "請啟動 firewalld 後，在不加 [bold]--offline[/bold] 的情況下執行 [bold]fwctl reload[/bold]。[/red]"
        )
        raise typer.Exit(2)
    if not dry_run and not yes:
        typer.confirm("要從 permanent 設定重載 firewalld runtime 嗎？", default=False, abort=True)
    if not dry_run:
        require_root("reload firewalld")
    try:
        res = run_firewall_cmd(["--reload"], check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]已重載。[/green]", res.stdout.strip())


@panic_app.command("on")
def panic_on(
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    if is_offline():
        console.print(
            "[red]offline 模式下無法使用 panic（僅 runtime）。[/red]"
        )
        raise typer.Exit(2)
    if not dry_run and not yes:
        typer.confirm(
            "要啟用 panic 模式嗎？將阻擋幾乎所有網路流量。",
            default=False,
            abort=True,
        )
    if not dry_run:
        require_root("enable panic mode")
    try:
        res = run_firewall_cmd(["--panic-on"], check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[red]Panic 已開啟[/red]", res.stdout.strip())


@panic_app.command("off")
def panic_off(
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    if is_offline():
        console.print(
            "[red]offline 模式下無法使用 panic（僅 runtime）。[/red]"
        )
        raise typer.Exit(2)
    if not dry_run and not yes:
        typer.confirm("要關閉 panic 模式嗎？", default=True, abort=True)
    if not dry_run:
        require_root("disable panic mode")
    try:
        res = run_firewall_cmd(["--panic-off"], check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]Panic 已關閉[/green]", res.stdout.strip())
