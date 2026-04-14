"""Rich rules."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel

from firewall_tool.formatters import print_firewall_cmd_error

from firewall_tool.runner import (
    FirewallCmdError,
    is_offline,
    require_root,
    run_firewall_cmd,
)

console = Console()
rule_app = typer.Typer(help="列出、新增或移除 rich rules。")

_RULE_PREVIEW_MAX = 220


def _zone_args(zone: Optional[str]) -> List[str]:
    return [f"--zone={zone}"] if zone else []


def _perm(permanent: bool) -> List[str]:
    return ["--permanent"] if permanent else []


def _rich_rule_preview_snippet(body: str, max_len: int = _RULE_PREVIEW_MAX) -> str:
    collapse = " ".join(body.split())
    if len(collapse) <= max_len:
        return collapse
    return collapse[: max_len - 1] + "…"


def _print_rule_preview(body: str) -> None:
    console.print("[dim]規則內容摘要（確認前預覽）：[/dim]")
    console.print(
        Panel(
            _rich_rule_preview_snippet(body),
            title="rich rule 預覽",
            expand=False,
        )
    )


@rule_app.command("list")
def rule_list(
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
) -> None:
    args: List[str] = ["--list-rich-rules", *_perm(permanent), *_zone_args(zone)]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    text = out.strip() or "（無）"
    console.print(Panel(text, title="Rich rules", expand=False))


@rule_app.command("add")
def rule_add(
    rule: Optional[str] = typer.Option(
        None,
        "--rule",
        "-r",
        help="Rich rule 字串（在 shell 請注意引號）。",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        help="從檔案讀取單一規則（一行或完整字串）。",
    ),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    if (rule is None) == (file is None):
        console.print("[red]請擇一提供：[bold]--rule[/bold] 或 [bold]--file[/bold]。[/red]")
        raise typer.Exit(2)
    if file is not None and not file.is_file():
        console.print(f"[red]不是有效檔案：{file}[/red]")
        raise typer.Exit(2)
    body = rule if rule is not None else file.read_text(encoding="utf-8").strip()
    if not body:
        console.print("[red]規則內容為空。[/red]")
        raise typer.Exit(2)
    _print_rule_preview(body)
    if not dry_run and not yes:
        z = zone or "（預設 zone）"
        scope = "permanent" if permanent else "runtime"
        typer.confirm(
            f"要新增此 rich rule 到 zone [bold]{z}[/bold]（[bold]{scope}[/bold]）？",
            default=False,
            abort=True,
        )
    if not dry_run:
        require_root("add rich rules")
    args: List[str] = [
        f"--add-rich-rule={body}",
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


@rule_app.command("remove")
def rule_remove(
    rule: Optional[str] = typer.Option(None, "--rule", "-r"),
    file: Optional[Path] = typer.Option(None, "--file", "-f"),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    if (rule is None) == (file is None):
        console.print("[red]請擇一提供：[bold]--rule[/bold] 或 [bold]--file[/bold]。[/red]")
        raise typer.Exit(2)
    if file is not None and not file.is_file():
        console.print(f"[red]不是有效檔案：{file}[/red]")
        raise typer.Exit(2)
    body = rule if rule is not None else file.read_text(encoding="utf-8").strip()
    if not body:
        console.print("[red]規則內容為空。[/red]")
        raise typer.Exit(2)
    _print_rule_preview(body)
    if not dry_run and not yes:
        z = zone or "（預設 zone）"
        scope = "permanent" if permanent else "runtime"
        typer.confirm(
            f"要從 zone [bold]{z}[/bold] 移除此 rich rule（[bold]{scope}[/bold]）？",
            default=False,
            abort=True,
        )
    if not dry_run:
        require_root("remove rich rules")
    args: List[str] = [
        f"--remove-rich-rule={body}",
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
