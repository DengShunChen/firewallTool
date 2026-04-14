"""Rich rules."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel

from firewall_tool.runner import (
    FirewallCmdError,
    require_root,
    run_firewall_cmd,
)

console = Console()
rule_app = typer.Typer(help="List, add, or remove rich rules.")


def _zone_args(zone: Optional[str]) -> List[str]:
    return [f"--zone={zone}"] if zone else []


def _perm(permanent: bool) -> List[str]:
    return ["--permanent"] if permanent else []


@rule_app.command("list")
def rule_list(
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
) -> None:
    args: List[str] = ["--list-rich-rules", *_perm(permanent), *_zone_args(zone)]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(e.code) from e
    text = out.strip() or "(none)"
    console.print(Panel(text, title="Rich rules", expand=False))


@rule_app.command("add")
def rule_add(
    rule: Optional[str] = typer.Option(
        None,
        "--rule",
        "-r",
        help="Rich rule string (quote carefully in shell).",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        help="Read rule text from file (single rule, one line or full string).",
    ),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    if (rule is None) == (file is None):
        console.print("[red]Provide exactly one of --rule or --file.[/red]")
        raise typer.Exit(2)
    if file is not None and not file.is_file():
        console.print(f"[red]Not a file: {file}[/red]")
        raise typer.Exit(2)
    body = rule if rule is not None else file.read_text(encoding="utf-8").strip()
    if not body:
        console.print("[red]Rule text is empty.[/red]")
        raise typer.Exit(2)
    if not dry_run and not yes:
        typer.confirm("Add this rich rule?", default=False, abort=True)
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
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())


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
        console.print("[red]Provide exactly one of --rule or --file.[/red]")
        raise typer.Exit(2)
    if file is not None and not file.is_file():
        console.print(f"[red]Not a file: {file}[/red]")
        raise typer.Exit(2)
    body = rule if rule is not None else file.read_text(encoding="utf-8").strip()
    if not body:
        console.print("[red]Rule text is empty.[/red]")
        raise typer.Exit(2)
    if not dry_run and not yes:
        typer.confirm("Remove this rich rule?", default=False, abort=True)
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
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())
