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

service_app = typer.Typer(help="Inspect or change allowed services.")
port_app = typer.Typer(help="Inspect or change allowed ports.")


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
    zone: Optional[str] = typer.Option(None, "--zone", "-z", help="Zone name."),
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="Show permanent configuration instead of runtime.",
    ),
) -> None:
    args: List[str] = ["--list-services", *_perm(permanent), *_zone_args(zone)]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    lines = [x for x in out.split() if x.strip()]
    print_lines_table(console, "Services", lines, column_name="service")


@service_app.command("add")
def service_add(
    name: str = typer.Argument(..., help="Service name, e.g. ssh."),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print firewall-cmd only."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    _confirm_mut(
        dry_run=dry_run,
        yes=yes,
        msg=f"Add service [bold]{name}[/bold] to zone {zone or '(default)'} "
        f"({'permanent' if permanent else 'runtime'})?",
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
        if not is_offline():
            console.print(
                "[dim]If --permanent, run `firewall-cmd --reload` to apply to runtime.[/dim]"
            )
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    if permanent and not is_offline():
        console.print("[dim]Remember: `fwctl reload` or firewall-cmd --reload[/dim]")


@service_app.command("remove")
def service_remove(
    name: str = typer.Argument(..., help="Service name."),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    _confirm_mut(
        dry_run=dry_run,
        yes=yes,
        msg=f"Remove service [bold]{name}[/bold] from zone {zone or '(default)'} "
        f"({'permanent' if permanent else 'runtime'})?",
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
    print_lines_table(console, "Ports", parts, column_name="port")


@port_app.command("add")
def port_add(
    spec: str = typer.Argument(
        ...,
        help="Port spec, e.g. 443/tcp or 1000-2000/udp.",
    ),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    _confirm_mut(
        dry_run=dry_run,
        yes=yes,
        msg=f"Add port [bold]{spec}[/bold] ({'permanent' if permanent else 'runtime'})?",
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
        console.print("[dim]Remember: reload if you expect runtime to match permanent.[/dim]")


@port_app.command("remove")
def port_remove(
    spec: str = typer.Argument(..., help="Port spec, e.g. 443/tcp."),
    zone: Optional[str] = typer.Option(None, "--zone", "-z"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    _confirm_mut(
        dry_run=dry_run,
        yes=yes,
        msg=f"Remove port [bold]{spec}[/bold] ({'permanent' if permanent else 'runtime'})?",
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
