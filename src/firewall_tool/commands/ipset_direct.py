"""ipset and --direct rule inspection."""

from __future__ import annotations

from typing import List

import typer
from rich.console import Console
from rich.panel import Panel

from firewall_tool.formatters import print_firewall_cmd_error, print_lines_table, split_space_list
from firewall_tool.runner import FirewallCmdError, run_firewall_cmd

console = Console()
ipset_app = typer.Typer(help="List or inspect firewalld ipsets.")
direct_app = typer.Typer(help="Inspect firewalld --direct (iptables/nft passthrough) rules.")


def _perm(permanent: bool) -> List[str]:
    return ["--permanent"] if permanent else []


@ipset_app.command("list")
def ipset_list(
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="Use permanent configuration instead of runtime.",
    ),
) -> None:
    args: List[str] = [*_perm(permanent), "--get-ipsets"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    names = split_space_list(out)
    print_lines_table(console, "IPSets", names, column_name="ipset")


@ipset_app.command("show")
def ipset_show(
    name: str = typer.Argument(..., metavar="NAME", help="ipset name."),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    entries: bool = typer.Option(
        True,
        "--entries/--no-entries",
        help="Also run --get-entries for this ipset (default on).",
    ),
) -> None:
    args_info: List[str] = [*_perm(permanent), f"--info-ipset={name}"]
    try:
        info = run_firewall_cmd(args_info, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    console.print(Panel(info.strip(), title=f"ipset: {name}", expand=False))

    if not entries:
        return

    args_ent: List[str] = [*_perm(permanent), f"--ipset={name}", "--get-entries"]
    try:
        ent = run_firewall_cmd(args_ent, check=True).stdout
    except FirewallCmdError as e:
        console.print(f"[dim]entries: {e}[/dim]")
        return
    text = ent.strip() or "(no entries)"
    console.print(Panel(text, title=f"ipset entries: {name}", expand=False))


@direct_app.command("rules")
def direct_rules(
    permanent: bool = typer.Option(False, "--permanent", "-p"),
) -> None:
    """Show all direct rules (`firewall-cmd --direct --get-all-rules`)."""
    args: List[str] = [*_perm(permanent), "--direct", "--get-all-rules"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    text = out.strip() or "(none)"
    console.print(Panel(text, title="direct rules (--get-all-rules)", expand=False))


@direct_app.command("chains")
def direct_chains(
    permanent: bool = typer.Option(False, "--permanent", "-p"),
) -> None:
    args: List[str] = [*_perm(permanent), "--direct", "--get-all-chains"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    text = out.strip() or "(none)"
    console.print(Panel(text, title="direct chains", expand=False))


@direct_app.command("passthroughs")
def direct_passthroughs(
    permanent: bool = typer.Option(False, "--permanent", "-p"),
) -> None:
    args: List[str] = [*_perm(permanent), "--direct", "--get-all-passthroughs"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    text = out.strip() or "(none)"
    console.print(Panel(text, title="direct passthroughs", expand=False))
