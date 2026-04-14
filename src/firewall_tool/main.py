"""CLI entrypoint for fwctl."""

from __future__ import annotations

import typer

from firewall_tool import __version__
from firewall_tool.commands import (
    ipset_direct,
    maintenance,
    rule_cmd,
    service_port,
    status_cmd,
    zone_cmd,
)
from firewall_tool.runner import set_use_offline

app = typer.Typer(
    name="fwctl",
    no_args_is_help=True,
    help="Query and manage firewalld via firewall-cmd (or firewall-offline-cmd with --offline).",
    rich_markup_mode="rich",
    epilog=(
        "Runtime vs --permanent (online only): without --permanent, changes apply to the "
        "running firewall only. With --permanent, changes are written to disk; use "
        "`fwctl reload` (or firewall-cmd --reload) to load them into runtime. "
        "With --offline, fwctl uses firewall-offline-cmd (on-disk config; no D-Bus); "
        "`--permanent` is stripped automatically, and reload/panic are unavailable."
    ),
)


@app.callback()
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Print version and exit."),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Use firewall-offline-cmd (firewalld may be stopped; edits on-disk only).",
    ),
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit(0)
    set_use_offline(offline)


@app.command("reload")
def reload_cmd(
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Reload runtime configuration from permanent rules."""
    maintenance.reload_action(dry_run=dry_run, yes=yes)


app.add_typer(status_cmd.status_app, name="status")
app.add_typer(zone_cmd.zone_app, name="zone")
app.add_typer(service_port.service_app, name="service")
app.add_typer(service_port.port_app, name="port")
app.add_typer(rule_cmd.rule_app, name="rule")
app.add_typer(ipset_direct.ipset_app, name="ipset")
app.add_typer(ipset_direct.direct_app, name="direct")
app.add_typer(maintenance.panic_app, name="panic")
