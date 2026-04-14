"""CLI entrypoint for fwctl."""

from __future__ import annotations

import typer

from firewall_tool import __version__
from firewall_tool.commands import maintenance, rule_cmd, service_port, status_cmd, zone_cmd

app = typer.Typer(
    name="fwctl",
    no_args_is_help=True,
    help="Query and manage firewalld via firewall-cmd.",
    rich_markup_mode="rich",
)


@app.callback()
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Print version and exit."),
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit(0)


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
app.add_typer(maintenance.panic_app, name="panic")
