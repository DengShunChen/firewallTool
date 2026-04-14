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
    help="以 firewall-cmd（線上）或 firewall-offline-cmd（--offline）查詢／管理 firewalld。",
    rich_markup_mode="rich",
    epilog=(
        "線上模式：未加 --permanent 時變更套在 runtime；加 --permanent 寫入設定檔後，請用 "
        "`fwctl reload`（或 `firewall-cmd --reload`）載入 runtime。 "
        "使用 --offline 時改跑 firewall-offline-cmd（僅磁碟設定、無 D-Bus），"
        "會自動略過 `--permanent` 旗標，且無法使用 reload／panic。"
    ),
)


@app.callback()
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="顯示版本後結束。"),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="改用 firewall-offline-cmd（daemon 可未啟動；只改磁碟設定）。",
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
    """依 permanent 設定重載 firewalld runtime。"""
    maintenance.reload_action(dry_run=dry_run, yes=yes)


app.add_typer(status_cmd.status_app, name="status")
app.add_typer(zone_cmd.zone_app, name="zone")
app.add_typer(service_port.service_app, name="service")
app.add_typer(service_port.port_app, name="port")
app.add_typer(rule_cmd.rule_app, name="rule")
app.add_typer(ipset_direct.ipset_app, name="ipset")
app.add_typer(ipset_direct.direct_app, name="direct")
app.add_typer(maintenance.panic_app, name="panic")
