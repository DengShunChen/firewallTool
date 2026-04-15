"""Export firewall snapshot JSON and static HTML visualization."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from firewall_tool.formatters import print_firewall_cmd_error
from firewall_tool.runner import FirewallCmdError
from firewall_tool.viz.html_report import generate_html_report, html_report_from_json_text
from firewall_tool.viz.snapshot import build_viz_snapshot, snapshot_to_json

console = Console()
viz_app = typer.Typer(help="匯出視覺化用 JSON 快照，或產生含 Mermaid 的 HTML 報告。")


@viz_app.command("export")
def viz_export(
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="寫入 JSON 檔；省略則印到 stdout。",
    ),
    include_raw: bool = typer.Option(
        False,
        "--include-raw",
        help="附上 --list-all-zones 原始文字（檔案較大）。",
    ),
) -> None:
    """收集 firewalld 狀態為 JSON（供儀表板或 `fwctl viz html --input` 使用）。"""
    try:
        snap = build_viz_snapshot(include_raw=include_raw)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    text = snapshot_to_json(snap)
    if output is not None:
        output.write_text(text, encoding="utf-8")
        console.print(f"已寫入 [bold]{output}[/bold]")
    else:
        console.print(text)


@viz_app.command("html")
def viz_html(
    input_path: Optional[Path] = typer.Option(
        None,
        "--input",
        "-i",
        help="使用既有 JSON（例如先前 `viz export`）；省略則即時查詢後產報告。",
    ),
    output: Path = typer.Option(
        Path("fwctl-viz-report.html"),
        "--output",
        "-o",
        help="HTML 輸出路徑。",
    ),
) -> None:
    """產生靜態 HTML（Mermaid 拓樸 + services／ports drift 表 + ipset／direct 摘要）。"""
    try:
        if input_path is not None:
            raw = input_path.read_text(encoding="utf-8")
            page = html_report_from_json_text(raw)
        else:
            snap = build_viz_snapshot(include_raw=False)
            page = generate_html_report(snap)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    except (OSError, UnicodeError, ValueError) as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from e
    output.write_text(page, encoding="utf-8")
    console.print(f"已寫入 [bold]{output}[/bold]")
