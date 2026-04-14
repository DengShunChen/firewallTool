"""Rich formatters for CLI output."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from firewall_tool.runner import FirewallCmdError


def print_kv(console: Console, title: str, rows: Sequence[Tuple[str, str]]) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    for k, v in rows:
        table.add_row(k, v)
    console.print(Panel(table, title=title, expand=False))


def print_lines_table(
    console: Console,
    title: str,
    lines: Iterable[str],
    column_name: str = "entry",
) -> None:
    """
    將多行條目印在單欄表內；標題放在外層 Panel，避免窄終端下 Rich Table 內建
    title 隨表格寬度強制折行而難讀。
    """
    table = Table(show_header=True, header_style="bold")
    table.add_column(column_name, overflow="fold")
    for line in lines:
        s = line.strip()
        if s:
            table.add_row(s)
    console.print(Panel(table, title=title, expand=False))


def split_space_list(text: str) -> List[str]:
    return [p for p in text.split() if p]


def parse_active_zones(text: str) -> List[Tuple[str, str]]:
    """Parse `firewall-cmd --get-active-zones` into (zone, details) rows."""
    rows: List[Tuple[str, str]] = []
    current_zone: Optional[str] = None
    buf: List[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            if current_zone is not None:
                rows.append((current_zone, "\n".join(buf).strip()))
            current_zone = line.split()[0].rstrip(":")
            buf = []
        else:
            buf.append(line.strip())
    if current_zone is not None:
        rows.append((current_zone, "\n".join(buf).strip()))
    return rows


def polkit_hint(text: str) -> Optional[str]:
    """若錯誤來自 PolicyKit／權限，回傳簡短處置說明。"""
    t = text.lower()
    if (
        "authorization failed" in t
        or "polkit" in t
        or "superuser" in t
        or "not authorized" in t
    ):
        return (
            "此主機未授權目前使用者存取 firewalld（PolicyKit）：請以 [bold]root[/bold] 跑同一支程式。"
            "\n若直接打 [bold]sudo fwctl[/bold] 卻出現 [bold]command not found[/bold]，是因為 sudo 會縮小 PATH，"
            "找不到 venv 裡的 [bold]fwctl[/bold]；請改用：\n"
            "[bold]sudo \"$(command -v fwctl)\" status[/bold]（把 status 換成你的子命令）。"
            "\n或在圖形／[bold]ssh -X[/bold] 環境啟好 polkit agent 再試一般使用者執行。"
        )
    return None


def print_firewall_cmd_error(console: Console, exc: FirewallCmdError) -> None:
    """印出 firewall 後端錯誤；若為 Polkit 相關則多一行提示。"""
    console.print(f"[red]{exc}[/red]")
    hint = polkit_hint(f"{exc.stderr}\n{exc}")
    if hint:
        console.print(f"[yellow]{hint}[/yellow]")
