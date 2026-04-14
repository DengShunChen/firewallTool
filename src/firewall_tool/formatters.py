"""Rich formatters for CLI output."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


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
    table = Table(title=title)
    table.add_column(column_name, overflow="fold")
    for line in lines:
        s = line.strip()
        if s:
            table.add_row(s)
    console.print(table)


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
