"""ipset and --direct rule inspection + guarded mutations."""

from __future__ import annotations

import ipaddress
import re
import shlex
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import typer
from rich.console import Console
from rich.panel import Panel

from firewall_tool.formatters import print_firewall_cmd_error, print_lines_table, split_space_list
from firewall_tool.runner import FirewallCmdError, require_root, run_firewall_cmd

console = Console()
ipset_app = typer.Typer(help="列出、檢視或變更 firewalld ipset。")
direct_app = typer.Typer(help="檢視或變更 firewalld --direct 規則（含防呆）。")

_COMMON_CHAINS = frozenset({"INPUT", "OUTPUT", "FORWARD"})


def _perm(permanent: bool) -> List[str]:
    return ["--permanent"] if permanent else []


def _ipset_name_ssh_caution(ipset_name: str) -> bool:
    """True if mutating this ipset is likely to affect SSH allow-lists."""
    return "ssh" in ipset_name.lower()


def _query_ipset_entry(name: str, entry: str, *, permanent: bool) -> bool:
    args: List[str] = [
        *_perm(permanent),
        f"--ipset={name}",
        f"--query-entry={entry}",
    ]
    res = run_firewall_cmd(args, check=False, dry_run=False)
    return res.code == 0


def _get_ipset_entries_lines(name: str, *, permanent: bool) -> str:
    """Raw stdout from --get-entries (for display / line splitting)."""
    args: List[str] = [*_perm(permanent), f"--ipset={name}", "--get-entries"]
    res = run_firewall_cmd(args, check=True)
    return res.stdout


def _looks_like_ipset_address_token(tok: str) -> bool:
    """保守判斷是否像 hash:net / hash:ip 的單一條目（避免把任意字串當成多筆）。"""
    t = tok.strip()
    if not t or len(t) > 128:
        return False
    try:
        if "/" in t:
            ipaddress.ip_network(t, strict=False)
        else:
            ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def _parse_ipset_entries_stdout(stdout: str) -> List[str]:
    """
    解析 `firewall-cmd --get-entries` 輸出：常見為一行一條目；若僅單行且以空白分隔多個
    IP／CIDR，則拆成多筆（供精靈選號）。其它型別若無法全部辨識為位址，維持整行一筆。
    """
    text = stdout.strip()
    if not text:
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) != 1:
        return lines
    sole = lines[0]
    if " " not in sole:
        return lines
    parts = sole.split()
    if len(parts) < 2:
        return lines
    if not all(_looks_like_ipset_address_token(p) for p in parts):
        return lines
    return parts


def _ipset_add_entry_core(
    name: str,
    entry: str,
    *,
    permanent: bool,
    dry_run: bool,
    yes: bool,
    verify_absent: bool,
    skip_confirm: bool = False,
) -> None:
    ent = entry.strip()
    if not ent:
        raise typer.BadParameter("entry 不可為空。")
    if verify_absent and not dry_run:
        if _query_ipset_entry(name, ent, permanent=permanent):
            console.print("[red]拒絕：[/red] entry 已存在（--verify-absent）。")
            raise typer.Exit(2)
    if not skip_confirm:
        _confirm(
            dry_run=dry_run,
            yes=yes,
            message=f"將條目 {ent!r} 加入 ipset {name!r}（permanent={permanent}）？",
        )
    if not dry_run:
        require_root("modify ipsets")
    args: List[str] = [*_perm(permanent), f"--ipset={name}", f"--add-entry={ent}"]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    if permanent:
        console.print("[dim]若需 runtime 同步：[/dim] [bold]fwctl reload[/bold]")


def _ipset_remove_entry_core(
    name: str,
    entry: str,
    *,
    permanent: bool,
    dry_run: bool,
    yes: bool,
    verify_present: bool,
    accept_ssh_ipset_risk: bool,
    skip_confirm: bool = False,
) -> None:
    ent = entry.strip()
    if not ent:
        raise typer.BadParameter("entry 不可為空。")
    if _ipset_name_ssh_caution(name) and not accept_ssh_ipset_risk:
        console.print(
            "[red]拒絕：[/red] ipset 名稱疑似與 SSH 白名單有關；"
            "若確定要刪條目，請加 [bold]--accept-ssh-ipset-risk[/bold]。"
        )
        raise typer.Exit(2)
    if verify_present and not dry_run:
        if not _query_ipset_entry(name, ent, permanent=permanent):
            console.print(
                "[red]拒絕：[/red] entry 不存在或 query 失敗（請確認名稱、--permanent 與字串完全一致）。"
            )
            raise typer.Exit(2)
    if not skip_confirm:
        _confirm(
            dry_run=dry_run,
            yes=yes,
            message=f"從 ipset {name!r} 移除條目 {ent!r}（permanent={permanent}）？",
        )
    if not dry_run:
        require_root("modify ipsets")
    args: List[str] = [*_perm(permanent), f"--ipset={name}", f"--remove-entry={ent}"]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    if permanent:
        console.print("[dim]若需 runtime 同步：[/dim] [bold]fwctl reload[/bold]")


def _ipset_exists_anywhere(name: str) -> bool:
    """True if runtime 或 permanent 任一可查到此 ipset。"""
    for use_perm in (False, True):
        argv: List[str] = [*_perm(use_perm), f"--info-ipset={name}"]
        if run_firewall_cmd(argv, check=False, dry_run=False).code == 0:
            return True
    return False


def _print_ipsets_table_for_wizard(*, permanent: bool, subtitle: str) -> None:
    """列出 `firewall-cmd --get-ipsets`（供精靈選名用）。"""
    args: List[str] = [*_perm(permanent), "--get-ipsets"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        console.print(f"[yellow]無法取得 {subtitle} ipset 清單：[/yellow]", str(e))
        return
    names = split_space_list(out)
    print_lines_table(console, f"現有 ipset（{subtitle}）", names, column_name="ipset")


def _wizard_show_existing_ipset_names() -> None:
    """精靈用：印出 runtime 與 permanent 的 ipset 名稱表。"""
    console.print(
        "[dim]以下與 [bold]fwctl ipset list[/bold] / [bold]fwctl ipset list --permanent[/bold] 相同來源；"
        "請從表內擇一，或手動輸入與 firewalld 完全一致的名稱。[/dim]"
    )
    _print_ipsets_table_for_wizard(permanent=False, subtitle="runtime")
    _print_ipsets_table_for_wizard(permanent=True, subtitle="permanent")


def _ipset_new_core(
    name: str,
    ipset_type: str,
    options: Sequence[str],
    *,
    dry_run: bool,
    yes: bool,
    skip_confirm: bool = False,
) -> None:
    """
    建立空 ipset（`--new-ipset` + `--type`；線上模式 firewall-cmd 標為 [P]，故一律帶 `--permanent`）。
    """
    nm = name.strip()
    if not nm:
        raise typer.BadParameter("ipset 名稱不可為空。")
    t = ipset_type.strip()
    if not t:
        raise typer.BadParameter("type 不可為空。")
    if not skip_confirm:
        _confirm(
            dry_run=dry_run,
            yes=yes,
            message=f"建立新 ipset {nm!r}，type={t!r}？",
        )
    if not dry_run:
        require_root("create ipsets")
    args: List[str] = [*_perm(True), f"--new-ipset={nm}", f"--type={t}"]
    for raw in options:
        o = raw.strip()
        if o:
            args.append(f"--option={o}")
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    console.print("[dim]新 ipset 寫入 permanent；若需 runtime 同步：[/dim] [bold]fwctl reload[/bold]")


def _rule_body(*, rule: Optional[str], rule_file: Optional[Path]) -> str:
    if (rule is None) == (rule_file is None):
        raise typer.BadParameter("請擇一提供 --rule 或 --rule-file。")
    if rule_file is not None:
        if not rule_file.is_file():
            raise typer.BadParameter(f"不是檔案：{rule_file}")
        return rule_file.read_text(encoding="utf-8").strip()
    assert rule is not None
    return rule.strip()


def _rule_tokens(rule_text: str) -> List[str]:
    if not rule_text:
        raise typer.BadParameter("規則內容為空。")
    return shlex.split(rule_text, posix=True)


def _tokens_have_drop_or_reject(tokens: Sequence[str]) -> bool:
    joined = " ".join(tokens).upper()
    return bool(re.search(r"-J\s+(DROP|REJECT)\b", joined))


def _rule_text_may_affect_ssh(rule_text: str) -> bool:
    low = rule_text.lower()
    if "ssh" in low:
        return True
    if re.search(r"--dports?\s+[^-\s]*22\b", low):
        return True
    if re.search(r"--sports?\s+[^-\s]*22\b", low):
        return True
    if "dport" in low and re.search(r"(^|[\s,])22([\s,/]|$)", low):
        return True
    return False


def _validate_direct_target(
    family: str,
    table: str,
    chain: str,
    *,
    allow_unusual_chain: bool,
) -> Tuple[str, str, str]:
    fam = family.lower()
    if fam not in ("ipv4", "ipv6", "eb"):
        raise typer.BadParameter("family 必須為：ipv4、ipv6、eb 之一。")
    if not allow_unusual_chain:
        if table != "filter":
            raise typer.BadParameter(
                f"table 為 {table!r}（非 filter）。若為刻意設定，請加 --allow-unusual-chain。"
            )
        if chain not in _COMMON_CHAINS:
            raise typer.BadParameter(
                f"chain {chain!r} 不在 {_COMMON_CHAINS} 內。"
                "若要 PREROUTING／nat／raw 等，請加 --allow-unusual-chain。"
            )
    return fam, table, chain


def _direct_rule_argv_tail(
    family: str,
    table: str,
    chain: str,
    priority: int,
    tokens: Sequence[str],
) -> List[str]:
    return [family, table, chain, str(int(priority)), *list(tokens)]


def _confirm(*, dry_run: bool, yes: bool, message: str) -> None:
    if dry_run or yes:
        return
    typer.confirm(message, default=False, abort=True)


def _query_direct_rule(
    family: str,
    table: str,
    chain: str,
    priority: int,
    tokens: Sequence[str],
    *,
    permanent: bool,
) -> bool:
    args: List[str] = [
        *_perm(permanent),
        "--direct",
        "--query-rule",
        *_direct_rule_argv_tail(family, table, chain, priority, tokens),
    ]
    res = run_firewall_cmd(args, check=False, dry_run=False)
    return res.code == 0


def _parse_direct_rules_line(line: str) -> Tuple[str, str, str, int, List[str]]:
    """
    Parse one line from `fwctl direct rules` / `firewall-cmd --get-all-rules`.

    Format: <family> <table> <chain> <priority> <rule tokens...>
    """
    parts = shlex.split(line.strip())
    if len(parts) < 5:
        raise typer.BadParameter("至少需要：family table chain priority 以及一段 rule。")
    fam, tbl, ch = parts[0], parts[1], parts[2]
    try:
        pri = int(parts[3])
    except ValueError as e:
        raise typer.BadParameter(f"priority 必須是整數：{parts[3]!r}") from e
    return fam, tbl, ch, pri, parts[4:]


def _direct_add_core(
    fam: str,
    tbl: str,
    ch: str,
    priority: int,
    tokens: List[str],
    *,
    permanent: bool,
    dry_run: bool,
    yes: bool,
    accept_drop_risk: bool,
    verify_absent: bool,
    skip_confirm: bool = False,
) -> None:
    if verify_absent and not dry_run:
        if _query_direct_rule(fam, tbl, ch, priority, tokens, permanent=permanent):
            console.print("[red]拒絕：[/red] 已存在相同規則（--verify-absent）。")
            raise typer.Exit(2)

    if _tokens_have_drop_or_reject(tokens):
        if not accept_drop_risk:
            console.print(
                "[red]拒絕：[/red] 規則含 DROP／REJECT。確認仍有管理連線後，請加 "
                "[bold]--accept-drop-risk[/bold] 再執行。"
            )
            raise typer.Exit(2)
        if not skip_confirm:
            _confirm(
                dry_run=dry_run,
                yes=yes,
                message="要新增含 DROP／REJECT 的 direct 規則（可能鎖死 SSH 等）？是否繼續？",
            )
    elif not skip_confirm:
        _confirm(
            dry_run=dry_run,
            yes=yes,
            message=f"要新增 direct 規則 {fam} {tbl} {ch} priority {priority}？",
        )

    if not dry_run:
        require_root("add direct rules")
    argv_tail = _direct_rule_argv_tail(fam, tbl, ch, priority, tokens)
    args: List[str] = [*_perm(permanent), "--direct", "--add-rule", *argv_tail]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]已新增。[/green]", res.stdout.strip())
    if permanent and not dry_run:
        console.print("[dim]若需 runtime 與 permanent 一致：[/dim] [bold]fwctl reload[/bold]")


def _direct_remove_core(
    fam: str,
    tbl: str,
    ch: str,
    priority: int,
    tokens: List[str],
    *,
    body_for_ssh_check: str,
    permanent: bool,
    dry_run: bool,
    yes: bool,
    verify_present: bool,
    accept_ssh_rule_risk: bool,
    skip_confirm: bool = False,
) -> None:
    if _rule_text_may_affect_ssh(body_for_ssh_check):
        if not accept_ssh_rule_risk:
            console.print(
                "[red]拒絕：[/red] 規則文字可能影響 SSH。若確定要刪，請加 "
                "[bold]--accept-ssh-rule-risk[/bold]。"
            )
            raise typer.Exit(2)

    if verify_present and not dry_run:
        if not _query_direct_rule(fam, tbl, ch, priority, tokens, permanent=permanent):
            console.print(
                "[red]拒絕：[/red] 查無此規則（請核對 family／table／chain／priority／內容，"
                "可從 `fwctl direct rules` 複製）。"
            )
            raise typer.Exit(2)

    if not skip_confirm:
        _confirm(
            dry_run=dry_run,
            yes=yes,
            message=f"要移除 direct 規則 {fam} {tbl} {ch} priority {priority}？",
        )

    if not dry_run:
        require_root("remove direct rules")
    argv_tail = _direct_rule_argv_tail(fam, tbl, ch, priority, tokens)
    args: List[str] = [*_perm(permanent), "--direct", "--remove-rule", *argv_tail]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]已移除。[/green]", res.stdout.strip())
    if permanent and not dry_run:
        console.print("[dim]若需 runtime 與 permanent 一致：[/dim] [bold]fwctl reload[/bold]")


@ipset_app.command("list")
def ipset_list(
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="讀取 permanent 設定（短選項請用 -p，勿用 --p）。",
    ),
) -> None:
    args: List[str] = [*_perm(permanent), "--get-ipsets"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    names = split_space_list(out)
    title = "ipsets（permanent）" if permanent else "ipsets（runtime）"
    print_lines_table(console, title, names, column_name="ipset")


@ipset_app.command("show")
def ipset_show(
    name: str = typer.Argument(..., metavar="NAME", help="ipset 名稱。"),
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="讀取 permanent（短選項請用 -p）。",
    ),
    entries: bool = typer.Option(
        True,
        "--entries/--no-entries",
        help="一併執行 --get-entries（預設開；多筆 IP 會盡量分行顯示）。",
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
        console.print(f"[dim]條目：{e}[/dim]")
        return
    items = _parse_ipset_entries_stdout(ent)
    text = "\n".join(items) if items else "（無條目）"
    console.print(Panel(text, title=f"ipset entries: {name}", expand=False))


@ipset_app.command("add-entry")
def ipset_add_entry(
    name: str = typer.Argument(..., metavar="NAME", help="ipset 名稱。"),
    entry: str = typer.Argument(..., help="條目，例如 10.0.0.1 或 192.168.0.0/24（依 ipset type）。"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    verify_absent: bool = typer.Option(
        False,
        "--verify-absent",
        help="若 entry 已存在（query-entry）則拒絕。",
    ),
) -> None:
    """新增 ipset 條目（`--ipset=NAME --add-entry=…`）。"""
    _ipset_add_entry_core(
        name,
        entry,
        permanent=permanent,
        dry_run=dry_run,
        yes=yes,
        verify_absent=verify_absent,
        skip_confirm=False,
    )


@ipset_app.command("remove-entry")
def ipset_remove_entry(
    name: str = typer.Argument(..., metavar="NAME", help="ipset 名稱。"),
    entry: str = typer.Argument(..., help="要移除的條目（須與 add 時字串一致）。"),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    verify_present: bool = typer.Option(
        True,
        "--verify-present/--no-verify-present",
        help="移除前先 query-entry（建議開）。",
    ),
    accept_ssh_ipset_risk: bool = typer.Option(
        False,
        "--accept-ssh-ipset-risk",
        help="當 ipset 名稱含 ssh（不分大小寫）時必須加上，避免誤刪 SSH 白名單。",
    ),
) -> None:
    """移除 ipset 條目（`--ipset=NAME --remove-entry=…`）。"""
    _ipset_remove_entry_core(
        name,
        entry,
        permanent=permanent,
        dry_run=dry_run,
        yes=yes,
        verify_present=verify_present,
        accept_ssh_ipset_risk=accept_ssh_ipset_risk,
        skip_confirm=False,
    )


@ipset_app.command("delete")
def ipset_delete_whole(
    name: str = typer.Argument(..., metavar="NAME", help="要刪除的整個 ipset 名稱（僅寫入 permanent，[P]）。"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    typed_delete_token: str = typer.Option(
        "",
        "--typed-delete-token",
        help="非 dry-run 時必填，值必須為大寫 DELETE-IPSET。",
    ),
    accept_ssh_ipset_risk: bool = typer.Option(
        False,
        "--accept-ssh-ipset-risk",
        help="當 ipset 名稱含 ssh（不分大小寫）時必傳。",
    ),
) -> None:
    """刪除整個 ipset（`firewall-cmd --delete-ipset`）；高風險，僅 permanent。"""
    if _ipset_name_ssh_caution(name) and not accept_ssh_ipset_risk:
        console.print(
            "[red]拒絕：[/red] ipset 名稱疑似與 SSH 白名單有關；請加 [bold]--accept-ssh-ipset-risk[/bold]。"
        )
        raise typer.Exit(2)
    if not dry_run and typed_delete_token.strip() != "DELETE-IPSET":
        console.print(
            "[red]拒絕：[/red] 刪除整個 ipset 風險極高；非 dry-run 時請傳 "
            "[bold]--typed-delete-token=DELETE-IPSET[/bold]（全大寫）。"
        )
        raise typer.Exit(2)
    if not _ipset_exists_anywhere(name):
        console.print("[red]找不到此 ipset（runtime／permanent 皆無 --info-ipset）。[/red]")
        raise typer.Exit(2)
    _confirm(
        dry_run=dry_run,
        yes=yes,
        message=f"永久刪除整個 ipset {name!r}（含所有條目）？此動作無法由 fwctl 復原。",
    )
    if not dry_run:
        require_root("delete ipsets")
    args: List[str] = [*_perm(True), f"--delete-ipset={name}"]
    try:
        res = run_firewall_cmd(args, check=True, dry_run=dry_run)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    if dry_run:
        console.print("[yellow]dry-run:[/yellow]", " ".join(res.argv))
        return
    console.print("[green]OK[/green]", res.stdout.strip())
    console.print("[dim]已從 permanent 設定移除；若需 runtime 同步：[/dim] [bold]fwctl reload[/bold]")


def _wizard_ipset_add_entry_to_existing(*, yes_wizard: bool) -> None:
    """精靈分支：對已存在的 ipset 加入條目。"""
    _wizard_show_existing_ipset_names()
    name = typer.prompt("現有 ipset 名稱").strip()
    if not name:
        console.print("[red]名稱不可為空。[/red]")
        raise typer.Exit(2)
    if not _ipset_exists_anywhere(name):
        console.print(
            "[red]找不到此 ipset[/red]（runtime／permanent 的 --info-ipset 皆失敗）。"
            "請確認名稱，或改選「建立新 ipset」。"
        )
        raise typer.Exit(2)
    entry = typer.prompt(
        "要加入的條目（須符合該 ipset 的 type，例如 10.0.0.1 或 192.168.0.0/24）"
    ).strip()
    if not entry:
        console.print("[red]條目不可為空。[/red]")
        raise typer.Exit(2)
    permanent = typer.confirm("寫入 permanent 設定？", default=False)
    verify_absent = typer.confirm("新增前檢查條目是否尚不存在（query-entry，建議開）？", default=True)

    console.print(
        Panel(
            f"[bold]摘要[/bold]\n"
            f"動作=加入條目  ipset={name!r} entry={entry!r}\n"
            f"permanent={permanent} verify_absent={verify_absent}",
            title="即將套用",
            expand=False,
        )
    )
    _ipset_add_entry_core(
        name,
        entry,
        permanent=permanent,
        dry_run=True,
        yes=True,
        verify_absent=False,
        skip_confirm=True,
    )

    if yes_wizard:
        run_for_real = True
    else:
        run_for_real = typer.confirm("以上為 dry-run。要實際執行嗎？（需要 root）", default=False)
    if not run_for_real:
        console.print("[dim]已取消，未寫入。[/dim]")
        raise typer.Exit(0)

    _ipset_add_entry_core(
        name,
        entry,
        permanent=permanent,
        dry_run=False,
        yes=True,
        verify_absent=verify_absent,
        skip_confirm=True,
    )


def _wizard_ipset_create_new_then_optional_entry(*, yes_wizard: bool) -> None:
    """精靈分支：建立新 ipset（--new-ipset），可選建立後立刻加第一筆條目。"""
    console.print(
        "[dim]firewall-cmd 的 --new-ipset 為 [P]；此分支一律使用 [bold]--permanent[/bold]。"
        "完成後建議 [bold]fwctl reload[/bold] 讓 runtime 同步。[/dim]"
    )
    if typer.confirm("是否顯示本機支援的 ipset type（--get-ipset-types）？", default=False):
        try:
            types_out = run_firewall_cmd(["--get-ipset-types"], check=True).stdout
            console.print(Panel(types_out.strip(), title="支援的 type", expand=False))
        except FirewallCmdError as e:
            print_firewall_cmd_error(console, e)

    name = typer.prompt("新 ipset 名稱").strip()
    if not name:
        console.print("[red]名稱不可為空。[/red]")
        raise typer.Exit(2)
    if _ipset_exists_anywhere(name):
        console.print(
            "[red]已存在同名 ipset。[/red]請換名稱，或改選「在現有 ipset 加入條目」。"
        )
        raise typer.Exit(2)

    ipset_type = typer.prompt("ipset type", default="hash:net").strip()
    console.print(
        "[dim]選填：每行一個 [bold]option[/bold]（會變成 `--option=…`，例 maxelem=65536），"
        "僅 Enter 結束。[/dim]"
    )
    opt_lines: List[str] = []
    while True:
        line = typer.prompt("  option（空行結束）", default="").strip()
        if not line:
            break
        opt_lines.append(line)

    console.print(
        Panel(
            f"[bold]摘要[/bold]\n"
            f"動作=建立新 ipset  name={name!r} type={ipset_type!r}\n"
            f"options={opt_lines!r}",
            title="即將套用",
            expand=False,
        )
    )
    _ipset_new_core(
        name,
        ipset_type,
        opt_lines,
        dry_run=True,
        yes=True,
        skip_confirm=True,
    )

    if yes_wizard:
        run_new = True
    else:
        run_new = typer.confirm("以上為 dry-run。要實際建立 ipset 嗎？（需要 root）", default=False)
    if not run_new:
        console.print("[dim]已取消，未建立。[/dim]")
        raise typer.Exit(0)

    _ipset_new_core(
        name,
        ipset_type,
        opt_lines,
        dry_run=False,
        yes=True,
        skip_confirm=True,
    )

    if not typer.confirm("要立即加入第一筆條目嗎？", default=False):
        return

    entry = typer.prompt("第一筆條目").strip()
    if not entry:
        console.print("[yellow]略過：條目為空。[/yellow]")
        return
    verify_absent = typer.confirm("新增前檢查條目是否尚不存在（query-entry，建議開）？", default=True)
    console.print(
        Panel(
            f"[bold]摘要[/bold]\n"
            f"動作=加入條目  ipset={name!r} entry={entry!r}\n"
            f"permanent=True verify_absent={verify_absent}\n"
            f"[dim]（新建之 ipset 在 permanent，條目一併寫入 permanent）[/dim]",
            title="即將套用",
            expand=False,
        )
    )
    _ipset_add_entry_core(
        name,
        entry,
        permanent=True,
        dry_run=True,
        yes=True,
        verify_absent=False,
        skip_confirm=True,
    )
    if yes_wizard:
        run_add = True
    else:
        run_add = typer.confirm("以上為 dry-run。要實際加入條目嗎？（需要 root）", default=False)
    if not run_add:
        console.print("[dim]已取消加入條目。[/dim]")
        return
    _ipset_add_entry_core(
        name,
        entry,
        permanent=True,
        dry_run=False,
        yes=True,
        verify_absent=verify_absent,
        skip_confirm=True,
    )


@ipset_app.command("wizard-add")
def ipset_wizard_add(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="略過最後「真的要執行」的確認。",
    ),
) -> None:
    """互動式引導：建立新 ipset，或對現有 ipset 加入條目（皆先 dry-run）。"""
    console.print(
        Panel(
            "第一步請選擇目的：\n"
            "  [bold]1[/bold] — 建立[bold]新的空[/bold] ipset（[cyan]--new-ipset[/cyan] + [cyan]--type[/cyan]，一律寫入 permanent）\n"
            "  [bold]2[/bold] — 在[bold]現有[/bold] ipset [bold]加入條目[/bold]（[cyan]--add-entry[/cyan]；可選 runtime 或 permanent）\n"
            "結束前會先顯示 [bold]dry-run[/bold] 指令。可先 [bold]fwctl ipset list[/bold] / [bold]ipset show NAME[/bold] 查現況。",
            title="ipset wizard-add",
            expand=False,
        )
    )
    goal = typer.prompt("請輸入 1 或 2", default="2").strip()
    if goal == "1":
        _wizard_ipset_create_new_then_optional_entry(yes_wizard=yes)
    elif goal == "2":
        _wizard_ipset_add_entry_to_existing(yes_wizard=yes)
    else:
        console.print("[red]請輸入 1 或 2。[/red]")
        raise typer.Exit(2)


def _wizard_ipset_pick_remove_entry(*, name: str, permanent: bool) -> str:
    """
    以 --get-entries 取得條目並顯示編號清單；可選號或改手動輸入。
    """
    try:
        raw = _get_ipset_entries_lines(name, permanent=permanent)
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    items = _parse_ipset_entries_stdout(raw)
    if items:
        console.print(
            Panel(
                "\n".join(f"  {i + 1}. {v}" for i, v in enumerate(items)),
                title=f"現有條目（{name}）",
                expand=False,
            )
        )
        pick = typer.prompt(
            "要刪除的條目編號（1–n），或輸入 0 改為手動輸入完整字串",
            default="1",
        ).strip()
        try:
            idx = int(pick, 10)
        except ValueError:
            console.print("[red]請輸入整數編號。[/red]")
            raise typer.Exit(2) from None
        if idx == 0:
            return typer.prompt("條目字串（須與列表或 firewall-cmd 顯示一致）").strip()
        if 1 <= idx <= len(items):
            return items[idx - 1]
        console.print("[red]編號超出範圍。[/red]")
        raise typer.Exit(2)
    console.print("[yellow]目前查無條目或為空；請手動輸入要刪除的條目字串。[/yellow]")
    return typer.prompt("條目字串").strip()


@ipset_app.command("wizard-remove")
def ipset_wizard_remove(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="略過最後「真的要執行」的確認（仍須通過 SSH 相關 ipset 打字關卡）。",
    ),
) -> None:
    """互動式引導刪除 ipset 條目（可從現有條目清單選號）。"""
    console.print(
        Panel(
            "先顯示 [bold]runtime／permanent[/bold] 的 ipset 名稱表（與 [bold]ipset wizard-add[/bold] 選 2 相同）。\n"
            "輸入 ipset 名稱後，程式會以 [bold]--get-entries[/bold] 列出目前條目，再選編號或改手動輸入（字串須與 [bold]ipset show[/bold] 一致）。\n"
            "若 ipset 名稱含 [bold]ssh[/bold]（不分大小寫），必須輸入大寫 [bold]SSH-IPSET-RISK[/bold]。",
            title="ipset wizard-remove",
            expand=False,
        )
    )
    permanent = typer.confirm("針對 permanent 設定？", default=False)

    _wizard_show_existing_ipset_names()

    name = ""
    entry = ""

    name = typer.prompt("ipset 名稱").strip()
    if not name:
        console.print("[red]名稱不可為空。[/red]")
        raise typer.Exit(2)
    entry = _wizard_ipset_pick_remove_entry(name=name, permanent=permanent)

    if not name or not entry:
        console.print("[red]名稱與條目皆不可為空。[/red]")
        raise typer.Exit(2)

    verify_present = typer.confirm("刪除前先 query-entry 確認存在？（強烈建議）", default=True)

    accept_ssh_ipset_risk = False
    if _ipset_name_ssh_caution(name):
        console.print("[yellow]偵測到 ipset 名稱可能與 SSH 白名單有關。[/yellow]")
        token = typer.prompt("若仍要刪除，請輸入大寫 SSH-IPSET-RISK", default="").strip()
        if token != "SSH-IPSET-RISK":
            console.print("[red]已取消。[/red]")
            raise typer.Exit(2)
        accept_ssh_ipset_risk = True

    console.print(
        Panel(
            f"[bold]摘要[/bold]\n"
            f"ipset={name!r} entry={entry!r}\n"
            f"permanent={permanent} verify_present={verify_present}",
            title="即將套用",
            expand=False,
        )
    )
    _ipset_remove_entry_core(
        name,
        entry,
        permanent=permanent,
        dry_run=True,
        yes=True,
        verify_present=False,
        accept_ssh_ipset_risk=accept_ssh_ipset_risk,
        skip_confirm=True,
    )

    if yes:
        run_for_real = True
    else:
        run_for_real = typer.confirm("以上為 dry-run。要實際刪除嗎？（需要 root）", default=False)
    if not run_for_real:
        console.print("[dim]已取消，未變更。[/dim]")
        raise typer.Exit(0)

    _ipset_remove_entry_core(
        name,
        entry,
        permanent=permanent,
        dry_run=False,
        yes=True,
        verify_present=verify_present,
        accept_ssh_ipset_risk=accept_ssh_ipset_risk,
        skip_confirm=True,
    )


@direct_app.command("rules")
def direct_rules(
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="讀取 permanent；短選項為 -p（勿寫成 --p）。",
    ),
) -> None:
    """列出所有 direct 規則（`firewall-cmd --direct --get-all-rules`）。"""
    args: List[str] = [*_perm(permanent), "--direct", "--get-all-rules"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    text = out.strip() or "（無）"
    console.print(Panel(text, title="direct rules (--get-all-rules)", expand=False))


@direct_app.command("chains")
def direct_chains(
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="讀取 permanent；短選項為 -p。",
    ),
) -> None:
    args: List[str] = [*_perm(permanent), "--direct", "--get-all-chains"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    text = out.strip() or "（無）"
    console.print(Panel(text, title="direct chains", expand=False))


@direct_app.command("passthroughs")
def direct_passthroughs(
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="讀取 permanent；短選項為 -p。",
    ),
) -> None:
    args: List[str] = [*_perm(permanent), "--direct", "--get-all-passthroughs"]
    try:
        out = run_firewall_cmd(args, check=True).stdout
    except FirewallCmdError as e:
        print_firewall_cmd_error(console, e)
        raise typer.Exit(e.code) from e
    text = out.strip() or "（無）"
    console.print(Panel(text, title="direct passthroughs", expand=False))


@direct_app.command("add")
def direct_rule_add(
    chain: str = typer.Option(
        ...,
        "--chain",
        "-c",
        help="鏈名稱，例如 INPUT、OUTPUT（見 --allow-unusual-chain）。",
    ),
    priority: int = typer.Option(
        ...,
        "--priority",
        "-n",
        help="該鏈上的 priority（與 firewall-cmd direct 相同）。",
    ),
    family: str = typer.Option("ipv4", "--family", help="ipv4 | ipv6 | eb"),
    table: str = typer.Option("filter", "--table", help="通常為 filter。"),
    rule: Optional[str] = typer.Option(
        None,
        "--rule",
        "-r",
        help="priority 之後的 iptables 參數（shell 請加引號）。",
    ),
    rule_file: Optional[Path] = typer.Option(
        None,
        "--rule-file",
        help="從檔案讀取與 --rule 相同內容。",
    ),
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="寫入 permanent；短選項為 -p。",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    accept_drop_risk: bool = typer.Option(
        False,
        "--accept-drop-risk",
        help="規則含 -j DROP 或 -j REJECT 時必傳。",
    ),
    allow_unusual_chain: bool = typer.Option(
        False,
        "--allow-unusual-chain",
        help="允許非 filter 表或 INPUT/OUTPUT/FORWARD 以外的鏈。",
    ),
    verify_absent: bool = typer.Option(
        False,
        "--verify-absent",
        help="若已存在相同規則（query-rule）則拒絕。",
    ),
) -> None:
    """新增 direct 規則（`firewall-cmd --direct --add-rule …`）。"""
    body = _rule_body(rule=rule, rule_file=rule_file)
    tokens = _rule_tokens(body)
    fam, tbl, ch = _validate_direct_target(
        family, table, chain, allow_unusual_chain=allow_unusual_chain
    )
    _direct_add_core(
        fam,
        tbl,
        ch,
        priority,
        list(tokens),
        permanent=permanent,
        dry_run=dry_run,
        yes=yes,
        accept_drop_risk=accept_drop_risk,
        verify_absent=verify_absent,
        skip_confirm=False,
    )


@direct_app.command("remove")
def direct_rule_remove(
    chain: str = typer.Option(..., "--chain", "-c"),
    priority: int = typer.Option(..., "--priority", "-n"),
    family: str = typer.Option("ipv4", "--family"),
    table: str = typer.Option("filter", "--table"),
    rule: Optional[str] = typer.Option(None, "--rule", "-r"),
    rule_file: Optional[Path] = typer.Option(None, "--rule-file"),
    permanent: bool = typer.Option(
        False,
        "--permanent",
        "-p",
        help="針對 permanent；短選項為 -p。",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    allow_unusual_chain: bool = typer.Option(False, "--allow-unusual-chain"),
    verify_present: bool = typer.Option(
        True,
        "--verify-present/--no-verify-present",
        help="刪除前先 --query-rule（建議開）。",
    ),
    accept_ssh_rule_risk: bool = typer.Option(
        False,
        "--accept-ssh-rule-risk",
        help="規則文字疑似與 SSH（22 等）有關時必傳。",
    ),
) -> None:
    """刪除一筆 direct 規則；參數須與 add 時完全一致。"""
    body = _rule_body(rule=rule, rule_file=rule_file)
    tokens = _rule_tokens(body)
    fam, tbl, ch = _validate_direct_target(
        family, table, chain, allow_unusual_chain=allow_unusual_chain
    )
    _direct_remove_core(
        fam,
        tbl,
        ch,
        priority,
        list(tokens),
        body_for_ssh_check=body,
        permanent=permanent,
        dry_run=dry_run,
        yes=yes,
        verify_present=verify_present,
        accept_ssh_rule_risk=accept_ssh_rule_risk,
        skip_confirm=False,
    )


def _wizard_resolve_target(family: str, table: str, chain: str) -> Tuple[str, str, str]:
    try:
        return _validate_direct_target(family, table, chain, allow_unusual_chain=False)
    except typer.BadParameter:
        if typer.confirm(
            "此組合不是預設的 filter + INPUT/OUTPUT/FORWARD。"
            "若確定要改 nat／PREROUTING／raw 等，請確認後繼續。",
            default=False,
        ):
            return _validate_direct_target(family, table, chain, allow_unusual_chain=True)
        raise typer.Exit(1) from None


@direct_app.command("wizard-add")
def direct_wizard_add(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="略過最後「真的要執行」的確認（仍須通過 DROP 打字關卡）。",
    ),
) -> None:
    """互動式引導新增 direct rule（含 dry-run 預覽與 DROP 打字防呆）。"""
    console.print(
        Panel(
            "依序回答問題；結束前會先顯示 [bold]dry-run[/bold] 指令。\n"
            "含 DROP/REJECT 時必須輸入大寫 [bold]DROP-RISK[/bold] 才可繼續。",
            title="direct 精靈（新增）",
            expand=False,
        )
    )
    family = typer.prompt("family", default="ipv4").strip()
    table = typer.prompt("table", default="filter").strip()
    chain = typer.prompt("chain（例如 INPUT）").strip()
    priority = int(typer.prompt("priority（整數，可負數）"))
    path_hint = typer.prompt("rule 用檔案提供？輸入路徑；否則直接 Enter", default="").strip()
    if path_hint:
        body = _rule_body(rule=None, rule_file=Path(path_hint).expanduser())
    else:
        body = typer.prompt("rule 尾端（priority 之後整段，注意 shell 引號）").strip()
    tokens = _rule_tokens(body)

    fam, tbl, ch = _wizard_resolve_target(family, table, chain)
    permanent = typer.confirm("寫入 permanent 設定？", default=False)
    verify_absent = typer.confirm("新增前檢查是否尚不存在相同規則（建議開）？", default=True)

    accept_drop_risk = False
    if _tokens_have_drop_or_reject(tokens):
        console.print(
            "[yellow]偵測到 DROP／REJECT：可能鎖死管理連線（含 SSH）。[/yellow]"
        )
        token = typer.prompt("若仍要新增，請輸入大寫 DROP-RISK", default="").strip()
        if token != "DROP-RISK":
            console.print("[red]已取消。[/red]")
            raise typer.Exit(2)
        accept_drop_risk = True

    console.print(
        Panel(
            f"[bold]摘要[/bold]\n"
            f"family={fam} table={tbl} chain={ch} priority={priority}\n"
            f"permanent={permanent} verify_absent={verify_absent}\n"
            f"rule_tokens={tokens!r}",
            title="即將套用",
            expand=False,
        )
    )
    _direct_add_core(
        fam,
        tbl,
        ch,
        priority,
        list(tokens),
        permanent=permanent,
        dry_run=True,
        yes=True,
        accept_drop_risk=accept_drop_risk,
        verify_absent=False,
        skip_confirm=True,
    )

    if yes:
        run_for_real = True
    else:
        run_for_real = typer.confirm("以上為 dry-run。要實際執行嗎？（需要 root）", default=False)
    if not run_for_real:
        console.print("[dim]已取消，未寫入。[/dim]")
        raise typer.Exit(0)

    _direct_add_core(
        fam,
        tbl,
        ch,
        priority,
        list(tokens),
        permanent=permanent,
        dry_run=False,
        yes=True,
        accept_drop_risk=accept_drop_risk,
        verify_absent=verify_absent,
        skip_confirm=True,
    )


@direct_app.command("wizard-remove")
def direct_wizard_remove(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="略過最後「真的要執行」的確認（仍須通過 SSH 相關打字關卡）。",
    ),
) -> None:
    """互動式引導刪除 direct rule（可貼 `direct rules` 一整行）。"""
    console.print(
        Panel(
            "模式 1：貼上 `fwctl direct rules` 的一整行（含 priority 後規則）。\n"
            "模式 2：分欄輸入 family/table/chain/priority/rule。\n"
            "若規則疑似與 SSH 有關，必須輸入大寫 [bold]SSH-RISK[/bold]。",
            title="direct 精靈（刪除）",
            expand=False,
        )
    )
    mode = typer.prompt("選擇模式", default="1").strip()
    if mode == "1":
        line = typer.prompt("貼上一整行").strip()
        try:
            fam, tbl, ch, priority, tokens = _parse_direct_rules_line(line)
        except typer.BadParameter as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(2) from e
        body = " ".join(tokens)
    elif mode == "2":
        family = typer.prompt("family", default="ipv4").strip()
        table = typer.prompt("table", default="filter").strip()
        chain = typer.prompt("chain").strip()
        priority = int(typer.prompt("priority"))
        path_hint = typer.prompt("rule 檔案路徑（無則 Enter）", default="").strip()
        if path_hint:
            body = _rule_body(rule=None, rule_file=Path(path_hint).expanduser())
        else:
            body = typer.prompt("rule 尾端").strip()
        tokens = _rule_tokens(body)
        fam, tbl, ch = _wizard_resolve_target(family, table, chain)
    else:
        console.print("[red]模式請輸入 1 或 2。[/red]")
        raise typer.Exit(2)

    if mode == "1":
        fam, tbl, ch = _wizard_resolve_target(fam, tbl, ch)

    permanent = typer.confirm("針對 permanent 設定？", default=False)
    verify_present = typer.confirm("刪除前先 query 確認存在？（強烈建議）", default=True)

    accept_ssh_rule_risk = False
    if _rule_text_may_affect_ssh(body):
        console.print("[yellow]偵測到可能與 SSH（22 等）有關的規則。[/yellow]")
        token = typer.prompt("若仍要刪除，請輸入大寫 SSH-RISK", default="").strip()
        if token != "SSH-RISK":
            console.print("[red]已取消。[/red]")
            raise typer.Exit(2)
        accept_ssh_rule_risk = True

    console.print(
        Panel(
            f"[bold]摘要[/bold]\n"
            f"family={fam} table={tbl} chain={ch} priority={priority}\n"
            f"permanent={permanent} verify_present={verify_present}\n"
            f"rule_tokens={tokens!r}",
            title="即將套用",
            expand=False,
        )
    )
    _direct_remove_core(
        fam,
        tbl,
        ch,
        priority,
        list(tokens),
        body_for_ssh_check=body,
        permanent=permanent,
        dry_run=True,
        yes=True,
        verify_present=False,
        accept_ssh_rule_risk=accept_ssh_rule_risk,
        skip_confirm=True,
    )

    if yes:
        run_for_real = True
    else:
        run_for_real = typer.confirm("以上為 dry-run。要實際刪除嗎？（需要 root）", default=False)
    if not run_for_real:
        console.print("[dim]已取消，未變更。[/dim]")
        raise typer.Exit(0)

    _direct_remove_core(
        fam,
        tbl,
        ch,
        priority,
        list(tokens),
        body_for_ssh_check=body,
        permanent=permanent,
        dry_run=False,
        yes=True,
        verify_present=verify_present,
        accept_ssh_rule_risk=accept_ssh_rule_risk,
        skip_confirm=True,
    )
