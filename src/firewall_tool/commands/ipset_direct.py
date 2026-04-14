"""ipset and --direct rule inspection + guarded mutations."""

from __future__ import annotations

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
ipset_app = typer.Typer(help="List or inspect firewalld ipsets.")
direct_app = typer.Typer(help="Inspect or change firewalld --direct rules (guarded).")

_COMMON_CHAINS = frozenset({"INPUT", "OUTPUT", "FORWARD"})


def _perm(permanent: bool) -> List[str]:
    return ["--permanent"] if permanent else []


def _rule_body(*, rule: Optional[str], rule_file: Optional[Path]) -> str:
    if (rule is None) == (rule_file is None):
        raise typer.BadParameter("Provide exactly one of --rule or --rule-file.")
    if rule_file is not None:
        if not rule_file.is_file():
            raise typer.BadParameter(f"Not a file: {rule_file}")
        return rule_file.read_text(encoding="utf-8").strip()
    assert rule is not None
    return rule.strip()


def _rule_tokens(rule_text: str) -> List[str]:
    if not rule_text:
        raise typer.BadParameter("Rule text is empty.")
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
        raise typer.BadParameter("family must be one of: ipv4, ipv6, eb")
    if not allow_unusual_chain:
        if table != "filter":
            raise typer.BadParameter(
                f"table is {table!r} (not filter). If intentional, pass --allow-unusual-chain."
            )
        if chain not in _COMMON_CHAINS:
            raise typer.BadParameter(
                f"chain {chain!r} is not one of {_COMMON_CHAINS}. "
                "For PREROUTING/nat/raw etc., pass --allow-unusual-chain."
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
            console.print("[red]Refused:[/red] an identical rule already exists (--verify-absent).")
            raise typer.Exit(2)

    if _tokens_have_drop_or_reject(tokens):
        if not accept_drop_risk:
            console.print(
                "[red]Refused:[/red] rule contains DROP/REJECT. "
                "Re-run with [bold]--accept-drop-risk[/bold] after you confirmed management access."
            )
            raise typer.Exit(2)
        if not skip_confirm:
            _confirm(
                dry_run=dry_run,
                yes=yes,
                msg="Add a DROP/REJECT direct rule (can lock out SSH or other access). Continue?",
            )
    elif not skip_confirm:
        _confirm(
            dry_run=dry_run,
            yes=yes,
            msg=f"Add direct rule {fam} {tbl} {ch} prio {priority}?",
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
    console.print("[green]Added.[/green]", res.stdout.strip())
    if permanent and not dry_run:
        console.print("[dim]Remember:[/dim] [bold]fwctl reload[/bold] if runtime should match permanent.")


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
                "[red]Refused:[/red] this rule text may affect SSH. "
                "Re-run with [bold]--accept-ssh-rule-risk[/bold] if you are sure."
            )
            raise typer.Exit(2)

    if verify_present and not dry_run:
        if not _query_direct_rule(fam, tbl, ch, priority, tokens, permanent=permanent):
            console.print(
                "[red]Refused:[/red] rule not present for this family/table/chain/priority/body "
                "(check spelling; copy from `fwctl direct rules`)."
            )
            raise typer.Exit(2)

    if not skip_confirm:
        _confirm(
            dry_run=dry_run,
            yes=yes,
            msg=f"Remove direct rule {fam} {tbl} {ch} prio {priority}?",
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
    console.print("[green]Removed.[/green]", res.stdout.strip())
    if permanent and not dry_run:
        console.print("[dim]Remember:[/dim] [bold]fwctl reload[/bold] if runtime should match permanent.")


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


@direct_app.command("add")
def direct_rule_add(
    chain: str = typer.Option(
        ...,
        "--chain",
        "-c",
        help="Chain name, e.g. INPUT, OUTPUT (see --allow-unusual-chain).",
    ),
    priority: int = typer.Option(
        ...,
        "--priority",
        "-n",
        help="Priority number in that chain (same as firewall-cmd direct).",
    ),
    family: str = typer.Option("ipv4", "--family", help="ipv4 | ipv6 | eb"),
    table: str = typer.Option("filter", "--table", help="Usually filter."),
    rule: Optional[str] = typer.Option(
        None,
        "--rule",
        "-r",
        help="iptables arguments after priority (quote for shell).",
    ),
    rule_file: Optional[Path] = typer.Option(
        None,
        "--rule-file",
        help="Read rule tail from file (same content as --rule).",
    ),
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    accept_drop_risk: bool = typer.Option(
        False,
        "--accept-drop-risk",
        help="Required if the rule contains -j DROP or -j REJECT.",
    ),
    allow_unusual_chain: bool = typer.Option(
        False,
        "--allow-unusual-chain",
        help="Allow non-filter table or chain outside INPUT/OUTPUT/FORWARD.",
    ),
    verify_absent: bool = typer.Option(
        False,
        "--verify-absent",
        help="If set, refuse when an identical rule already exists (query-rule).",
    ),
) -> None:
    """Add a direct rule (`firewall-cmd --direct --add-rule ...`)."""
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
    permanent: bool = typer.Option(False, "--permanent", "-p"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    allow_unusual_chain: bool = typer.Option(False, "--allow-unusual-chain"),
    verify_present: bool = typer.Option(
        True,
        "--verify-present/--no-verify-present",
        help="Run --query-rule before remove (recommended).",
    ),
    accept_ssh_rule_risk: bool = typer.Option(
        False,
        "--accept-ssh-rule-risk",
        help="Required when the rule text looks SSH-related (port 22 / 'ssh').",
    ),
) -> None:
    """Remove one direct rule; must match add-rule arguments exactly."""
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
            "若你確定要改 nat/PREROUTING/raw 等，請確認後繼續。",
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
            title="direct wizard-add",
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
            title="direct wizard-remove",
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
