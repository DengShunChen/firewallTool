"""Generate a Markdown report (Mermaid + tables) from a viz snapshot."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Sequence

from firewall_tool.viz.html_report import (
    _direct_parsed,
    _ipset_first_info_line,
    _mermaid_direct_allow_pie,
    _mermaid_direct_chains,
    _mermaid_ipset_name_overlap,
    _mermaid_topology,
)
from firewall_tool.viz.network_allow_extract import allow_matrix_from_snapshot_dict


def _md_cell(s: Any) -> str:
    t = " ".join(str(s).splitlines())
    return t.replace("|", "\\|")


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    if not rows:
        return ""
    h = "| " + " | ".join(_md_cell(x) for x in headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body = "\n".join("| " + " | ".join(_md_cell(c) for c in row) + " |" for row in rows)
    return "\n".join([h, sep, body])


def _mermaid_block(diagram: str) -> str:
    d = diagram.strip()
    if not d:
        return "（無圖）\n"
    return "```mermaid\n" + d + "\n```\n"


def _md_drift_section(snapshot: Mapping[str, Any]) -> str:
    if not snapshot.get("drift_available"):
        note = snapshot.get("drift")
        msg = "無 drift 資料。"
        if isinstance(note, dict):
            msg = str(note.get("note", msg))
        return msg + "\n\n"

    drift = snapshot.get("drift") or {}
    zones_d = drift.get("zones") if isinstance(drift, dict) else None
    if not isinstance(zones_d, dict):
        return "（無 drift 區塊）\n\n"

    headers = [
        "Zone",
        "僅 runtime services",
        "僅 permanent services",
        "僅 runtime ports",
        "僅 permanent ports",
        "摘要",
    ]
    rows: List[List[str]] = []
    for zname in sorted(zones_d.keys()):
        zd = zones_d[zname]
        if not isinstance(zd, dict):
            continue
        lists = zd.get("lists") or {}
        if not isinstance(lists, dict):
            lists = {}
        svc = lists.get("services") if isinstance(lists.get("services"), dict) else {}
        prt = lists.get("ports") if isinstance(lists.get("ports"), dict) else {}
        only_r = svc.get("only_runtime") or []
        only_p = svc.get("only_permanent") or []
        pr_r = prt.get("only_runtime") or []
        pr_p = prt.get("only_permanent") or []
        svc_ok = not only_r and not only_p
        pr_ok = not pr_r and not pr_p
        status = "一致" if (svc_ok and pr_ok) else "差異"
        rows.append(
            [
                zname,
                ", ".join(str(x) for x in only_r) or "—",
                ", ".join(str(x) for x in only_p) or "—",
                ", ".join(str(x) for x in pr_r) or "—",
                ", ".join(str(x) for x in pr_p) or "—",
                status,
            ]
        )
    if not rows:
        return "（無 zone 可比對）\n\n"
    return _md_table(headers, rows) + "\n\n"


def _md_ipset_names(snapshot: Mapping[str, Any]) -> str:
    ips = snapshot.get("ipsets") or {}
    if not isinstance(ips, dict):
        return ""
    rt = ips.get("runtime") or []
    pm = ips.get("permanent") or []
    if not isinstance(rt, list):
        rt = []
    if not isinstance(pm, list):
        pm = []
    lines = [
        f"- **ipsets（runtime）**：{', '.join(str(x) for x in rt) or '—'}",
        f"- **ipsets（permanent）**：{', '.join(str(x) for x in pm) or '—'}",
        "",
    ]
    return "\n".join(lines)


def _md_ipset_details(snapshot: Mapping[str, Any]) -> str:
    ips = snapshot.get("ipsets") or {}
    if not isinstance(ips, dict):
        return ""
    det = ips.get("details")
    if not isinstance(det, dict):
        return "（此快照無 ipset 詳情；schema < 2 或查詢失敗）\n\n" + _md_ipset_names(snapshot)

    chunks: List[str] = []
    for side, label in (("runtime", "runtime"), ("permanent", "permanent")):
        rows_in = det.get(side) or []
        if not isinstance(rows_in, list):
            rows_in = []
        chunks.append(f"### ipset 詳情（{label}）\n\n")
        if not rows_in:
            chunks.append("—\n\n")
            continue
        headers = ["名稱", "info 首行／錯誤", "條目數", "濃縮預覽"]
        rows: List[List[str]] = []
        for r in rows_in:
            if not isinstance(r, dict):
                continue
            nm = str(r.get("name", ""))
            inf = str(r.get("info", ""))
            summ = _ipset_first_info_line(inf) or "—"
            et_raw = r.get("entries_total")
            if isinstance(et_raw, int):
                tot = str(et_raw)
            else:
                ent = r.get("entries") or []
                tot = str(len(ent)) if isinstance(ent, list) else "0"
            summ_compact = r.get("entries_summary")
            if isinstance(summ_compact, str) and summ_compact.strip():
                prev = summ_compact.strip()
            else:
                ent = r.get("entries") if isinstance(r.get("entries"), list) else []
                prev = ", ".join(str(x) for x in ent[:16])
                if r.get("entries_truncated") or (isinstance(et_raw, int) and et_raw > len(ent)):
                    prev += " …"
            flags: List[str] = []
            if r.get("info_error"):
                flags.append(f"info: {r['info_error']}")
            if r.get("entries_error"):
                flags.append(f"entries: {r['entries_error']}")
            if flags:
                summ = f"{summ}（{'；'.join(flags)}）"
            rows.append([nm, summ, tot, prev or "—"])
        chunks.append(_md_table(headers, rows) + "\n\n")
    return "".join(chunks)


def _md_fmt_list(xs: Any, *, max_items: int = 12) -> str:
    if not isinstance(xs, list) or not xs:
        return "—"
    parts = [str(x) for x in xs[:max_items]]
    tail = " …" if len(xs) > max_items else ""
    return ", ".join(parts) + tail


def _md_allow_chain_table(title: str, rows: Any) -> str:
    out = f"### {title}\n\n"
    if not isinstance(rows, list) or not rows:
        return out + "—\n\n"
    headers = [
        "prio",
        "fam",
        "table",
        "來源 -s",
        "目的 -d",
        "-p",
        "dport",
        "sport",
        "-i",
        "-o",
        "ipset",
        "ipset 摘要",
        "raw",
    ]
    md_rows: List[List[str]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        resolved = r.get("ipset_resolved") or []
        if not isinstance(resolved, list):
            resolved = []
        iset_cells = []
        iset_sum = []
        for x in resolved:
            if not isinstance(x, dict):
                continue
            nm = str(x.get("name") or "")
            dr = str(x.get("direction") or "")
            sm = str(x.get("entries_summary") or "")
            iset_cells.append(f"{nm}({dr})" if dr else nm)
            if sm:
                iset_sum.append(f"{nm}: {sm}"[:200])
        raw = str(r.get("raw") or "")
        raw_short = raw if len(raw) <= 200 else raw[:197] + "…"
        md_rows.append(
            [
                str(r.get("priority", "")),
                str(r.get("family", "")),
                str(r.get("table", "")),
                _md_fmt_list(r.get("sources")),
                _md_fmt_list(r.get("destinations")),
                str(r.get("proto") or "—"),
                _md_fmt_list(r.get("dports")),
                _md_fmt_list(r.get("sports")),
                _md_fmt_list(r.get("in_interfaces")),
                _md_fmt_list(r.get("out_interfaces")),
                ", ".join(iset_cells) if iset_cells else "—",
                " | ".join(iset_sum) if iset_sum else "—",
                raw_short,
            ]
        )
    return out + _md_table(headers, md_rows) + "\n\n"


def _md_direct_allow_matrix(matrix: Mapping[str, Any]) -> str:
    parts: List[str] = []
    note = matrix.get("note")
    if isinstance(note, str) and note.strip():
        parts.append(f"> {note.strip()}\n\n")
    stats = matrix.get("stats")
    if isinstance(stats, dict):
        parts.append(
            f"> 解析統計：ACCEPT 列 {stats.get('accept_rows', 0)}；"
            f"略過非 ACCEPT {stats.get('skipped_non_accept', 0)}；"
            f"略過解析失敗 {stats.get('skipped_parse_error', 0)}。\n\n"
        )
    for title, key in (
        ("INPUT（-j ACCEPT）", "input"),
        ("OUTPUT（-j ACCEPT）", "output"),
        ("FORWARD（-j ACCEPT）", "forward"),
        ("其它 chain（-j ACCEPT）", "other"),
    ):
        parts.append(_md_allow_chain_table(title, matrix.get(key)))
    return "".join(parts)


def _md_direct_rules_table(parsed: Sequence[Mapping[str, Any]]) -> str:
    if not parsed:
        return "（無）\n\n"
    headers = ["prio", "family", "table", "chain", "rule"]
    rows: List[List[str]] = []
    limit = 250
    for p in parsed[:limit]:
        if not isinstance(p, dict):
            continue
        if not p.get("parse_error"):
            toks = p.get("tokens") or []
            rule = " ".join(str(t) for t in toks) if isinstance(toks, list) else ""
            rows.append(
                [
                    str(p.get("priority", "")),
                    str(p.get("family", "")),
                    str(p.get("table", "")),
                    str(p.get("chain", "")),
                    rule,
                ]
            )
        else:
            rows.append(["", "", "", "（解析失敗）", str(p.get("raw", ""))])
    more = ""
    if len(parsed) > limit:
        more = f"\n\n> 表格僅顯示前 {limit} 筆。\n"
    return _md_table(headers, rows) + more + "\n"


def _md_direct_raw(snapshot: Mapping[str, Any]) -> str:
    rules = snapshot.get("direct_rules") or []
    if not isinstance(rules, list) or not rules:
        return ""
    lines = "\n".join(str(r) for r in rules[:200])
    more = ""
    if len(rules) > 200:
        more = f"\n# … 其餘 {len(rules) - 200} 行略\n"
    return "### 原始 `--get-all-rules` 行\n\n```text\n" + lines + "\n```" + more + "\n\n"


def generate_markdown_report(snapshot: Mapping[str, Any]) -> str:
    """由快照產出 Markdown（GitHub／GitLab 等可渲染 Mermaid）。"""
    title = "fwctl 防火牆快照"
    gen = str(snapshot.get("generated_at", ""))
    backend = str(snapshot.get("backend", ""))
    ver = snapshot.get("schema_version", "")
    parsed = _direct_parsed(snapshot)
    matrix = allow_matrix_from_snapshot_dict(snapshot)

    parts: List[str] = [
        f"# {title}\n",
        f"- **產生時間**：`{gen}`",
        f"- **後端**：`{backend}`",
        f"- **schema**：`{ver}`",
        "",
        "> Mermaid 圖在 GitHub／GitLab／部分編輯器可預覽；純文字檢視可略過程式碼塊。",
        "",
        "## Zone／介面拓樸（Mermaid）\n",
        _mermaid_block(_mermaid_topology(snapshot)),
        "## Runtime vs Permanent（services／ports drift）\n",
        _md_drift_section(snapshot),
        "## ipset 名稱\n",
        _md_ipset_names(snapshot),
        "## ipset 名稱分布（Mermaid）\n",
        _mermaid_block(_mermaid_ipset_name_overlap(snapshot)),
        _md_ipset_details(snapshot),
        "## Direct 允許流量摘要（INPUT／OUTPUT）\n",
        "> 由 `direct_rules_parsed`（僅 `-j ACCEPT`）與 `ipsets.details` 對照；不含 zone／rich rules。\n",
        _mermaid_block(_mermaid_direct_allow_pie(matrix)),
        _md_direct_allow_matrix(matrix),
        "## Direct 規則（全列）\n",
        "> 下列流程圖僅輔助閱讀，不代表 netfilter 實際順序。\n",
        _mermaid_block(_mermaid_direct_chains(parsed)),
        "### Direct 結構化表格\n",
        _md_direct_rules_table(parsed),
        _md_direct_raw(snapshot),
    ]
    return "\n".join(parts)


def markdown_report_from_json_text(text: str) -> str:
    snap = json.loads(text)
    if not isinstance(snap, dict):
        raise ValueError("snapshot JSON 必須為 object")
    return generate_markdown_report(snap)
