"""快照層級狀態指標與額外 Mermaid 圖表（drift、direct -j 分布）。"""

from __future__ import annotations

import html
from collections import Counter
from typing import Any, Dict, List, Mapping, Optional, Sequence

from firewall_tool.viz.network_allow_extract import allow_matrix_from_snapshot_dict


def _zones_list(side: Any) -> List[Mapping[str, Any]]:
    if not isinstance(side, dict):
        return []
    z = side.get("zones")
    if not isinstance(z, list):
        return []
    return [x for x in z if isinstance(x, dict)]


def _jump_target(tokens: Sequence[str]) -> Optional[str]:
    for i in range(len(tokens) - 1):
        if tokens[i] == "-j":
            return str(tokens[i + 1])
    return None


def _primary_zones(snapshot: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    z = _zones_list(snapshot.get("runtime"))
    if not z:
        z = _zones_list(snapshot.get("permanent"))
    return z


def _rich_rules_count(zones: Sequence[Mapping[str, Any]]) -> int:
    n = 0
    for z in zones:
        rr = z.get("rich_rules") or []
        if isinstance(rr, list):
            n += sum(1 for x in rr if str(x).strip())
    return n


def _drift_zone_consistency(snapshot: Mapping[str, Any]) -> tuple[int, int, int]:
    """回傳 (可比對 zone 總數, services+ports 皆一致數, 有差異數)。"""
    if not snapshot.get("drift_available"):
        return 0, 0, 0
    drift = snapshot.get("drift") or {}
    zones_d = drift.get("zones") if isinstance(drift, dict) else None
    if not isinstance(zones_d, dict):
        return 0, 0, 0
    total = ok = 0
    for _zname, zd in zones_d.items():
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
        if not only_r and not only_p and not pr_r and not pr_p:
            ok += 1
        total += 1
    return total, ok, total - ok


def compute_status_summary(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """由快照彙總數字與簡短建議（不含連線探測）。"""
    zones_rt = _zones_list(snapshot.get("runtime"))
    zones_pm = _zones_list(snapshot.get("permanent"))
    primary = _primary_zones(snapshot)
    drift_total, drift_ok, drift_bad = _drift_zone_consistency(snapshot)

    ips = snapshot.get("ipsets") or {}
    rt_names = {str(x).strip() for x in (ips.get("runtime") or []) if str(x).strip()}
    pm_names = {str(x).strip() for x in (ips.get("permanent") or []) if str(x).strip()}
    only_rt = len(rt_names - pm_names)
    only_pm = len(pm_names - rt_names)
    both = len(rt_names & pm_names)

    parsed = snapshot.get("direct_rules_parsed")
    if not isinstance(parsed, list):
        parsed = []
    parse_err = sum(1 for p in parsed if isinstance(p, dict) and p.get("parse_error"))
    parse_ok = len([p for p in parsed if isinstance(p, dict) and not p.get("parse_error")])

    matrix = allow_matrix_from_snapshot_dict(snapshot)
    stats = matrix.get("stats") if isinstance(matrix, dict) else {}
    if not isinstance(stats, dict):
        stats = {}

    hints: List[str] = []
    level = "ok"
    if drift_bad > 0:
        hints.append(f"有 {drift_bad} 個 zone 的 services／ports 在 runtime 與 permanent 不一致，建議檢視 drift。")
        level = "warn"
    if parse_err > 0:
        hints.append(f"direct 規則有 {parse_err} 行解析失敗，請手動核對。")
        level = "warn" if level == "warn" else "notice"
    if only_rt > 0 or only_pm > 0:
        hints.append("ipset 名稱在 runtime／permanent 兩側不一致，reload 前後請留意。")
        if level == "ok":
            level = "notice"
    if not hints:
        hints.append("未偵測到上述警示條件（仍不代表整體安全性）。")

    return {
        "drift_available": bool(snapshot.get("drift_available")),
        "zones_runtime_count": len(zones_rt),
        "zones_permanent_count": len(zones_pm),
        "zones_primary_count": len(primary),
        "rich_rules_count": _rich_rules_count(primary),
        "drift_zones_total": drift_total,
        "drift_zones_consistent": drift_ok,
        "drift_zones_conflict": drift_bad,
        "ipsets_runtime_count": len(rt_names),
        "ipsets_permanent_count": len(pm_names),
        "ipsets_both_names": both,
        "ipsets_only_runtime_names": only_rt,
        "ipsets_only_permanent_names": only_pm,
        "direct_rules_total": len(snapshot.get("direct_rules") or [])
        if isinstance(snapshot.get("direct_rules"), list)
        else 0,
        "direct_parsed_ok": parse_ok,
        "direct_parsed_errors": parse_err,
        "direct_accept_rows": int(stats.get("accept_rows", 0) or 0),
        "direct_skipped_non_accept": int(stats.get("skipped_non_accept", 0) or 0),
        "direct_skipped_parse_error": int(stats.get("skipped_parse_error", 0) or 0),
        "status_level": level,
        "status_hints": hints,
    }


def ensure_status_summary(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    s = snapshot.get("status_summary")
    if isinstance(s, dict) and "zones_primary_count" in s:
        return s
    return compute_status_summary(snapshot)


def mermaid_drift_zone_pie(snapshot: Mapping[str, Any]) -> str:
    if not snapshot.get("drift_available"):
        return 'flowchart TB\n  N["（無 runtime／permanent drift）"]'
    total, ok, bad = _drift_zone_consistency(snapshot)
    if total == 0:
        return 'flowchart TB\n  N["（無 zone 可比對）"]'
    if bad == 0:
        return "\n".join(["pie showData", '    title Zone drift（services／ports）', f'    "一致" : {ok}'])
    return "\n".join(
        [
            "pie showData",
            '    title Zone drift（services／ports）',
            f'    "一致" : {ok}',
            f'    "有差異" : {bad}',
        ]
    )


def mermaid_direct_jump_pie(snapshot: Mapping[str, Any]) -> str:
    parsed = snapshot.get("direct_rules_parsed")
    if not isinstance(parsed, list):
        parsed = []
    c: Counter[str] = Counter()
    for p in parsed:
        if not isinstance(p, dict) or p.get("parse_error"):
            continue
        toks = [str(x) for x in (p.get("tokens") or [])]
        j = _jump_target(toks)
        if j:
            c[j] += 1
    if not c:
        return 'flowchart TB\n  E["（無可解析的 -j 目標）"]'
    lines = ["pie showData", '    title Direct -j 目標（列數）']
    for label, n in c.most_common(8):
        safe = label.replace('"', "'")[:40]
        lines.append(f'    "{safe}" : {n}')
    if len(c) > 8:
        rest = sum(n for _, n in c.most_common()[8:])
        lines.append(f'    "（其它 {len(c) - 8} 種）" : {rest}')
    return "\n".join(lines)


def status_summary_html_table(st: Mapping[str, Any]) -> str:
    rows: List[tuple[str, str]] = [
        ("drift 可比對", "是" if st.get("drift_available") else "否"),
        ("runtime zone 數", str(st.get("zones_runtime_count", ""))),
        ("permanent zone 數", str(st.get("zones_permanent_count", ""))),
        ("主要視角 zone 數", str(st.get("zones_primary_count", ""))),
        ("rich rules 筆數（主要視角）", str(st.get("rich_rules_count", ""))),
        ("drift：一致 zone", str(st.get("drift_zones_consistent", ""))),
        ("drift：有差異 zone", str(st.get("drift_zones_conflict", ""))),
        ("ipset 名稱（runtime／permanent／交集）", f"{st.get('ipsets_runtime_count')}/{st.get('ipsets_permanent_count')}/{st.get('ipsets_both_names')}"),
        ("僅 runtime／僅 permanent 的 ipset 名稱數", f"{st.get('ipsets_only_runtime_names')} / {st.get('ipsets_only_permanent_names')}"),
        ("direct 規則行數", str(st.get("direct_rules_total", ""))),
        ("direct 解析成功／失敗", f"{st.get('direct_parsed_ok')} / {st.get('direct_parsed_errors')}"),
        ("direct ACCEPT 摘要列／略過非 ACCEPT", f"{st.get('direct_accept_rows')} / {st.get('direct_skipped_non_accept')}"),
        ("狀態等級", str(st.get("status_level", ""))),
    ]
    body = "".join(
        "<tr><td>"
        f"{html.escape(str(k), quote=True)}</td><td>{html.escape(str(v), quote=True)}</td></tr>"
        for k, v in rows
    )
    hints = st.get("status_hints") or []
    hint_html = ""
    if isinstance(hints, list) and hints:
        items = "".join(
            f"<li>{html.escape(str(h), quote=True)}</li>" for h in hints if str(h).strip()
        )
        hint_html = f"<p><strong>建議</strong></p><ul>{items}</ul>"
    return f"<table><thead><tr><th>項目</th><th>值</th></tr></thead><tbody>{body}</tbody></table>{hint_html}"


def status_summary_markdown_block(st: Mapping[str, Any]) -> str:
    lines = [
        "## 快照狀態與圖表分析",
        "",
        "| 項目 | 值 |",
        "| --- | --- |",
        f"| drift 可比對 | {'是' if st.get('drift_available') else '否'} |",
        f"| runtime／permanent zone 數 | {st.get('zones_runtime_count')}／{st.get('zones_permanent_count')} |",
        f"| rich rules 筆數（主要視角） | {st.get('rich_rules_count')} |",
        f"| drift 一致／有差異 zone | {st.get('drift_zones_consistent')}／{st.get('drift_zones_conflict')} |",
        f"| ipset 名稱 runtime／permanent／交集 | {st.get('ipsets_runtime_count')}／{st.get('ipsets_permanent_count')}／{st.get('ipsets_both_names')} |",
        f"| direct 行數；解析成功／失敗 | {st.get('direct_rules_total')}；{st.get('direct_parsed_ok')}／{st.get('direct_parsed_errors')} |",
        f"| direct ACCEPT 列／略過非 ACCEPT | {st.get('direct_accept_rows')}／{st.get('direct_skipped_non_accept')} |",
        f"| **狀態等級** | **{st.get('status_level')}** |",
        "",
    ]
    hints = st.get("status_hints") or []
    if isinstance(hints, list) and hints:
        lines.append("**建議**")
        for h in hints:
            if str(h).strip():
                lines.append(f"- {str(h).strip()}")
        lines.append("")
    return "\n".join(lines)
