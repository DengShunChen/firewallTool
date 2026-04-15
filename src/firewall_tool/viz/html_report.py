"""Generate a static HTML report (Mermaid + drift tables) from a viz snapshot."""

from __future__ import annotations

import html
import json
import re
from collections import defaultdict
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from firewall_tool.viz.snapshot import parse_direct_rule_line

_MERMAID_ID_RE = re.compile(r"[^0-9a-zA-Z_]")


def _mid(name: str) -> str:
    """Mermaid-safe node id."""
    s = _MERMAID_ID_RE.sub("_", name)
    if s and s[0].isdigit():
        return "Z_" + s
    return "Z_" + s if not s.startswith("Z_") else s


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def _mermaid_label(s: str) -> str:
    t = " ".join(s.split())
    return t.replace('"', "'")[:120]


def _zones_list(side: Any) -> List[Mapping[str, Any]]:
    if not isinstance(side, dict):
        return []
    z = side.get("zones")
    if not isinstance(z, list):
        return []
    return [x for x in z if isinstance(x, dict)]


def _mermaid_topology(snapshot: Mapping[str, Any]) -> str:
    """Flowchart: default zone -> each zone with interfaces (no subgraph, parser 較穩)."""
    default_z = str(snapshot.get("default_zone") or "default")
    lines = [
        "flowchart TB",
        f'  DNODE["{_mermaid_label("預設 zone: " + default_z)}"]',
    ]

    zones = _zones_list(snapshot.get("runtime"))
    if not zones:
        zones = _zones_list(snapshot.get("permanent"))
    if not zones:
        lines.append('  EMPTY["（無 zone 資料）"]')
        lines.append("  DNODE --> EMPTY")
        return "\n".join(lines)

    for z in zones:
        name = str(z.get("name", "?"))
        active = bool(z.get("active"))
        attrs = z.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}
        ifaces = attrs.get("interfaces") or []
        if isinstance(ifaces, str):
            ifaces = [ifaces] if ifaces.strip() else []
        if not isinstance(ifaces, list):
            ifaces = []
        iface_str = ", ".join(str(x) for x in ifaces[:8])
        if len(ifaces) > 8:
            iface_str += "…"
        suffix = " (active)" if active else ""
        nid = _mid(name)
        label = _mermaid_label(f"{name}{suffix}" + (f" | {iface_str}" if iface_str else ""))
        lines.append(f'  {nid}["{label}"]')
        lines.append(f"  DNODE --> {nid}")
    return "\n".join(lines)


def _drift_table(snapshot: Mapping[str, Any]) -> str:
    if not snapshot.get("drift_available"):
        note = snapshot.get("drift")
        msg = ""
        if isinstance(note, dict):
            msg = str(note.get("note", "無 runtime／permanent 對照。"))
        return f"<p class=\"muted\">{_esc(msg or '無 drift 資料。')}</p>"

    drift = snapshot.get("drift") or {}
    zones_d = drift.get("zones") if isinstance(drift, dict) else None
    if not isinstance(zones_d, dict):
        return "<p class=\"muted\">（無 drift 區塊）</p>"

    rows_html: List[str] = []
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
        svc_ok = not only_r and not only_p
        pr_r = prt.get("only_runtime") or []
        pr_p = prt.get("only_permanent") or []
        pr_ok = not pr_r and not pr_p
        status = "一致" if (svc_ok and pr_ok) else "差異"
        row = (
            f"<tr><td>{_esc(zname)}</td>"
            f"<td>{_esc(', '.join(str(x) for x in only_r)) or '—'}</td>"
            f"<td>{_esc(', '.join(str(x) for x in only_p)) or '—'}</td>"
            f"<td>{_esc(', '.join(str(x) for x in pr_r)) or '—'}</td>"
            f"<td>{_esc(', '.join(str(x) for x in pr_p)) or '—'}</td>"
            f"<td>{_esc(status)}</td></tr>"
        )
        rows_html.append(row)

    if not rows_html:
        return "<p class=\"muted\">（無 zone 可比對）</p>"

    thead = (
        "<thead><tr>"
        "<th>Zone</th>"
        "<th>僅 runtime services</th>"
        "<th>僅 permanent services</th>"
        "<th>僅 runtime ports</th>"
        "<th>僅 permanent ports</th>"
        "<th>摘要</th>"
        "</tr></thead>"
    )
    return f"<table>{thead}<tbody>{''.join(rows_html)}</tbody></table>"


def _ipset_name_lines(snapshot: Mapping[str, Any]) -> str:
    ips = snapshot.get("ipsets") or {}
    if not isinstance(ips, dict):
        return ""
    rt = ips.get("runtime") or []
    pm = ips.get("permanent") or []
    if not isinstance(rt, list):
        rt = []
    if not isinstance(pm, list):
        pm = []
    return (
        f"<p><strong>ipsets（runtime）</strong>：{_esc(', '.join(str(x) for x in rt)) or '—'}</p>"
        f"<p><strong>ipsets（permanent）</strong>：{_esc(', '.join(str(x) for x in pm)) or '—'}</p>"
    )


def _ipset_first_info_line(info: str) -> str:
    for ln in info.splitlines():
        t = ln.strip()
        if t:
            return t[:160]
    return ""


def _mermaid_ipset_name_overlap(snapshot: Mapping[str, Any]) -> str:
    ips = snapshot.get("ipsets") or {}
    if not isinstance(ips, dict):
        return 'flowchart TB\n  E["（無 ipset 名稱）"]'
    rt = {str(x).strip() for x in (ips.get("runtime") or []) if str(x).strip()}
    pm = {str(x).strip() for x in (ips.get("permanent") or []) if str(x).strip()}
    only_rt = len(rt - pm)
    only_pm = len(pm - rt)
    both = len(rt & pm)
    return "\n".join(
        [
            "flowchart LR",
            f'  NRT["{_mermaid_label(f"僅 runtime：{only_rt} 個")}"]',
            f'  NB["{_mermaid_label(f"兩側皆有：{both} 個")}"]',
            f'  NPM["{_mermaid_label(f"僅 permanent：{only_pm} 個")}"]',
            "  NRT --- NB --- NPM",
        ]
    )


def _ipset_detail_tables(snapshot: Mapping[str, Any]) -> str:
    ips = snapshot.get("ipsets") or {}
    if not isinstance(ips, dict):
        return ""
    det = ips.get("details")
    if not isinstance(det, dict):
        return f"<p class=\"muted\">（此快照無 ipset 詳情；schema &lt; 2 或查詢失敗）</p>{_ipset_name_lines(snapshot)}"

    chunks: List[str] = []
    for side, label in (("runtime", "runtime"), ("permanent", "permanent")):
        rows_in = det.get(side) or []
        if not isinstance(rows_in, list):
            rows_in = []
        chunks.append(f"<h3>ipset 詳情（{label}）</h3>")
        if not rows_in:
            chunks.append("<p class=\"muted\">—</p>")
            continue
        body_rows: List[str] = []
        for r in rows_in:
            if not isinstance(r, dict):
                continue
            nm = _esc(str(r.get("name", "")))
            inf = str(r.get("info", ""))
            summ = _esc(_ipset_first_info_line(inf) or "—")
            et_raw = r.get("entries_total")
            if isinstance(et_raw, int):
                tot = et_raw
            else:
                ent = r.get("entries") or []
                tot = len(ent) if isinstance(ent, list) else 0
            summ_compact = r.get("entries_summary")
            if isinstance(summ_compact, str) and summ_compact.strip():
                prev = _esc(summ_compact.strip())
            else:
                ent = r.get("entries") if isinstance(r.get("entries"), list) else []
                prev = ", ".join(_esc(str(x)) for x in ent[:16])
                if r.get("entries_truncated") or (isinstance(et_raw, int) and et_raw > len(ent)):
                    prev += " …"
            flags: List[str] = []
            if r.get("info_error"):
                flags.append(f"info: {_esc(str(r['info_error']))}")
            if r.get("entries_error"):
                flags.append(f"entries: {_esc(str(r['entries_error']))}")
            flag_html = f' <span class="muted">（{"；".join(flags)}）</span>' if flags else ""
            info_block = ""
            if inf.strip():
                info_block = (
                    f"<details><summary>完整 <code>--info-ipset</code></summary>"
                    f"<pre>{_esc(inf)}</pre></details>"
                )
            body_rows.append(
                f"<tr><td>{nm}</td><td>{summ}{flag_html}</td><td>{tot}</td><td>{prev or '—'}</td>"
                f"<td>{info_block}</td></tr>"
            )
        chunks.append(
            "<table><thead><tr>"
            "<th>名稱</th><th>info 首行／錯誤</th><th>條目數</th><th>濃縮預覽（/24 方括號）</th><th>完整 info</th>"
            "</tr></thead><tbody>"
            + "".join(body_rows)
            + "</tbody></table>"
        )
    return "".join(chunks)


def _direct_parsed(snapshot: Mapping[str, Any]) -> List[Dict[str, Any]]:
    raw_p = snapshot.get("direct_rules_parsed")
    if isinstance(raw_p, list) and raw_p:
        return [x for x in raw_p if isinstance(x, dict)]
    rules = snapshot.get("direct_rules") or []
    if not isinstance(rules, list):
        return []
    return [parse_direct_rule_line(str(ln)) for ln in rules if str(ln).strip()]


def _mermaid_direct_chains(parsed: Sequence[Mapping[str, Any]]) -> str:
    ok = [p for p in parsed if not p.get("parse_error")]
    if not ok:
        return 'flowchart TB\n  E["（無可解析的 direct 規則）"]'
    groups: Dict[Tuple[str, str, str], List[Mapping[str, Any]]] = defaultdict(list)
    for p in ok:
        key = (str(p.get("family", "")), str(p.get("table", "")), str(p.get("chain", "")))
        groups[key].append(p)
    lines = ["flowchart TB"]
    max_groups = 14
    max_nodes = 22
    keys = sorted(groups.keys())[:max_groups]
    nid = 0
    for fam, tbl, ch in keys:
        rules = sorted(
            groups[(fam, tbl, ch)],
            key=lambda x: (int(x.get("priority", 0) or 0), str(x.get("raw", ""))),
        )
        total = len(rules)
        truncated = rules[max_nodes:]
        rules = rules[:max_nodes]
        sg_id = _mid(f"dir_{fam}_{tbl}_{ch}")
        title = _mermaid_label(f"{fam} / {tbl} / {ch}（共 {total} 條）")
        lines.append(f'  subgraph {sg_id}["{title}"]')
        lines.append("    direction TB")
        prev: Optional[str] = None
        for p in rules:
            toks = p.get("tokens") or []
            tail = " ".join(str(t) for t in toks) if isinstance(toks, list) else ""
            lbl = _mermaid_label(f"{p.get('priority', '?')}: {tail}")
            node = f"DR{nid}"
            nid += 1
            lines.append(f'    {node}["{lbl}"]')
            if prev:
                lines.append(f"    {prev} --> {node}")
            prev = node
        if truncated:
            node = f"DR{nid}"
            nid += 1
            lines.append(f'    {node}["{_mermaid_label(f"… 另有 {len(truncated)} 條未畫出")}"]')
            if prev:
                lines.append(f"    {prev} --> {node}")
        lines.append("  end")
    if len(groups) > max_groups:
        lines.append(f'  DMORE["{_mermaid_label(f"… 另有 {len(groups) - max_groups} 組 chain 未畫出")}"]')
    return "\n".join(lines)


def _direct_table_html(parsed: Sequence[Mapping[str, Any]]) -> str:
    if not parsed:
        return "<p class=\"muted\">（無）</p>"
    rows: List[str] = []
    limit = 250
    for p in parsed[:limit]:
        if not p.get("parse_error"):
            toks = p.get("tokens") or []
            rule = " ".join(str(t) for t in toks) if isinstance(toks, list) else ""
            row = (
                f"<tr><td>{p.get('priority', '')}</td>"
                f"<td>{_esc(str(p.get('family', '')))}</td>"
                f"<td>{_esc(str(p.get('table', '')))}</td>"
                f"<td>{_esc(str(p.get('chain', '')))}</td>"
                f"<td>{_esc(rule)}</td></tr>"
            )
        else:
            row = (
                f"<tr><td colspan=\"5\" class=\"muted\">"
                f"無法解析：{_esc(str(p.get('raw', '')))}</td></tr>"
            )
        rows.append(row)
    more = ""
    if len(parsed) > limit:
        more = f"<p class=\"muted\">… 表格僅顯示前 {limit} 筆</p>"
    thead = (
        "<thead><tr><th>prio</th><th>family</th><th>table</th><th>chain</th><th>rule</th></tr></thead>"
    )
    return f"<table>{thead}<tbody>{''.join(rows)}</tbody></table>{more}"


def _direct_raw_block(snapshot: Mapping[str, Any]) -> str:
    rules = snapshot.get("direct_rules") or []
    if not isinstance(rules, list) or not rules:
        return ""
    lines = "\n".join(_esc(str(r)) for r in rules[:200])
    more = ""
    if len(rules) > 200:
        more = f"<p class=\"muted\">… 其餘 {len(rules) - 200} 行略</p>"
    return (
        "<details><summary>原始 <code>--get-all-rules</code> 行</summary>"
        f"<pre>{lines}</pre>{more}</details>"
    )


def generate_html_report(snapshot: Mapping[str, Any]) -> str:
    """Full HTML document with embedded Mermaid (CDN) + drift + ipset + direct."""
    title = "fwctl 防火牆快照"
    gen = _esc(str(snapshot.get("generated_at", "")))
    backend = _esc(str(snapshot.get("backend", "")))
    ver = snapshot.get("schema_version", "")
    diagram = _mermaid_topology(snapshot)
    diagram_html = _esc(diagram)
    drift_html = _drift_table(snapshot)
    parsed = _direct_parsed(snapshot)
    direct_mermaid = _esc(_mermaid_direct_chains(parsed))
    ipset_overlap = _esc(_mermaid_ipset_name_overlap(snapshot))

    return f"""<!DOCTYPE html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{_esc(title)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 1.5rem; line-height: 1.45; }}
    h1, h2 {{ line-height: 1.2; }}
    .muted {{ color: #666; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.9rem; }}
    th, td {{ border: 1px solid #ccc; padding: 0.35rem 0.5rem; vertical-align: top; }}
    th {{ background: #f4f4f4; }}
    pre {{ background: #f8f8f8; padding: 0.75rem; overflow: auto; max-height: 24rem; }}
    .mermaid {{ margin: 1rem 0; }}
  </style>
</head>
<body>
  <h1>{_esc(title)}</h1>
  <p>產生時間：<code>{gen}</code> · 後端：<code>{backend}</code> · schema：<code>{_esc(str(ver))}</code></p>

  <h2>Zone／介面拓樸（Mermaid）</h2>
  <p class="muted">有 runtime 時以 runtime 為準；否則使用 permanent。需可連至 CDN 載入 Mermaid。</p>
  <pre class="mermaid">{diagram_html}</pre>

  <h2>Runtime vs Permanent（services／ports drift）</h2>
  {drift_html}

  <h2>ipset 名稱與條目</h2>
  {_ipset_name_lines(snapshot)}
  <h3>名稱分布（Mermaid）</h3>
  <pre class="mermaid">{ipset_overlap}</pre>
  {_ipset_detail_tables(snapshot)}

  <h2>Direct 規則</h2>
  <p class="muted">圖示依 family／table／chain 分組，組內依 priority 串接（<strong>不代表</strong> netfilter 實際跳轉順序；除錯請對照原始行與 nft／iptables）。</p>
  <h3>Direct 流程概覽（Mermaid）</h3>
  <pre class="mermaid">{direct_mermaid}</pre>
  <h3>Direct 結構化表格</h3>
  {_direct_table_html(parsed)}
  {_direct_raw_block(snapshot)}

  <script type="module">
    import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";
    mermaid.initialize({{ startOnLoad: false, securityLevel: "strict", flowchart: {{ htmlLabels: false }} }});
    const nodes = document.querySelectorAll(".mermaid");
    if (nodes.length) await mermaid.run({{ nodes: [...nodes] }});
  </script>
</body>
</html>
"""


def html_report_from_json_text(text: str) -> str:
    snap = json.loads(text)
    if not isinstance(snap, dict):
        raise ValueError("snapshot JSON 必須為 object")
    return generate_html_report(snap)
