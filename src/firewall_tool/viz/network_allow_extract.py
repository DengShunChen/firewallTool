"""從 direct 規則與 ipset 快照整理 INPUT／OUTPUT（等）允許型規則摘要（僅最佳努力解析）。"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence


def _jump_target(tokens: Sequence[str]) -> Optional[str]:
    for i in range(len(tokens) - 1):
        if tokens[i] == "-j":
            return tokens[i + 1]
    return None


def _extend_ports(blob: str, bucket: List[str]) -> None:
    for p in blob.replace(" ", "").split(","):
        if p:
            bucket.append(p)


def extract_direct_tokens_semantics(tokens: Sequence[str]) -> Dict[str, Any]:
    """
    從 iptables 風格 token 列表掃描常見欄位（不完整 iptables 語意）。

    回傳鍵：``proto``, ``sources``, ``dests``, ``sports``, ``dports``,
    ``in_if``, ``out_if``, ``ipset_matches``（``{name, direction}`` 列表）。
    """
    sources: List[str] = []
    dests: List[str] = []
    sports: List[str] = []
    dports: List[str] = []
    in_if: List[str] = []
    out_if: List[str] = []
    ipset_matches: List[Dict[str, str]] = []
    proto: Optional[str] = None

    toks = [str(x) for x in tokens]
    n = len(toks)
    i = 0
    while i < n:
        t = toks[i]
        if t == "!" and i + 2 < n and toks[i + 1] == "-s":
            sources.append(f"! {toks[i + 2]}")
            i += 3
            continue
        if t == "!" and i + 2 < n and toks[i + 1] == "-d":
            dests.append(f"! {toks[i + 2]}")
            i += 3
            continue
        if t == "-s" and i + 1 < n:
            sources.append(toks[i + 1])
            i += 2
            continue
        if t == "-d" and i + 1 < n:
            dests.append(toks[i + 1])
            i += 2
            continue
        if t == "-p" and i + 1 < n:
            proto = toks[i + 1]
            i += 2
            continue
        if t in ("--dport", "--destination-port") and i + 1 < n:
            dports.append(toks[i + 1])
            i += 2
            continue
        if t in ("--sport", "--source-port") and i + 1 < n:
            sports.append(toks[i + 1])
            i += 2
            continue
        if t == "--dports" and i + 1 < n:
            _extend_ports(toks[i + 1], dports)
            i += 2
            continue
        if t == "--sports" and i + 1 < n:
            _extend_ports(toks[i + 1], sports)
            i += 2
            continue
        if t == "-i" and i + 1 < n:
            in_if.append(toks[i + 1])
            i += 2
            continue
        if t == "-o" and i + 1 < n:
            out_if.append(toks[i + 1])
            i += 2
            continue
        if t == "-m" and i + 1 < n:
            mod = toks[i + 1]
            i += 2
            if mod == "set" and i + 2 < n and toks[i] == "--match-set":
                ipset_matches.append({"name": toks[i + 1], "direction": toks[i + 2]})
                i += 3
                continue
            continue
        i += 1

    return {
        "proto": proto,
        "sources": sources,
        "dests": dests,
        "sports": sports,
        "dports": dports,
        "in_if": in_if,
        "out_if": out_if,
        "ipset_matches": ipset_matches,
    }


def build_ipset_summary_lookup(snapshot: Mapping[str, Any]) -> Dict[str, str]:
    """ipset 名稱 -> 濃縮摘要（優先 runtime，其次 permanent）。"""
    out: Dict[str, str] = {}
    ips = snapshot.get("ipsets") or {}
    if not isinstance(ips, dict):
        return out
    det = ips.get("details")
    if not isinstance(det, dict):
        return out
    for side in ("permanent", "runtime"):
        rows = det.get(side) or []
        if not isinstance(rows, list):
            continue
        for r in rows:
            if not isinstance(r, dict):
                continue
            name = str(r.get("name") or "").strip()
            if not name:
                continue
            summ = str(r.get("entries_summary") or "").strip()
            if not summ:
                comp = r.get("entries_compact")
                if isinstance(comp, list) and comp:
                    summ = ", ".join(str(x) for x in comp[:6])
                    if len(comp) > 6:
                        summ += " …"
            out[name] = summ or "（無摘要）"
    return out


def build_direct_allow_matrix(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """
    整理 ``-j ACCEPT`` 的 direct 規則，依 chain 分 INPUT／OUTPUT／FORWARD／其它。

    每列含語意欄位與 ``ipset_resolved``（對照本快照 ``ipsets.details``）。
    """
    lookup = build_ipset_summary_lookup(snapshot)
    parsed = snapshot.get("direct_rules_parsed")
    if not isinstance(parsed, list):
        parsed = []

    buckets: MutableMapping[str, List[Dict[str, Any]]] = {
        "input": [],
        "output": [],
        "forward": [],
        "other": [],
    }
    stats = {"accept_rows": 0, "skipped_non_accept": 0, "skipped_parse_error": 0}

    for pr in parsed:
        if not isinstance(pr, dict):
            continue
        if pr.get("parse_error"):
            stats["skipped_parse_error"] += 1
            continue
        toks = pr.get("tokens") or []
        if not isinstance(toks, list):
            toks = []
        stoks = [str(x) for x in toks]
        tgt = _jump_target(stoks)
        if tgt != "ACCEPT":
            stats["skipped_non_accept"] += 1
            continue

        sem = extract_direct_tokens_semantics(stoks)
        chain_u = str(pr.get("chain") or "").upper()
        if chain_u == "INPUT":
            key = "input"
        elif chain_u == "OUTPUT":
            key = "output"
        elif chain_u == "FORWARD":
            key = "forward"
        else:
            key = "other"

        ipset_resolved: List[Dict[str, str]] = []
        for m in sem.get("ipset_matches") or []:
            if not isinstance(m, dict):
                continue
            nm = str(m.get("name") or "").strip()
            if not nm:
                continue
            ipset_resolved.append(
                {
                    "name": nm,
                    "direction": str(m.get("direction") or ""),
                    "entries_summary": lookup.get(nm, "（快照內無此 ipset 詳情）"),
                }
            )

        row = {
            "family": str(pr.get("family") or ""),
            "table": str(pr.get("table") or ""),
            "chain": str(pr.get("chain") or ""),
            "priority": pr.get("priority"),
            "proto": sem.get("proto"),
            "sources": sem.get("sources") or [],
            "destinations": sem.get("dests") or [],
            "sports": sem.get("sports") or [],
            "dports": sem.get("dports") or [],
            "in_interfaces": sem.get("in_if") or [],
            "out_interfaces": sem.get("out_if") or [],
            "ipset_matches": sem.get("ipset_matches") or [],
            "ipset_resolved": ipset_resolved,
            "raw": str(pr.get("raw") or ""),
        }
        buckets[key].append(row)
        stats["accept_rows"] += 1

    for k in buckets:
        buckets[k].sort(key=lambda r: (int(r.get("priority") or 0), str(r.get("raw") or "")))

    return {
        "note": (
            "僅掃描 ``-j ACCEPT`` 且 ``parse_error=false`` 的 direct 規則；"
            "常見 ``-s/-d/-p/--dport/--sport/--dports/--sports`` 與 ``-m set --match-set``。"
            "非完整 iptables／nft 語意，若有自訂 match 可能漏欄。"
        ),
        "stats": stats,
        "input": buckets["input"],
        "output": buckets["output"],
        "forward": buckets["forward"],
        "other": buckets["other"],
    }


def allow_matrix_from_snapshot_dict(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """若快照已含 ``direct_allow_matrix`` 則沿用，否則即時計算（供僅 JSON 的 HTML 輸入）。"""
    existing = snapshot.get("direct_allow_matrix")
    if isinstance(existing, dict) and existing.get("input") is not None:
        return existing
    return build_direct_allow_matrix(snapshot)
