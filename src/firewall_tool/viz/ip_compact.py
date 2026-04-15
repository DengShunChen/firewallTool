"""Condense ipset-style IP lists: same-/24 hosts -> a.b.c.[x,y] or a.b.c.[x-y]."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Sequence, Tuple

# 合併運算最多餵入筆數，避免極大 ipset 卡死。
_MAX_INPUT_FOR_COLLAPSE = 20000
# JSON／預覽最多保留幾段合併後字串。
_MAX_COMPACT_STRINGS = 40


def _runs_to_bracket_inner(last_octets: Sequence[int]) -> str:
    """
    末位元組排序去重後濃縮為方括號內字串。

    - 連續 3 個以上：`a-b`
    - 連續 2 個：`a,b`（符合 172.16.90.[1,2]）
    - 單一：`a`
    """
    nums = sorted(set(last_octets))
    if not nums:
        return ""
    parts: List[str] = []
    i = 0
    while i < len(nums):
        start = nums[i]
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        end = nums[j]
        span = j - i + 1
        if span == 1:
            parts.append(str(start))
        elif span == 2:
            parts.append(f"{start},{end}")
        else:
            parts.append(f"{start}-{end}")
        i = j + 1
    return ",".join(parts)


def _bracket_strings_for_ipv4_hosts(hosts: Sequence[ipaddress.IPv4Address]) -> List[str]:
    """同一前綴 /24 分組 -> ``172.16.90.[1,2]``；單一主機維持 ``172.16.90.1``。"""
    groups: Dict[Tuple[int, int, int], List[int]] = {}
    for h in hosts:
        o = h.packed
        key = (o[0], o[1], o[2])
        groups.setdefault(key, []).append(o[3])
    out: List[str] = []
    for a, b, c in sorted(groups.keys()):
        lasts = groups[(a, b, c)]
        uniq = sorted(set(lasts))
        if len(uniq) == 1:
            out.append(f"{a}.{b}.{c}.{uniq[0]}")
        else:
            inner = _runs_to_bracket_inner(uniq)
            out.append(f"{a}.{b}.{c}.[{inner}]")
    return out


def collapse_ip_tokens(tokens: Sequence[str]) -> Tuple[List[str], List[str]]:
    """
    濃縮條目字串列表。

    - IPv4 **主機**（無 slash 或 /32）：同一 /24 合併為 ``a.b.c.[…]``；單機維持四段式。
    - IPv4 **其它 prefix** 的 CIDR：``ipaddress.collapse_addresses``。
    - IPv6：CIDR 合併（含單位址視為 /128）。
    - 無法解析：原字串保留（第二個回傳值亦為該集合，供呼叫端參考）。
    """
    v4_hosts: List[ipaddress.IPv4Address] = []
    v4_nets: List[ipaddress.IPv4Network] = []
    v6_nets: List[ipaddress.IPv6Network] = []
    other: List[str] = []

    for raw in tokens:
        t = str(raw).strip()
        if not t:
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if net.version == 4:
                if net.prefixlen == 32:
                    v4_hosts.append(ipaddress.IPv4Address(net.network_address))
                else:
                    v4_nets.append(net)
            else:
                v6_nets.append(net)
            continue
        try:
            addr = ipaddress.ip_address(t)
        except ValueError:
            other.append(t)
            continue
        if addr.version == 4:
            v4_hosts.append(ipaddress.IPv4Address(addr))
        else:
            v6_nets.append(ipaddress.ip_network((addr, 128), strict=False))

    out: List[str] = []
    out.extend(_bracket_strings_for_ipv4_hosts(v4_hosts))
    if v4_nets:
        out.extend(str(x) for x in ipaddress.collapse_addresses(sorted(v4_nets)))
    if v6_nets:
        out.extend(str(x) for x in ipaddress.collapse_addresses(sorted(v6_nets)))
    out.extend(other)
    return out, list(other)


def build_ipset_compact_fields(entries: Sequence[str]) -> Dict[str, Any]:
    """
    由完整條目列表產出濃縮欄位，供 `ipsets.details` 寫入。

    - ``entries_compact``：濃縮後前 N 段字串（含 ``a.b.c.[1,2]`` 形式）
    - ``entries_compact_total``：濃縮後總段數（在餵入上限內）
    - ``entries_summary``：一行中文摘要，供 HTML 直接使用
    """
    raw_list = [str(x).strip() for x in entries if str(x).strip()]
    total_raw = len(raw_list)
    if not raw_list:
        return {
            "entries_compact": [],
            "entries_compact_total": 0,
            "entries_compact_truncated": False,
            "entries_collapse_input_capped": False,
            "entries_summary": "（無條目）",
        }
    capped = total_raw > _MAX_INPUT_FOR_COLLAPSE
    to_proc = raw_list[:_MAX_INPUT_FOR_COLLAPSE] if capped else raw_list
    collapsed, _other = collapse_ip_tokens(to_proc)
    full_len = len(collapsed)
    stored = collapsed[:_MAX_COMPACT_STRINGS]
    store_trunc = full_len > len(stored)

    preview = ", ".join(stored[:12])
    if len(stored) > 12 or store_trunc:
        preview += " …"
    note_parts = [f"濃縮後 {full_len} 段", f"原始 {total_raw} 筆"]
    if capped:
        note_parts.append(f"濃縮僅以前 {_MAX_INPUT_FOR_COLLAPSE} 筆為準")
    summary = f"{preview}（{'；'.join(note_parts)}）" if preview.strip() else "（無可濃縮條目）"

    return {
        "entries_compact": stored,
        "entries_compact_total": full_len,
        "entries_compact_truncated": store_trunc,
        "entries_collapse_input_capped": capped,
        "entries_summary": summary,
    }
