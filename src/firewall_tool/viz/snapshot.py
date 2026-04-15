"""Collect firewalld state into a JSON-serializable snapshot for visualization."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from firewall_tool.formatters import split_space_list
from firewall_tool.runner import (
    FirewallCmdError,
    backend_name,
    is_offline,
    run_firewall_cmd,
)
from firewall_tool.viz.ip_compact import build_ipset_compact_fields
from firewall_tool.viz.network_allow_extract import build_direct_allow_matrix

SCHEMA_VERSION = 2

# ipset 詳情寫入快照時，避免 JSON／HTML 過大。
_MAX_IPSET_INFO_CHARS = 4000
_MAX_IPSET_ENTRIES = 64

# Keys whose values are typically space-separated tokens in `firewall-cmd --list-all-zones`.
_LIST_KEYS = frozenset(
    {
        "interfaces",
        "sources",
        "services",
        "ports",
        "protocols",
        "forward-ports",
        "source-ports",
        "icmp-blocks",
        "helpers",
    }
)


def parse_list_all_zones(text: str) -> List[Dict[str, Any]]:
    """
    Parse `firewall-cmd [--permanent] --list-all-zones` into a list of zone dicts:

    - name, active (bool)
    - attributes: scalar keys -> str; list keys -> list[str]
    - rich_rules: list[str]
    """
    zones: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    collecting_rich = False
    rich_lines: List[str] = []

    def flush_zone() -> None:
        nonlocal current, collecting_rich, rich_lines
        if current is None:
            return
        current["rich_rules"] = [ln for ln in rich_lines if ln.strip()]
        zones.append(current)
        current = None
        collecting_rich = False
        rich_lines = []

    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        if not line[0].isspace():
            flush_zone()
            name, active = _parse_zone_header(line)
            current = {"name": name, "active": active, "attributes": {}, "rich_rules": []}
            collecting_rich = False
            rich_lines = []
            continue
        if current is None:
            continue
        if collecting_rich:
            rich_lines.append(line.strip())
            continue
        stripped = line.strip()
        if stripped.lower().startswith("rich rules:"):
            collecting_rich = True
            tail = stripped.split(":", 1)[1].strip()
            if tail:
                rich_lines.append(tail)
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        attrs: Dict[str, Any] = current["attributes"]
        if key in _LIST_KEYS:
            attrs[key] = split_space_list(value) if value else []
        else:
            attrs[key] = value

    flush_zone()
    return zones


_ZONE_HEADER_RE = re.compile(r"^(\S+)\s*(?:\(active\))?\s*$")


def _parse_zone_header(line: str) -> Tuple[str, bool]:
    line = line.strip()
    if line.endswith("(active)"):
        base = line[: -len("(active)")].strip()
        return base, True
    m = _ZONE_HEADER_RE.match(line)
    if m:
        return m.group(1), False
    return line.split()[0], False


def _zone_by_name(zones: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {str(z["name"]): z for z in zones}


def _sorted_tokens(attrs: Mapping[str, Any], key: str) -> List[str]:
    raw = attrs.get(key)
    if raw is None:
        return []
    if isinstance(raw, list):
        return sorted(str(x) for x in raw)
    if isinstance(raw, str) and raw.strip():
        return sorted(split_space_list(raw))
    return []


def _rich_rules_list(zone: Mapping[str, Any]) -> List[str]:
    rr = zone.get("rich_rules") or []
    if not isinstance(rr, list):
        return []
    norm = [" ".join(str(x).split()) for x in rr if str(x).strip()]
    return sorted(norm)


def compute_zone_drift(
    runtime_zones: Sequence[Mapping[str, Any]],
    permanent_zones: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Per-zone set diffs for common attributes (MVP for services/ports/etc.)."""
    rt = _zone_by_name(runtime_zones)
    pm = _zone_by_name(permanent_zones)
    names = sorted(set(rt) | set(pm))
    compare_keys = [
        "services",
        "ports",
        "interfaces",
        "sources",
        "protocols",
        "forward-ports",
        "source-ports",
        "icmp-blocks",
    ]
    scalar_keys = ["target", "masquerade", "forward", "icmp-block-inversion"]
    out: Dict[str, Any] = {}
    for name in names:
        zr = rt.get(name, {})
        zp = pm.get(name, {})
        ar = zr.get("attributes") or {}
        ap = zp.get("attributes") or {}
        if not isinstance(ar, dict):
            ar = {}
        if not isinstance(ap, dict):
            ap = {}
        key_entry: Dict[str, Any] = {"lists": {}, "scalars": {}, "rich_rules": {}}
        for k in compare_keys:
            a = set(_sorted_tokens(ar, k))
            b = set(_sorted_tokens(ap, k))
            key_entry["lists"][k] = {
                "only_runtime": sorted(a - b),
                "only_permanent": sorted(b - a),
                "both": sorted(a & b),
            }
        for k in scalar_keys:
            vr = str(ar.get(k, ""))
            vp = str(ap.get(k, ""))
            key_entry["scalars"][k] = {
                "runtime": vr,
                "permanent": vp,
                "match": vr == vp,
            }
        r_rules = set(_rich_rules_list(zr))
        p_rules = set(_rich_rules_list(zp))
        key_entry["rich_rules"] = {
            "only_runtime": sorted(r_rules - p_rules),
            "only_permanent": sorted(p_rules - r_rules),
            "both": sorted(r_rules & p_rules),
        }
        out[name] = key_entry
    return {"zones": out}


def _get_zones_blob(*, permanent: bool) -> str:
    args = ["--permanent", "--list-all-zones"] if permanent else ["--list-all-zones"]
    return run_firewall_cmd(args, check=True).stdout


def _get_ipset_names(*, permanent: bool) -> List[str]:
    args = ["--permanent", "--get-ipsets"] if permanent else ["--get-ipsets"]
    out = run_firewall_cmd(args, check=True).stdout
    return split_space_list(out)


def _get_direct_rules() -> List[str]:
    res = run_firewall_cmd(["--direct", "--get-all-rules"], check=True)
    lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    return lines


def _perm_args(permanent: bool) -> List[str]:
    return ["--permanent"] if permanent else []


def _looks_like_ipset_entry_token(tok: str) -> bool:
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
    if not all(_looks_like_ipset_entry_token(p) for p in parts):
        return lines
    return parts


def parse_direct_rule_line(line: str) -> Dict[str, Any]:
    """Parse `firewall-cmd --direct --get-all-rules` 單行；失敗時 `parse_error` 為 True。"""
    raw = line.strip()
    out: Dict[str, Any] = {"raw": raw, "parse_error": True}
    if not raw:
        return out
    try:
        parts = shlex.split(raw)
    except ValueError:
        return out
    if len(parts) < 5:
        return out
    try:
        pri = int(parts[3])
    except ValueError:
        return out
    out["parse_error"] = False
    out["family"] = parts[0]
    out["table"] = parts[1]
    out["chain"] = parts[2]
    out["priority"] = pri
    out["tokens"] = parts[4:]
    return out


def _ipset_one_detail(name: str, *, permanent: bool) -> Dict[str, Any]:
    row: Dict[str, Any] = {"name": name}
    try:
        info = run_firewall_cmd(
            [*_perm_args(permanent), f"--info-ipset={name}"],
            check=True,
        ).stdout.strip()
        if len(info) > _MAX_IPSET_INFO_CHARS:
            row["info"] = info[:_MAX_IPSET_INFO_CHARS] + "\n…（已截斷）"
            row["info_truncated"] = True
        else:
            row["info"] = info
    except FirewallCmdError as e:
        row["info"] = ""
        row["info_error"] = str(e).strip() or "query failed"

    try:
        raw_ent = run_firewall_cmd(
            [*_perm_args(permanent), f"--ipset={name}", "--get-entries"],
            check=True,
        ).stdout
        entries = _parse_ipset_entries_stdout(raw_ent)
    except FirewallCmdError as e:
        entries = []
        row["entries_error"] = str(e).strip() or "query failed"

    row["entries_total"] = len(entries)
    row["entries_truncated"] = len(entries) > _MAX_IPSET_ENTRIES
    row["entries"] = entries[:_MAX_IPSET_ENTRIES]
    row.update(build_ipset_compact_fields(entries))
    return row


def _ipset_details_for_names(names: Sequence[str], *, permanent: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for n in names:
        nm = str(n).strip()
        if not nm:
            continue
        out.append(_ipset_one_detail(nm, permanent=permanent))
    return out


def _get_default_zone() -> str:
    return run_firewall_cmd(["--get-default-zone"], check=True).stdout.strip()


def build_viz_snapshot(*, include_raw: bool = False) -> Dict[str, Any]:
    """
    Query firewall backend and return a dict suitable for `json.dumps`.

    When `is_offline()`, only on-disk config is available: a single zones view
    is stored under ``permanent`` and ``drift_available`` is False.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    snap: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now,
        "backend": backend_name(),
        "default_zone": "",
        "runtime": None,
        "permanent": None,
        "drift_available": False,
        "drift": None,
        "ipsets": {"runtime": [], "permanent": [], "details": {"runtime": [], "permanent": []}},
        "direct_rules": [],
        "direct_rules_parsed": [],
    }

    if is_offline():
        raw_perm = _get_zones_blob(permanent=False)
        zones_perm = parse_list_all_zones(raw_perm)
        snap["default_zone"] = _get_default_zone()
        snap["permanent"] = {
            "zones": zones_perm,
            **({"raw_list_all_zones": raw_perm} if include_raw else {}),
        }
        snap["runtime"] = None
        snap["drift_available"] = False
        snap["drift"] = {"note": "offline 模式僅磁碟設定，無 runtime／permanent 對照。"}
        try:
            snap["ipsets"]["permanent"] = _get_ipset_names(permanent=False)
        except FirewallCmdError:
            snap["ipsets"]["permanent"] = []
        snap["ipsets"]["runtime"] = []
        snap["ipsets"]["details"] = {
            "runtime": [],
            "permanent": _ipset_details_for_names(snap["ipsets"]["permanent"], permanent=False),
        }
    else:
        raw_rt = _get_zones_blob(permanent=False)
        raw_pm = _get_zones_blob(permanent=True)
        zones_rt = parse_list_all_zones(raw_rt)
        zones_pm = parse_list_all_zones(raw_pm)
        snap["default_zone"] = _get_default_zone()
        snap["runtime"] = {
            "zones": zones_rt,
            **({"raw_list_all_zones": raw_rt} if include_raw else {}),
        }
        snap["permanent"] = {
            "zones": zones_pm,
            **({"raw_list_all_zones": raw_pm} if include_raw else {}),
        }
        snap["drift_available"] = True
        snap["drift"] = compute_zone_drift(zones_rt, zones_pm)
        try:
            snap["ipsets"]["runtime"] = _get_ipset_names(permanent=False)
        except FirewallCmdError:
            snap["ipsets"]["runtime"] = []
        try:
            snap["ipsets"]["permanent"] = _get_ipset_names(permanent=True)
        except FirewallCmdError:
            snap["ipsets"]["permanent"] = []
        snap["ipsets"]["details"] = {
            "runtime": _ipset_details_for_names(snap["ipsets"]["runtime"], permanent=False),
            "permanent": _ipset_details_for_names(snap["ipsets"]["permanent"], permanent=True),
        }

    try:
        snap["direct_rules"] = _get_direct_rules()
    except FirewallCmdError:
        snap["direct_rules"] = []

    snap["direct_rules_parsed"] = [parse_direct_rule_line(str(ln)) for ln in snap["direct_rules"]]
    snap["direct_allow_matrix"] = build_direct_allow_matrix(snap)

    return snap


def snapshot_to_json(snapshot: Mapping[str, Any], *, indent: int = 2) -> str:
    return json.dumps(snapshot, indent=indent, ensure_ascii=False)
