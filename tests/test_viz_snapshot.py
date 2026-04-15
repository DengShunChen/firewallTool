"""Tests for viz snapshot parsing, drift, and CLI."""

from __future__ import annotations

import json
import unittest.mock as mock

import pytest
from typer.testing import CliRunner

from firewall_tool.main import app
from firewall_tool.runner import RunResult, set_use_offline
from firewall_tool.viz.html_report import generate_html_report
from firewall_tool.viz.markdown_report import generate_markdown_report
from firewall_tool.viz.ip_compact import build_ipset_compact_fields, collapse_ip_tokens
from firewall_tool.viz.network_allow_extract import (
    build_direct_allow_matrix,
    extract_direct_tokens_semantics,
)
from firewall_tool.viz.snapshot import (
    compute_zone_drift,
    parse_direct_rule_line,
    parse_list_all_zones,
    snapshot_to_json,
)


SAMPLE_LIST_ALL_ZONES = """
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: ssh http
  ports: 8080/tcp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
\trule family="ipv4" source address="10.0.0.1" accept
home
  target: default
  interfaces: eth1
  services: dhcpv6-client
  ports:
  rich rules:
"""


def test_extract_direct_tokens_semantics_multiport() -> None:
    sem = extract_direct_tokens_semantics(
        ["-m", "multiport", "--dports", "80,443", "-p", "tcp", "-j", "ACCEPT"]
    )
    assert "80" in sem["dports"] and "443" in sem["dports"]


def test_direct_allow_matrix_resolves_ipset() -> None:
    snap = {
        "direct_rules_parsed": [
            {
                "raw": "ipv4 filter INPUT 0 -m set --match-set wl src -p tcp --dport 443 -j ACCEPT",
                "parse_error": False,
                "family": "ipv4",
                "table": "filter",
                "chain": "INPUT",
                "priority": 0,
                "tokens": [
                    "-m",
                    "set",
                    "--match-set",
                    "wl",
                    "src",
                    "-p",
                    "tcp",
                    "--dport",
                    "443",
                    "-j",
                    "ACCEPT",
                ],
            }
        ],
        "ipsets": {
            "details": {
                "runtime": [{"name": "wl", "entries_summary": "摘要測試", "entries_compact": ["1.1.1.1"]}],
                "permanent": [],
            }
        },
    }
    m = build_direct_allow_matrix(snap)
    assert len(m["input"]) == 1
    assert m["input"][0]["dports"] == ["443"]
    assert m["input"][0]["ipset_resolved"][0]["name"] == "wl"
    assert "摘要測試" in m["input"][0]["ipset_resolved"][0]["entries_summary"]


def test_bracket_two_hosts() -> None:
    xs, _ = collapse_ip_tokens(["172.16.90.1", "172.16.90.2"])
    assert xs == ["172.16.90.[1,2]"]


def test_bracket_slash24_hosts() -> None:
    d = build_ipset_compact_fields([f"10.0.0.{i}" for i in range(256)])
    assert d["entries_compact_total"] == 1
    assert d["entries_compact"][0] == "10.0.0.[0-255]"
    assert "原始 256 筆" in d["entries_summary"]


def test_single_host_plain() -> None:
    xs, _ = collapse_ip_tokens(["10.0.0.5"])
    assert xs == ["10.0.0.5"]


def test_parse_direct_rule_line() -> None:
    p = parse_direct_rule_line('ipv4 filter INPUT 0 -j ACCEPT')
    assert p["parse_error"] is False
    assert p["family"] == "ipv4"
    assert p["table"] == "filter"
    assert p["chain"] == "INPUT"
    assert p["priority"] == 0
    assert p["tokens"] == ["-j", "ACCEPT"]
    bad = parse_direct_rule_line("not enough tokens")
    assert bad["parse_error"] is True


def test_parse_list_all_zones_basic() -> None:
    zones = parse_list_all_zones(SAMPLE_LIST_ALL_ZONES)
    assert len(zones) == 2
    pub = zones[0]
    assert pub["name"] == "public"
    assert pub["active"] is True
    attrs = pub["attributes"]
    assert attrs["services"] == ["ssh", "http"]
    assert attrs["ports"] == ["8080/tcp"]
    assert attrs["interfaces"] == ["eth0"]
    assert len(pub["rich_rules"]) == 1
    assert "10.0.0.1" in pub["rich_rules"][0]
    home = zones[1]
    assert home["name"] == "home"
    assert home["active"] is False
    assert home["attributes"]["services"] == ["dhcpv6-client"]


def test_compute_zone_drift_services_ports() -> None:
    rt = parse_list_all_zones(
        """
public (active)
  services: ssh
  ports: 80/tcp
  interfaces:
  rich rules:
"""
    )
    pm = parse_list_all_zones(
        """
public (active)
  services: ssh http
  ports: 80/tcp 443/tcp
  interfaces:
  rich rules:
"""
    )
    drift = compute_zone_drift(rt, pm)
    z = drift["zones"]["public"]
    assert z["lists"]["services"]["only_runtime"] == []
    assert z["lists"]["services"]["only_permanent"] == ["http"]
    assert z["lists"]["ports"]["only_permanent"] == ["443/tcp"]


def test_generate_markdown_report_offline_snapshot() -> None:
    snap = {
        "schema_version": 2,
        "generated_at": "2026-01-01T00:00:00Z",
        "backend": "firewall-offline-cmd",
        "default_zone": "public",
        "runtime": None,
        "permanent": {
            "zones": [
                {
                    "name": "public",
                    "active": False,
                    "attributes": {"services": ["ssh"], "interfaces": ["eth0"]},
                    "rich_rules": [],
                }
            ]
        },
        "drift_available": False,
        "drift": {"note": "offline 模式僅磁碟設定，無 runtime／permanent 對照。"},
        "ipsets": {"runtime": [], "permanent": ["x"], "details": {"runtime": [], "permanent": []}},
        "direct_rules": [],
        "direct_rules_parsed": [],
    }
    md = generate_markdown_report(snap)
    assert "防火牆快照" in md
    assert "```mermaid" in md
    assert "offline" in md


def test_generate_html_offline_drift_message() -> None:
    snap = {
        "schema_version": 1,
        "generated_at": "2026-01-01T00:00:00Z",
        "backend": "firewall-offline-cmd",
        "default_zone": "public",
        "runtime": None,
        "permanent": {
            "zones": [
                {
                    "name": "public",
                    "active": False,
                    "attributes": {"services": ["ssh"], "interfaces": ["eth0"]},
                    "rich_rules": [],
                }
            ]
        },
        "drift_available": False,
        "drift": {"note": "offline 模式僅磁碟設定，無 runtime／permanent 對照。"},
        "ipsets": {"runtime": [], "permanent": ["blocklist"], "details": {"runtime": [], "permanent": []}},
        "direct_rules": [],
        "direct_rules_parsed": [],
    }
    html = generate_html_report(snap)
    assert "Mermaid" in html
    assert "offline" in html
    assert "blocklist" in html
    assert "預設 zone: public" in html
    assert "名稱分布（Mermaid）" in html
    assert "Direct 允許流量摘要" in html


def test_snapshot_to_json_roundtrip_keys() -> None:
    snap = {"schema_version": 1, "generated_at": "t", "backend": "x", "drift_available": False}
    out = snapshot_to_json(snap)
    data = json.loads(out)
    assert data["schema_version"] == 1


@mock.patch("firewall_tool.viz.snapshot.run_firewall_cmd")
def test_build_viz_snapshot_online(mock_run: mock.MagicMock) -> None:
    set_use_offline(False)

    def side_effect(args: object, **kwargs: object) -> RunResult:
        a = list(args)
        if a == ["--list-all-zones"]:
            return RunResult(
                stdout='public (active)\n  services: ssh\n  interfaces:\n  rich rules:\n',
                stderr="",
                code=0,
                argv=[],
            )
        if a == ["--permanent", "--list-all-zones"]:
            return RunResult(
                stdout='public (active)\n  services: ssh http\n  interfaces:\n  rich rules:\n',
                stderr="",
                code=0,
                argv=[],
            )
        if a == ["--get-default-zone"]:
            return RunResult(stdout="public\n", stderr="", code=0, argv=[])
        if a == ["--get-ipsets"]:
            return RunResult(stdout="a b\n", stderr="", code=0, argv=[])
        if a == ["--permanent", "--get-ipsets"]:
            return RunResult(stdout="a\n", stderr="", code=0, argv=[])
        if a == ["--info-ipset=a"]:
            return RunResult(stdout="a\ntype: hash:ip\n", stderr="", code=0, argv=[])
        if a == ["--ipset=a", "--get-entries"]:
            return RunResult(stdout="10.0.0.1\n", stderr="", code=0, argv=[])
        if a == ["--info-ipset=b"]:
            return RunResult(stdout="b\ntype: hash:net\n", stderr="", code=0, argv=[])
        if a == ["--ipset=b", "--get-entries"]:
            return RunResult(stdout="", stderr="", code=0, argv=[])
        if a == ["--permanent", "--info-ipset=a"]:
            return RunResult(stdout="a\ntype: hash:ip\n", stderr="", code=0, argv=[])
        if a == ["--permanent", "--ipset=a", "--get-entries"]:
            return RunResult(stdout="10.0.0.2\n", stderr="", code=0, argv=[])
        if a == ["--direct", "--get-all-rules"]:
            return RunResult(
                stdout=(
                    "ipv4 filter INPUT 0 -p tcp -m tcp --dport 22 -j ACCEPT\n"
                    "ipv4 filter INPUT 10 -s 192.168.0.0/24 -j DROP\n"
                ),
                stderr="",
                code=0,
                argv=[],
            )
        raise AssertionError(f"unexpected argv: {a!r}")

    mock_run.side_effect = side_effect
    from firewall_tool.viz.snapshot import build_viz_snapshot

    snap = build_viz_snapshot(include_raw=False)
    assert snap["drift_available"] is True
    assert snap["schema_version"] == 2
    assert snap["drift"]["zones"]["public"]["lists"]["services"]["only_permanent"] == ["http"]
    assert snap["ipsets"]["runtime"] == ["a", "b"]
    assert len(snap["ipsets"]["details"]["runtime"]) == 2
    assert snap["ipsets"]["details"]["runtime"][0]["entries_total"] >= 1
    assert "entries_summary" in snap["ipsets"]["details"]["runtime"][0]
    assert "entries_compact" in snap["ipsets"]["details"]["runtime"][0]
    assert snap["direct_rules_parsed"][0]["parse_error"] is False
    assert snap["direct_rules_parsed"][0]["chain"] == "INPUT"
    assert len(snap["direct_allow_matrix"]["input"]) == 1
    assert snap["direct_allow_matrix"]["input"][0]["dports"] == ["22"]
    assert snap["direct_allow_matrix"]["stats"]["skipped_non_accept"] == 1


@mock.patch("firewall_tool.viz.snapshot.run_firewall_cmd")
def test_cli_viz_export_json(mock_run: mock.MagicMock) -> None:
    set_use_offline(False)

    def side_effect(args: object, **kwargs: object) -> RunResult:
        a = list(args)
        if a == ["--list-all-zones"]:
            return RunResult(
                stdout='z1\n  services: a\n  interfaces:\n  rich rules:\n',
                stderr="",
                code=0,
                argv=[],
            )
        if a == ["--permanent", "--list-all-zones"]:
            return RunResult(
                stdout='z1\n  services: a\n  interfaces:\n  rich rules:\n',
                stderr="",
                code=0,
                argv=[],
            )
        if a == ["--get-default-zone"]:
            return RunResult(stdout="z1\n", stderr="", code=0, argv=[])
        if a == ["--get-ipsets"]:
            return RunResult(stdout="\n", stderr="", code=0, argv=[])
        if a == ["--permanent", "--get-ipsets"]:
            return RunResult(stdout="\n", stderr="", code=0, argv=[])
        if a == ["--direct", "--get-all-rules"]:
            return RunResult(stdout="", stderr="", code=0, argv=[])
        raise AssertionError(f"unexpected argv: {a!r}")

    mock_run.side_effect = side_effect
    runner = CliRunner()
    r = runner.invoke(app, ["viz", "export"])
    assert r.exit_code == 0, r.stdout
    data = json.loads(r.stdout)
    assert data["schema_version"] == 2
    assert data["default_zone"] == "z1"
    assert data["direct_rules_parsed"] == []


@pytest.fixture(autouse=True)
def reset_offline() -> None:
    set_use_offline(False)
    yield
    set_use_offline(False)
