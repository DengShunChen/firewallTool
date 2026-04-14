"""Tests for firewall-cmd runner and small parsers."""

from __future__ import annotations

import subprocess
import unittest.mock as mock

import pytest

from firewall_tool.formatters import parse_active_zones
from firewall_tool.runner import FirewallCmdError, run_firewall_cmd


def test_parse_active_zones() -> None:
    sample = """public
  interfaces: eth0
  sources:
docker
  interfaces: br-1234
"""
    rows = parse_active_zones(sample)
    assert rows[0][0] == "public"
    assert "eth0" in rows[0][1]
    assert rows[1][0] == "docker"


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_run_firewall_cmd_success(mock_which: mock.MagicMock, mock_run: mock.MagicMock) -> None:
    mock_which.return_value = "/sbin/firewall-cmd"
    mock_run.return_value = subprocess.CompletedProcess(
        ["/sbin/firewall-cmd", "--state"],
        0,
        stdout="running\n",
        stderr="",
    )
    r = run_firewall_cmd(["--state"], check=True)
    assert r.stdout.strip() == "running"
    mock_run.assert_called_once()
    argv = mock_run.call_args[0][0]
    assert argv[:2] == ["/sbin/firewall-cmd", "--state"]


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_run_firewall_cmd_error(mock_which: mock.MagicMock, mock_run: mock.MagicMock) -> None:
    mock_which.return_value = "/sbin/firewall-cmd"
    mock_run.return_value = subprocess.CompletedProcess(
        ["/sbin/firewall-cmd", "--panic-on"],
        1,
        stdout="",
        stderr="Access denied\n",
    )
    with pytest.raises(FirewallCmdError) as ei:
        run_firewall_cmd(["--panic-on"], check=True)
    assert "Access denied" in str(ei.value) or ei.value.stderr == "Access denied\n"


@mock.patch("firewall_tool.runner.shutil.which")
def test_run_firewall_cmd_missing_binary(mock_which: mock.MagicMock) -> None:
    mock_which.return_value = None
    with pytest.raises(FirewallCmdError) as ei:
        run_firewall_cmd(["--state"], check=True)
    assert ei.value.code == 127


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_dry_run_skips_subprocess(
    mock_which: mock.MagicMock,
    mock_run: mock.MagicMock,
) -> None:
    mock_which.return_value = "/sbin/firewall-cmd"
    r = run_firewall_cmd(["--reload"], dry_run=True)
    mock_run.assert_not_called()
    assert "/sbin/firewall-cmd" in r.argv[0]
    assert r.argv[1] == "--reload"


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_check_false_returns_code(mock_which: mock.MagicMock, mock_run: mock.MagicMock) -> None:
    mock_which.return_value = "/sbin/firewall-cmd"
    mock_run.return_value = subprocess.CompletedProcess(
        ["/sbin/firewall-cmd", "--add-service=missing"],
        1,
        stdout="",
        stderr="nope",
    )
    r = run_firewall_cmd(["--add-service=missing"], check=False)
    assert r.code == 1
    assert r.stderr == "nope"
