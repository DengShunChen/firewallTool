"""Tests for firewall-cmd runner and small parsers."""

from __future__ import annotations

import subprocess
import unittest.mock as mock

import pytest

from typer.testing import CliRunner

from firewall_tool.commands.ipset_direct import (
    _parse_direct_rules_line,
    _parse_ipset_entries_stdout,
)
from firewall_tool.formatters import parse_active_zones, polkit_hint
from firewall_tool.main import app
from firewall_tool.runner import (
    FirewallCmdError,
    RunResult,
    run_firewall_cmd,
    set_use_offline,
)


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_direct_add_drop_refuses_without_accept_risk(mock_run: mock.MagicMock) -> None:
    runner = CliRunner()
    r = runner.invoke(
        app,
        [
            "direct",
            "add",
            "--chain",
            "INPUT",
            "--priority",
            "999",
            "--rule",
            "-j DROP",
            "--yes",
        ],
    )
    assert r.exit_code == 2
    mock_run.assert_not_called()


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_direct_remove_ssh_refuses_without_accept(mock_run: mock.MagicMock) -> None:
    runner = CliRunner()
    r = runner.invoke(
        app,
        [
            "direct",
            "remove",
            "--chain",
            "INPUT",
            "--priority",
            "512",
            "--rule",
            "-p tcp --dport 22 -j ACCEPT",
            "--yes",
            "--no-verify-present",
        ],
    )
    assert r.exit_code == 2
    mock_run.assert_not_called()


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_direct_rules_argv(mock_run: mock.MagicMock) -> None:
    mock_run.return_value = RunResult(stdout="OK\n", stderr="", code=0, argv=[])
    runner = CliRunner()
    r = runner.invoke(app, ["direct", "rules"])
    assert r.exit_code == 0, r.stdout
    mock_run.assert_called_once()
    assert list(mock_run.call_args[0][0]) == ["--direct", "--get-all-rules"]


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_remove_entry_ssh_refuses_without_accept(mock_run: mock.MagicMock) -> None:
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["ipset", "remove-entry", "ssh-in", "10.0.0.1", "--yes", "--no-verify-present"],
    )
    assert r.exit_code == 2
    mock_run.assert_not_called()


@mock.patch("firewall_tool.commands.ipset_direct.require_root")
@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_add_entry_argv(mock_run: mock.MagicMock, _nr: mock.MagicMock) -> None:
    mock_run.return_value = RunResult(stdout="success\n", stderr="", code=0, argv=[])
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["ipset", "add-entry", "MYSET", "192.168.1.0/24", "--permanent", "--yes"],
    )
    assert r.exit_code == 0, r.stdout
    mock_run.assert_called_once()
    assert list(mock_run.call_args[0][0]) == [
        "--permanent",
        "--ipset=MYSET",
        "--add-entry=192.168.1.0/24",
    ]


@mock.patch("firewall_tool.commands.ipset_direct.require_root")
@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_remove_entry_query_then_remove(
    mock_run: mock.MagicMock,
    _nr: mock.MagicMock,
) -> None:
    mock_run.side_effect = [
        RunResult(stdout="", stderr="", code=0, argv=[]),
        RunResult(stdout="success\n", stderr="", code=0, argv=[]),
    ]
    runner = CliRunner()
    r = runner.invoke(
        app,
        [
            "ipset",
            "remove-entry",
            "MYSET",
            "10.0.0.1",
            "--permanent",
            "--yes",
        ],
    )
    assert r.exit_code == 0, r.stdout
    assert mock_run.call_count == 2
    assert list(mock_run.call_args_list[0][0][0]) == [
        "--permanent",
        "--ipset=MYSET",
        "--query-entry=10.0.0.1",
    ]
    assert list(mock_run.call_args_list[1][0][0]) == [
        "--permanent",
        "--ipset=MYSET",
        "--remove-entry=10.0.0.1",
    ]


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_wizard_add_dry_run_then_cancel(mock_run: mock.MagicMock) -> None:
    mock_run.return_value = RunResult(stdout="", stderr="", code=0, argv=["/sbin/firewall-cmd", "argv"])
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["ipset", "wizard-add"],
        input="2\nMYSET\n10.0.0.1\n\n\n\n",
    )
    assert r.exit_code == 0, r.stdout
    add_calls = [
        c
        for c in mock_run.call_args_list
        if c.args
        and isinstance(c.args[0], (list, tuple))
        and any(str(a).startswith("--add-entry") for a in c.args[0])
    ]
    assert len(add_calls) == 1
    assert add_calls[0].kwargs.get("dry_run") is True


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_wizard_add_new_ipset_dry_run_then_cancel(mock_run: mock.MagicMock) -> None:
    mock_run.side_effect = [
        RunResult("", "", 1, []),
        RunResult("", "", 1, []),
        RunResult(
            stdout="",
            stderr="",
            code=0,
            argv=["/sbin/firewall-cmd", "--permanent", "--new-ipset=wiz", "--type=hash:net"],
        ),
    ]
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["ipset", "wizard-add"],
        input="1\n\nwiz\nhash:net\n\n\n",
    )
    assert r.exit_code == 0, r.stdout
    assert mock_run.call_count == 3
    last = list(mock_run.call_args_list[2].args[0])
    assert last[:4] == ["--permanent", "--new-ipset=wiz", "--type=hash:net"]
    assert mock_run.call_args_list[2].kwargs.get("dry_run") is True


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_wizard_remove_dry_run_then_cancel(mock_run: mock.MagicMock) -> None:
    mock_run.return_value = RunResult(stdout="", stderr="", code=0, argv=["/sbin/firewall-cmd", "argv"])
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["ipset", "wizard-remove"],
        input="\nMYSET\n10.0.0.1\n\n\n",
    )
    assert r.exit_code == 0, r.stdout
    remove_calls = [
        c
        for c in mock_run.call_args_list
        if c.args
        and isinstance(c.args[0], (list, tuple))
        and any(str(a).startswith("--remove-entry") for a in c.args[0])
    ]
    assert len(remove_calls) == 1
    assert remove_calls[0].kwargs.get("dry_run") is True
    assert mock_run.call_count >= 4


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_wizard_remove_pick_entry_by_index(mock_run: mock.MagicMock) -> None:
    mock_run.side_effect = [
        RunResult("MYSET\n", "", 0, []),
        RunResult("MYSET\n", "", 0, []),
        RunResult("10.0.0.1\n10.0.0.2\n", "", 0, []),
        RunResult("", "", 0, ["/sbin/firewall-cmd", "argv"]),
    ]
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["ipset", "wizard-remove"],
        input="\nMYSET\n\n\n\n",
    )
    assert r.exit_code == 0, r.stdout
    remove_calls = [
        c
        for c in mock_run.call_args_list
        if c.args
        and isinstance(c.args[0], (list, tuple))
        and any(str(a).startswith("--remove-entry") for a in c.args[0])
    ]
    assert len(remove_calls) == 1
    assert "--remove-entry=10.0.0.1" in remove_calls[0].args[0]
    assert remove_calls[0].kwargs.get("dry_run") is True


def test_parse_ipset_entries_stdout_multiline() -> None:
    raw = "10.0.0.1\n10.0.0.2\n"
    assert _parse_ipset_entries_stdout(raw) == ["10.0.0.1", "10.0.0.2"]


def test_parse_ipset_entries_stdout_single_line_spaced() -> None:
    raw = "172.16.1.1 172.16.1.2 10.0.0.0/24\n"
    assert _parse_ipset_entries_stdout(raw) == ["172.16.1.1", "172.16.1.2", "10.0.0.0/24"]


def test_parse_ipset_entries_stdout_non_ip_single_line_unchanged() -> None:
    raw = "foo bar\n"
    assert _parse_ipset_entries_stdout(raw) == ["foo bar"]


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_delete_refuses_without_typed_token(mock_run: mock.MagicMock) -> None:
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["ipset", "delete", "MYSET", "--yes"],
    )
    assert r.exit_code == 2
    mock_run.assert_not_called()


@mock.patch("firewall_tool.commands.ipset_direct.run_firewall_cmd")
def test_ipset_delete_dry_run_without_typed_token(mock_run: mock.MagicMock) -> None:
    mock_run.side_effect = [
        RunResult("", "", 0, []),
        RunResult("", "", 0, ["/sbin/firewall-cmd", "--permanent", "--delete-ipset=MYSET"]),
    ]
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["ipset", "delete", "MYSET", "--dry-run", "--yes"],
    )
    assert r.exit_code == 0, r.stdout
    del_calls = [
        c
        for c in mock_run.call_args_list
        if c.args and "--delete-ipset=MYSET" in c.args[0]
    ]
    assert len(del_calls) == 1
    assert del_calls[0].kwargs.get("dry_run") is True


def test_parse_direct_rules_line() -> None:
    line = (
        "ipv4 filter INPUT 512 -p tcp -m set --match-set ssh-in src "
        "--dport 22 -j ACCEPT"
    )
    fam, tbl, ch, pri, tok = _parse_direct_rules_line(line)
    assert (fam, tbl, ch, pri) == ("ipv4", "filter", "INPUT", 512)
    assert "-j" in tok and "ACCEPT" in tok


def test_polkit_hint_detects_authorization_failed() -> None:
    text = "Authorization failed.\nMake sure polkit agent is running or run the application as superuser.\n"
    h = polkit_hint(text)
    assert h is not None
    assert "command -v fwctl" in h
    assert "PolicyKit" in h


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
    mock_which.side_effect = lambda name: (
        "/sbin/firewall-cmd" if name == "firewall-cmd" else None
    )
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
    mock_which.side_effect = lambda name: (
        "/sbin/firewall-cmd" if name == "firewall-cmd" else None
    )
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
    mock_which.side_effect = lambda name: None
    with pytest.raises(FirewallCmdError) as ei:
        run_firewall_cmd(["--state"], check=True)
    assert ei.value.code == 127


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_dry_run_skips_subprocess(
    mock_which: mock.MagicMock,
    mock_run: mock.MagicMock,
) -> None:
    mock_which.side_effect = lambda name: (
        "/sbin/firewall-cmd" if name == "firewall-cmd" else None
    )
    r = run_firewall_cmd(["--reload"], dry_run=True)
    mock_run.assert_not_called()
    assert "/sbin/firewall-cmd" in r.argv[0]
    assert r.argv[1] == "--reload"


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_check_false_returns_code(mock_which: mock.MagicMock, mock_run: mock.MagicMock) -> None:
    mock_which.side_effect = lambda name: (
        "/sbin/firewall-cmd" if name == "firewall-cmd" else None
    )
    mock_run.return_value = subprocess.CompletedProcess(
        ["/sbin/firewall-cmd", "--add-service=missing"],
        1,
        stdout="",
        stderr="nope",
    )
    r = run_firewall_cmd(["--add-service=missing"], check=False)
    assert r.code == 1
    assert r.stderr == "nope"


@mock.patch("firewall_tool.commands.service_port.run_firewall_cmd")
def test_cli_service_add_dry_run_builds_argv(mock_run: mock.MagicMock) -> None:
    mock_run.return_value = RunResult(
        stdout="",
        stderr="",
        code=0,
        argv=["/sbin/firewall-cmd", "--add-service=ssh", "--permanent", "--zone=public"],
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["service", "add", "ssh", "--zone", "public", "--permanent", "--dry-run", "--yes"],
    )
    assert result.exit_code == 0, result.stdout
    mock_run.assert_called_once()
    pos, kw = mock_run.call_args
    assert list(pos[0]) == [
        "--add-service=ssh",
        "--permanent",
        "--zone=public",
    ]
    assert kw.get("dry_run") is True


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_offline_dry_run_uses_offline_binary(
    mock_which: mock.MagicMock,
    mock_run: mock.MagicMock,
) -> None:
    mock_which.side_effect = lambda name: (
        "/sbin/firewall-offline-cmd" if name == "firewall-offline-cmd" else None
    )
    set_use_offline(True)
    r = run_firewall_cmd(["--list-all-zones"], dry_run=True)
    mock_run.assert_not_called()
    assert r.argv[0].endswith("firewall-offline-cmd")
    assert r.argv[1] == "--list-all-zones"


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_offline_strips_permanent(
    mock_which: mock.MagicMock,
    mock_run: mock.MagicMock,
) -> None:
    mock_which.side_effect = lambda name: (
        "/sbin/firewall-offline-cmd" if name == "firewall-offline-cmd" else None
    )
    mock_run.return_value = subprocess.CompletedProcess(
        ["/sbin/firewall-offline-cmd", "--add-service=ssh"],
        0,
        stdout="success\n",
        stderr="",
    )
    set_use_offline(True)
    run_firewall_cmd(["--add-service=ssh", "--permanent"], check=True)
    argv = mock_run.call_args[0][0]
    assert argv[0].endswith("firewall-offline-cmd")
    assert "--permanent" not in argv


def test_cli_reload_rejected_in_offline() -> None:
    runner = CliRunner()
    r = runner.invoke(app, ["--offline", "reload", "--yes"])
    assert r.exit_code == 2


@mock.patch("firewall_tool.runner.subprocess.run")
@mock.patch("firewall_tool.runner.shutil.which")
def test_cli_offline_service_dry_run_shows_offline_cmd_without_permanent(
    mock_which: mock.MagicMock,
    mock_run: mock.MagicMock,
) -> None:
    mock_which.side_effect = lambda name: (
        f"/sbin/{name}" if name in ("firewall-cmd", "firewall-offline-cmd") else None
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["--offline", "service", "add", "ssh", "--permanent", "--dry-run", "--yes"],
    )
    assert result.exit_code == 0, result.stdout
    mock_run.assert_not_called()
    dry_lines = [ln for ln in result.stdout.splitlines() if ln.strip().startswith("dry-run:")]
    assert len(dry_lines) == 1
    cmdline = dry_lines[0]
    assert "firewall-offline-cmd" in cmdline
    assert "--permanent" not in cmdline
    assert "--add-service=ssh" in cmdline
