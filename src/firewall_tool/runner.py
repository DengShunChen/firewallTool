"""Execute firewall-cmd / firewall-offline-cmd with consistent error handling."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Sequence

FIREWALL_CMD = "firewall-cmd"
FIREWALL_OFFLINE_CMD = "firewall-offline-cmd"

_use_offline: bool = False


class FirewallCmdError(Exception):
    """Non-zero exit or invocation failure from firewall backend."""

    def __init__(self, message: str, *, stderr: str = "", code: int = 1) -> None:
        super().__init__(message)
        self.stderr = stderr
        self.code = code


@dataclass
class RunResult:
    stdout: str
    stderr: str
    code: int
    argv: List[str]


def set_use_offline(enabled: bool) -> None:
    """When True, `run_firewall_cmd` invokes `firewall-offline-cmd` instead of `firewall-cmd`."""
    global _use_offline
    _use_offline = enabled


def is_offline() -> bool:
    return _use_offline


def backend_name() -> str:
    return FIREWALL_OFFLINE_CMD if _use_offline else FIREWALL_CMD


def _normalize_args_for_backend(args: Sequence[str]) -> List[str]:
    """
    Offline tool edits on-disk config only; it typically does not accept `--permanent`
    (everything is effectively permanent). Strip those flags to avoid parse errors.
    """
    if not _use_offline:
        return list(args)
    out: List[str] = []
    for a in args:
        if a == "--permanent":
            continue
        out.append(a)
    return out


def require_backend() -> str:
    name = backend_name()
    path = shutil.which(name)
    if not path:
        raise FirewallCmdError(
            f"{name} not found in PATH; install firewalld.",
            code=127,
        )
    return path


def require_firewall_cmd() -> str:
    """Backward-compatible name: returns path to the active backend binary."""
    return require_backend()


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def require_root(action: str = "modify firewall rules") -> None:
    if not is_root():
        raise FirewallCmdError(
            f"Must run as root to {action}.",
            code=13,
        )


def run_firewall_cmd(
    args: Sequence[str],
    *,
    check: bool = True,
    dry_run: bool = False,
    timeout: float = 120.0,
) -> RunResult:
    """
    Run `firewall-cmd` or `firewall-offline-cmd` (see `set_use_offline`) with extra args.

    When dry_run is True, does not execute; returns empty stdout and argv recorded.
    """
    argv_args = _normalize_args_for_backend(args)
    bin_path = require_backend()
    argv = [bin_path, *argv_args]
    if dry_run:
        return RunResult(stdout="", stderr="", code=0, argv=list(argv))

    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        text=True,
        check=False,
    )
    out = proc.stdout or ""
    err = proc.stderr or ""
    result = RunResult(stdout=out, stderr=err, code=proc.returncode, argv=list(argv))
    if check and proc.returncode != 0:
        msg = err.strip() or out.strip() or f"exit code {proc.returncode}"
        raise FirewallCmdError(msg, stderr=err, code=proc.returncode)
    return result
