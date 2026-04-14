"""Execute firewall-cmd with consistent error handling."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence

FIREWALL_CMD = "firewall-cmd"


class FirewallCmdError(Exception):
    """Non-zero exit or invocation failure from firewall-cmd."""

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


def firewall_cmd_on_path() -> Optional[str]:
    return shutil.which(FIREWALL_CMD)


def require_firewall_cmd() -> str:
    path = firewall_cmd_on_path()
    if not path:
        raise FirewallCmdError(
            f"{FIREWALL_CMD} not found in PATH; install firewalld.",
            code=127,
        )
    return path


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
    Run `firewall-cmd` with extra args (do not include the binary name).

    When dry_run is True, does not execute; returns empty stdout and argv recorded.
    """
    bin_path = require_firewall_cmd()
    argv = [bin_path, *list(args)]
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
