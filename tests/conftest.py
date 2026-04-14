"""Pytest fixtures."""

from __future__ import annotations

import pytest

from firewall_tool.runner import set_use_offline


@pytest.fixture(autouse=True)
def _reset_offline_mode() -> None:
    set_use_offline(False)
    yield
    set_use_offline(False)
