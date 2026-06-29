from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _block_live_port_scanners(monkeypatch):
    # `_run_port_scan` branches into `run_masscan_nmap_two_pass` whenever the
    # run config has `masscan_enabled` or `naabu_enabled` set (the "fast" profile
    # default). That two-pass path bails out to plain nmap only when both
    # `is_masscan_available` and `is_naabu_available` report False — otherwise
    # it spawns real masscan/naabu against the test's CIDR (seen in the wild
    # firing at 10.0.0.0/24 and 10.20.30.0/24). Force the availability checks
    # off so unit tests stay offline; tests covering the adapters themselves
    # can override these in their own fixtures.
    monkeypatch.setattr(
        "scanner.adapters.masscan_runner.is_masscan_available",
        lambda *a, **kw: False,
        raising=True,
    )
    monkeypatch.setattr(
        "scanner.adapters.naabu_runner.is_naabu_available",
        lambda *a, **kw: False,
        raising=True,
    )

    def _refuse(name):
        def _raise(*_a, **_kw):
            raise AssertionError(
                f"{name} invoked from a unit test — patch it explicitly if needed"
            )
        return _raise

    monkeypatch.setattr(
        "scanner.adapters.masscan_runner.run_masscan",
        _refuse("run_masscan"),
        raising=True,
    )
    monkeypatch.setattr(
        "scanner.adapters.naabu_runner.run_naabu",
        _refuse("run_naabu"),
        raising=True,
    )
