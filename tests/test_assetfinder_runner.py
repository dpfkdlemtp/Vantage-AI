from __future__ import annotations

import subprocess

import pytest

from scanner.adapters.assetfinder_runner import AssetfinderError, run_assetfinder_discovery


def test_run_assetfinder_discovery_parses_output() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        assert command == ["assetfinder", "--subs-only", "example.com"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="blog.example.com\napi.example.com\nblog.example.com\n",
            stderr="",
        )

    result = run_assetfinder_discovery("Example.COM", runner=runner)

    assert result.root_domain == "example.com"
    assert result.hosts == ["api.example.com", "blog.example.com"]


def test_run_assetfinder_discovery_empty_output() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = run_assetfinder_discovery("example.com", runner=runner)

    assert result.hosts == []
    assert result.raw_output == ""


def test_run_assetfinder_discovery_failure() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 2, stdout="", stderr="bad request")

    with pytest.raises(AssetfinderError, match="bad request"):
        run_assetfinder_discovery("example.com", runner=runner)
