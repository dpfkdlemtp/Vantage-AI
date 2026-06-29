from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from scanner.utils.process import run_text_capture

AssetfinderRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class AssetfinderError(RuntimeError):
    pass


@dataclass(frozen=True)
class AssetfinderRunResult:
    command: list[str]
    root_domain: str
    hosts: list[str]
    raw_output: str


def run_assetfinder_discovery(
    root_domain: str,
    *,
    assetfinder_bin: str = "assetfinder",
    runner: AssetfinderRunner | None = None,
) -> AssetfinderRunResult:
    normalized_domain = _normalize_root_domain(root_domain)
    command = [assetfinder_bin, "--subs-only", normalized_domain]

    try:
        completed = (runner or _default_runner)(command)
    except FileNotFoundError as exc:
        raise AssetfinderError(f"assetfinder command failed to start: {exc}") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "assetfinder command failed"
        raise AssetfinderError(f"assetfinder exited with code {completed.returncode}: {detail}")

    raw_output = completed.stdout
    return AssetfinderRunResult(
        command=command,
        root_domain=normalized_domain,
        hosts=_parse_hosts(raw_output),
        raw_output=raw_output,
    )


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return run_text_capture(command)


def _parse_hosts(raw_output: str) -> list[str]:
    normalized = {
        line.strip().lower().rstrip(".")
        for line in raw_output.splitlines()
        if line.strip()
    }
    return sorted(item for item in normalized if item)


def _normalize_root_domain(root_domain: str) -> str:
    normalized = root_domain.strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("root_domain must not be empty")
    return normalized
