from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from scanner.utils.process import run_text_capture

SubfinderRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class SubfinderError(RuntimeError):
    pass


@dataclass(frozen=True)
class SubfinderRunResult:
    command: list[str]
    root_domain: str
    hosts: list[str]
    raw_output: str


def run_subfinder_discovery(
    root_domain: str,
    *,
    subfinder_bin: str = "subfinder",
    runner: SubfinderRunner | None = None,
) -> SubfinderRunResult:
    normalized_domain = _normalize_root_domain(root_domain)
    command = [subfinder_bin, "-silent", "-d", normalized_domain]

    try:
        completed = (runner or _default_runner)(command)
    except FileNotFoundError as exc:
        raise SubfinderError(f"subfinder command failed to start: {exc}") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "subfinder command failed"
        raise SubfinderError(f"subfinder exited with code {completed.returncode}: {detail}")

    raw_output = completed.stdout
    return SubfinderRunResult(
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
