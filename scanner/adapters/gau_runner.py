from __future__ import annotations

import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from scanner.utils.process import run_text_capture


class GauError(RuntimeError):
    pass


@dataclass(frozen=True)
class GauRunResult:
    command: list[str]
    targets: list[str]
    urls: list[str]
    raw_output: str


def is_gau_available(gau_bin: str = "gau") -> bool:
    return shutil.which(gau_bin) is not None


def run_gau(
    domains: Sequence[str],
    *,
    gau_bin: str = "gau",
    threads: int = 5,
    timeout_seconds: int = 60,
    providers: Sequence[str] = ("wayback", "commoncrawl", "otx"),
) -> GauRunResult:
    normalized = sorted({d.strip().lower() for d in domains if d.strip()})
    if not normalized:
        return GauRunResult(command=[], targets=[], urls=[], raw_output="")

    command = [
        gau_bin,
        "--threads", str(threads),
        "--timeout", str(timeout_seconds),
        "--providers", ",".join(providers),
        "--subs",
    ] + normalized
    completed = run_text_capture(command)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "gau failed"
        raise GauError(f"gau exited {completed.returncode}: {detail}")
    raw = completed.stdout or ""
    return GauRunResult(
        command=command,
        targets=normalized,
        urls=_parse_urls(raw),
        raw_output=raw,
    )


def _parse_urls(raw: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        parts = urlsplit(line)
        if parts.scheme not in ("http", "https"):
            continue
        if not parts.netloc:
            continue
        if line in seen:
            continue
        seen.add(line)
        urls.append(line)
    return urls


def group_urls_by_host(urls: Sequence[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for u in urls:
        parts = urlsplit(u)
        host = parts.netloc.lower()
        if not host:
            continue
        out.setdefault(host, []).append(u)
    return out
