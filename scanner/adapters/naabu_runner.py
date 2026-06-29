from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from dataclasses import dataclass

from scanner.utils.process import run_text_capture


class NaabuError(RuntimeError):
    pass


@dataclass(frozen=True)
class NaabuPortResult:
    host: str
    ip: str
    port: int
    protocol: str = "tcp"


@dataclass(frozen=True)
class NaabuRunResult:
    command: list[str]
    targets: list[str]
    ports: list[NaabuPortResult]
    raw_output: str


def is_naabu_available(naabu_bin: str = "naabu") -> bool:
    return shutil.which(naabu_bin) is not None


def run_naabu(
    targets: Sequence[str],
    *,
    naabu_bin: str = "naabu",
    ports: str = "1-65535",
    rate: int = 5000,
    retries: int = 3,
    scan_type: str = "syn",
) -> NaabuRunResult:
    normalized = sorted({t.strip() for t in targets if t.strip()})
    if not normalized:
        return NaabuRunResult(command=[], targets=[], ports=[], raw_output="")

    scan_mode = scan_type.strip().lower()
    if scan_mode not in ("syn", "connect"):
        scan_mode = "syn"

    command = [
        naabu_bin,
        "-p", ports,
        "-rate", str(rate),
        "-retries", str(retries),
        "-s", "s" if scan_mode == "syn" else "c",
        "-json",
        "-silent",
        "-host", ",".join(normalized),
    ]
    completed = run_text_capture(command)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "naabu failed"
        raise NaabuError(f"naabu exited {completed.returncode}: {detail}")

    raw = completed.stdout
    return NaabuRunResult(
        command=command,
        targets=normalized,
        ports=_parse_json_lines(raw) if raw.strip() else [],
        raw_output=raw,
    )


def open_ports_by_host(result: NaabuRunResult) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for entry in result.ports:
        key = entry.ip or entry.host
        if not key:
            continue
        out.setdefault(key, [])
        if entry.port not in out[key]:
            out[key].append(entry.port)
    for k in out:
        out[k].sort()
    return out


def _parse_json_lines(raw: str) -> list[NaabuPortResult]:
    entries: list[NaabuPortResult] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        host = str(payload.get("host") or "").strip()
        ip = str(payload.get("ip") or "").strip()
        port_raw = payload.get("port")
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            continue
        proto = str(payload.get("protocol") or "tcp").strip().lower() or "tcp"
        entries.append(NaabuPortResult(host=host, ip=ip or host, port=port, protocol=proto))
    return entries
