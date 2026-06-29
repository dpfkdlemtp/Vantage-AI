from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from scanner.utils.process import run_text_capture


class SubzyError(RuntimeError):
    pass


@dataclass(frozen=True)
class SubzyMatch:
    host: str
    service: str
    vulnerable: bool
    raw: dict


@dataclass(frozen=True)
class SubzyRunResult:
    command: list[str]
    targets: list[str]
    matches: list[SubzyMatch]
    raw_output: str


def is_subzy_available(subzy_bin: str = "subzy") -> bool:
    return shutil.which(subzy_bin) is not None


def run_subzy(
    hostnames: Sequence[str],
    *,
    subzy_bin: str = "subzy",
    timeout_seconds: int = 10,
    concurrency: int = 20,
) -> SubzyRunResult:
    normalized = sorted({h.strip().lower() for h in hostnames if h.strip()})
    if not normalized:
        return SubzyRunResult(command=[], targets=[], matches=[], raw_output="")

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
        tf.write("\n".join(normalized))
        targets_path = tf.name

    try:
        command = [
            subzy_bin,
            "run",
            "--targets", targets_path,
            "--concurrency", str(concurrency),
            "--timeout", str(timeout_seconds),
            "--output", "json",
            "--hide_fails",
        ]
        completed = run_text_capture(command)
        # subzy returns non-zero when vulnerabilities found — don't fail on that
        raw = completed.stdout or ""
        if completed.returncode not in (0, 1):
            detail = completed.stderr.strip() or "subzy failed"
            raise SubzyError(f"subzy exited {completed.returncode}: {detail}")
        return SubzyRunResult(
            command=command,
            targets=normalized,
            matches=_parse_output(raw),
            raw_output=raw,
        )
    finally:
        try:
            Path(targets_path).unlink()
        except OSError:
            pass


def _parse_output(raw: str) -> list[SubzyMatch]:
    matches: list[SubzyMatch] = []
    stripped = raw.strip()
    if not stripped:
        return matches
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        for line in stripped.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                matches.append(_match_from_dict(obj))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return matches
    if isinstance(payload, list):
        for obj in payload:
            if isinstance(obj, dict):
                try:
                    matches.append(_match_from_dict(obj))
                except (KeyError, TypeError):
                    continue
    elif isinstance(payload, dict):
        try:
            matches.append(_match_from_dict(payload))
        except (KeyError, TypeError):
            pass
    return matches


def _match_from_dict(obj: dict) -> SubzyMatch:
    host = str(obj.get("subdomain") or obj.get("host") or obj.get("target") or "").strip().lower()
    service = str(obj.get("service") or obj.get("engine") or "").strip()
    vuln_raw = obj.get("vulnerable")
    if vuln_raw is None:
        status = str(obj.get("status") or "").lower()
        vulnerable = status in ("vulnerable", "potential", "high", "medium")
    else:
        vulnerable = bool(vuln_raw)
    return SubzyMatch(host=host, service=service, vulnerable=vulnerable, raw=obj)
