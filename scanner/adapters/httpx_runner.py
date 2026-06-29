from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence

from scanner.utils.process import run_text_capture
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

HttpxRunner = Callable[[list[str], str], subprocess.CompletedProcess[str]]


class HttpxError(RuntimeError):
    pass


@dataclass(frozen=True)
class HttpxProbeResult:
    input_target: str
    url: str
    host: str | None
    path: str
    scheme: str | None
    port: int | None
    status_code: int | None
    title: str | None
    technologies: list[str]
    content_type: str | None
    webserver: str | None
    ip: str | None
    cname: list[str]
    probe_status: str | None
    response_headers: dict[str, str] = field(default_factory=dict)
    raw_entry: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HttpxRunResult:
    command: list[str]
    targets: list[str]
    entries: list[HttpxProbeResult]
    raw_output: str


def run_httpx_probe(
    targets: Sequence[str],
    *,
    httpx_bin: str = "httpx",
    profile: str = "safe",
    timeout_seconds: int = 10,
    threads: int = 10,
    rate_limit_per_second: int | None = None,
    proxy: str | None = None,
    runner: HttpxRunner | None = None,
) -> HttpxRunResult:
    normalized_targets = sorted({target.strip() for target in targets if target.strip()})
    command = _build_httpx_command(
        httpx_bin=httpx_bin,
        profile=profile,
        timeout_seconds=timeout_seconds,
        threads=threads,
        rate_limit_per_second=rate_limit_per_second,
        proxy=proxy,
    )
    if not normalized_targets:
        return HttpxRunResult(command=command, targets=[], entries=[], raw_output="")

    completed = (runner or _default_runner)(command, "\n".join(normalized_targets))
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "httpx command failed"
        raise HttpxError(f"httpx exited with code {completed.returncode}: {detail}")

    raw_output = completed.stdout
    if not raw_output.strip():
        return HttpxRunResult(command=command, targets=normalized_targets, entries=[], raw_output=raw_output)

    return HttpxRunResult(
        command=command,
        targets=normalized_targets,
        entries=_parse_jsonl_output(raw_output),
        raw_output=raw_output,
    )


def _build_httpx_command(
    *,
    httpx_bin: str,
    profile: str,
    timeout_seconds: int,
    threads: int,
    rate_limit_per_second: int | None,
    proxy: str | None = None,
) -> list[str]:
    derived_threads, derived_rate_limit = _derive_profile_limits(profile, threads, rate_limit_per_second)
    command = [
        httpx_bin,
        "-silent",
        "-no-color",
        "-json",
        "-sc",
        "-title",
        "-td",
        "-ip",
        "-cname",
        "-server",
        "-ct",
        "-probe",
        "-irh",
        "-tls-grab",
        "-threads",
        str(derived_threads),
        "-timeout",
        str(timeout_seconds),
    ]
    if derived_rate_limit is not None:
        command.extend(["-rate-limit", str(derived_rate_limit)])
    proxy_value = (proxy or "").strip()
    if proxy_value:
        command.extend(["-proxy", proxy_value])
    return command


def _derive_profile_limits(
    profile: str,
    threads: int,
    rate_limit_per_second: int | None,
) -> tuple[int, int | None]:
    normalized_profile = profile.strip().lower()
    if normalized_profile == "safe":
        return min(threads, 10), rate_limit_per_second or 25
    if normalized_profile == "balanced":
        return min(threads, 25), rate_limit_per_second or 75
    return max(1, threads), rate_limit_per_second


def _default_runner(command: list[str], stdin_text: str) -> subprocess.CompletedProcess[str]:
    return run_text_capture(command, stdin_text=stdin_text)


def _parse_jsonl_output(raw_output: str) -> list[HttpxProbeResult]:
    entries: list[HttpxProbeResult] = []
    for line in raw_output.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HttpxError("httpx returned invalid JSONL output") from exc
        if not isinstance(payload, dict):
            raise HttpxError("httpx returned a non-object JSONL entry")
        entries.append(_parse_probe_entry(payload))
    return entries


def _parse_probe_entry(payload: dict[str, Any]) -> HttpxProbeResult:
    url = _string_value(payload.get("url")) or ""
    input_target = _string_value(payload.get("input")) or url
    parsed_url = urlsplit(url) if url else None
    host_raw = parsed_url.hostname if parsed_url is not None else _string_value(payload.get("host"))
    host = host_raw.lower() if isinstance(host_raw, str) else host_raw
    path = parsed_url.path if parsed_url and parsed_url.path else "/"
    scheme = parsed_url.scheme if parsed_url and parsed_url.scheme else _string_value(payload.get("scheme"))
    port = parsed_url.port if parsed_url and parsed_url.port else _coerce_int(payload.get("port"))
    raw_headers = payload.get("response_headers") or payload.get("response-headers") or {}
    response_headers = {
        str(k).lower(): str(v)
        for k, v in (raw_headers.items() if isinstance(raw_headers, dict) else [])
    }
    return HttpxProbeResult(
        input_target=input_target,
        url=url,
        host=host,
        path=path,
        scheme=scheme,
        port=port,
        status_code=_coerce_int(payload.get("status_code")),
        title=_string_value(payload.get("title")),
        technologies=_string_list(payload.get("tech") or payload.get("technologies")),
        content_type=_string_value(payload.get("content_type")),
        webserver=_string_value(payload.get("webserver")),
        ip=_string_value(payload.get("ip")),
        cname=_string_list(payload.get("cname")),
        probe_status=_string_value(payload.get("probe_status") or payload.get("probe")),
        response_headers=response_headers,
        raw_entry=payload,
    )


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item.strip()]
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def _string_value(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None
