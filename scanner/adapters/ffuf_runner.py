from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scanner.utils.process import run_text_capture

FfufRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class FfufError(RuntimeError):
    pass


@dataclass(frozen=True)
class FfufResultEntry:
    url: str
    status_code: int | None
    length: int | None
    words: int | None
    lines: int | None
    content_type: str | None
    redirect_target: str | None
    host: str | None
    input_value: str | None
    position: int | None
    raw_entry: dict[str, Any]


@dataclass(frozen=True)
class FfufRunResult:
    command: list[str]
    base_url: str
    output_path: Path
    matches: list[FfufResultEntry]
    raw_output: str


def run_ffuf_scan(
    base_url: str,
    *,
    output_path: Path,
    ffuf_bin: str = "ffuf",
    wordlist_path: Path,
    profile: str = "safe",
    threads: int = 20,
    match_status_codes: Sequence[int] | None = None,
    extensions: Sequence[str] | None = None,
    auto_calibration: bool = True,
    per_host_auto_calibration: bool = True,
    filter_sizes: Sequence[int] | None = None,
    filter_codes: Sequence[int] | None = None,
    proxy: str | None = None,
    runner: FfufRunner | None = None,
) -> FfufRunResult:
    normalized_base_url = _normalize_base_url(base_url)
    command = _build_ffuf_command(
        ffuf_bin=ffuf_bin,
        base_url=normalized_base_url,
        output_path=output_path,
        wordlist_path=wordlist_path,
        profile=profile,
        threads=threads,
        match_status_codes=match_status_codes or (),
        extensions=extensions or (),
        auto_calibration=auto_calibration,
        per_host_auto_calibration=per_host_auto_calibration,
        filter_sizes=filter_sizes or (),
        filter_codes=filter_codes or (),
        proxy=proxy,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    completed = (runner or _default_runner)(command)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "ffuf command failed"
        raise FfufError(f"ffuf exited with code {completed.returncode}: {detail}")
    if not output_path.exists():
        raise FfufError("ffuf did not produce the expected JSON output file")

    raw_output = output_path.read_text(encoding="utf-8")
    if not raw_output.strip():
        return FfufRunResult(
            command=command,
            base_url=normalized_base_url,
            output_path=output_path,
            matches=[],
            raw_output=raw_output,
        )

    return FfufRunResult(
        command=command,
        base_url=normalized_base_url,
        output_path=output_path,
        matches=_parse_ffuf_output(raw_output),
        raw_output=raw_output,
    )


def _build_ffuf_command(
    *,
    ffuf_bin: str,
    base_url: str,
    output_path: Path,
    wordlist_path: Path,
    profile: str,
    threads: int,
    match_status_codes: Sequence[int],
    extensions: Sequence[str],
    auto_calibration: bool,
    per_host_auto_calibration: bool,
    filter_sizes: Sequence[int],
    filter_codes: Sequence[int] = (),
    proxy: str | None = None,
) -> list[str]:
    command = [
        ffuf_bin,
        "-noninteractive",
        "-s",
        "-u",
        f"{base_url.rstrip('/')}/FUZZ",
        "-w",
        str(wordlist_path),
        "-o",
        str(output_path),
        "-of",
        "json",
        "-t",
        str(_derive_profile_threads(profile, threads)),
    ]
    if auto_calibration:
        command.append("-ac")
        if per_host_auto_calibration:
            command.append("-ach")
    normalized_status_codes = _normalize_status_codes(match_status_codes)
    if normalized_status_codes:
        command.extend(["-mc", normalized_status_codes])
    normalized_extensions = _normalize_extensions(extensions)
    if normalized_extensions:
        command.extend(["-e", normalized_extensions])
    normalized_filter_sizes = _normalize_filter_sizes(filter_sizes)
    if normalized_filter_sizes:
        command.extend(["-fs", normalized_filter_sizes])
    normalized_filter_codes = _normalize_status_codes(filter_codes)
    if normalized_filter_codes:
        command.extend(["-fc", normalized_filter_codes])
    proxy_value = str(proxy or "").strip()
    if proxy_value:
        command.extend(["-x", proxy_value])
    return command


def _derive_profile_threads(profile: str, threads: int) -> int:
    normalized_profile = profile.strip().lower()
    if normalized_profile == "safe":
        return min(threads, 10)
    if normalized_profile == "balanced":
        return min(threads, 25)
    return max(1, threads)


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return run_text_capture(command)


def _parse_ffuf_output(raw_output: str) -> list[FfufResultEntry]:
    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise FfufError("ffuf returned invalid JSON output") from exc
    if not isinstance(payload, dict):
        raise FfufError("ffuf returned an unexpected JSON structure")

    raw_results = payload.get("results", [])
    if raw_results is None:
        return []
    if not isinstance(raw_results, list):
        raise FfufError("ffuf returned an invalid results payload")

    matches: list[FfufResultEntry] = []
    for item in raw_results:
        if not isinstance(item, dict):
            raise FfufError("ffuf returned a non-object result entry")
        matches.append(_parse_result_entry(item))
    return matches


def _parse_result_entry(payload: dict[str, Any]) -> FfufResultEntry:
    return FfufResultEntry(
        url=_string_value(payload.get("url")) or "",
        status_code=_coerce_int(payload.get("status")),
        length=_coerce_int(payload.get("length")),
        words=_coerce_int(payload.get("words")),
        lines=_coerce_int(payload.get("lines")),
        content_type=_string_value(payload.get("content-type")),
        redirect_target=_string_value(payload.get("redirectlocation")),
        host=_string_value(payload.get("host")),
        input_value=_extract_input_value(payload.get("input")),
        position=_coerce_int(payload.get("position")),
        raw_entry=payload,
    )


def _extract_input_value(value: Any) -> str | None:
    if isinstance(value, dict):
        fuzz_value = value.get("FUZZ")
        if isinstance(fuzz_value, str) and fuzz_value.strip():
            return fuzz_value
        for item in value.values():
            if isinstance(item, str) and item.strip():
                return item
    if isinstance(value, str) and value.strip():
        return value
    return None


def _normalize_base_url(base_url: str) -> str:
    normalized = base_url.strip()
    if not normalized:
        raise ValueError("base_url must not be empty")
    return normalized


def _normalize_status_codes(status_codes: Sequence[int]) -> str:
    normalized = sorted({code for code in status_codes if code > 0})
    return ",".join(str(code) for code in normalized)


def _normalize_extensions(extensions: Sequence[str]) -> str:
    normalized = sorted({item.strip().lstrip(".") for item in extensions if item.strip()})
    return ",".join(item for item in normalized if item)


def _normalize_filter_sizes(filter_sizes: Sequence[int]) -> str:
    normalized = sorted({size for size in filter_sizes if size >= 0})
    return ",".join(str(size) for size in normalized)


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _string_value(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None
