from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from urllib.parse import urlsplit

from scanner.adapters.ffuf_runner import FfufRunResult
from scanner.models import Finding


def normalize_ffuf_results(
    result: FfufRunResult,
    *,
    run_id: str,
    task_id: str,
    observed_at: datetime | None = None,
) -> list[Finding]:
    created_at = observed_at or datetime.now(UTC)
    findings: list[Finding] = []
    seen_location_keys: set[tuple[str, str, str]] = set()

    for match in result.matches:
        normalized = normalize_ffuf_result(match, result.base_url)
        target = str(normalized.get("url") or "").strip()
        host = str(normalized.get("host") or "").strip().lower()
        path = str(normalized.get("path") or "/").strip() or "/"
        port = str(normalized.get("port") or "").strip()
        dedup_key = (host, port, path)
        if not target or dedup_key in seen_location_keys:
            continue
        seen_location_keys.add(dedup_key)
        tags = ["dirscan", "path", "ffuf"]
        if match.redirect_target:
            tags.append("redirect")
        metadata_json = {
            "depth": normalized.get("depth", 0),
            "parent": normalized.get("parent_base_url"),
        }
        findings.append(
            Finding(
                finding_id=_build_finding_id(run_id, task_id, "dir_enum", target),
                run_id=run_id,
                task_id=task_id,
                module="dir_enum",
                target=target,
                status="observed",
                summary=_build_summary(target, match.status_code),
                evidence_json=_compact_evidence(
                    {
                        **normalized,
                        "source_tool": "ffuf",
                        "base_url": result.base_url,
                        "status_code": normalized.get("status"),
                        "length": normalized.get("size"),
                        "size": normalized.get("size"),
                        "content_length": normalized.get("size"),
                        "content_type": match.content_type,
                        "redirect_target": match.redirect_target,
                        "input_value": match.input_value,
                        "position": match.position,
                        "metadata_json": metadata_json,
                    }
                ),
                tags=tags,
                created_at=created_at,
            )
        )

    return findings


def _build_finding_id(run_id: str, task_id: str, module: str, target: str) -> str:
    digest = sha256(f"{run_id}:{task_id}:{module}:{target}".encode("utf-8")).hexdigest()
    return f"finding-{digest[:24]}"


def _build_summary(target: str, status_code: int | None) -> str:
    suffix = f" [{status_code}]" if status_code is not None else ""
    return f"Discovered path {target}{suffix}"


def normalize_ffuf_result(result: object, base_url: str) -> dict[str, object]:
    entry = result
    if hasattr(result, "url"):
        url = str(getattr(result, "url", "") or "").strip()
        status = getattr(result, "status_code", None)
        size = getattr(result, "length", None)
        words = getattr(result, "words", None)
        lines = getattr(result, "lines", None)
    elif isinstance(result, dict):
        url = str(result.get("url") or "").strip()
        status = result.get("status")
        size = result.get("length")
        words = result.get("words")
        lines = result.get("lines")
    else:
        raise TypeError(f"Unsupported ffuf result type: {type(entry)!r}")

    parsed = urlsplit(url)
    base = urlsplit(str(base_url or "").strip())
    protocol = (parsed.scheme or base.scheme or "http").lower()
    host = parsed.hostname or base.hostname or ""
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    port_value = parsed.port
    if port_value is None:
        if protocol == "https":
            port_value = 443
        elif protocol == "http":
            port_value = 80
    parent_base_url = f"{protocol}://{host}:{port_value}/" if host and port_value else str(base_url or "")
    canonical_url = (
        f"{protocol}://{host}:{port_value}{path}"
        if host and port_value is not None
        else url
    )
    depth = len([segment for segment in path.split("/") if segment])
    service_id = f"{host}:{port_value}" if host and port_value is not None else host
    return {
        "type": "directory",
        "source": "ffuf",
        "protocol": protocol or None,
        "host": host or None,
        "port": port_value,
        "url": canonical_url,
        "path": path,
        "status": _to_int(status),
        "size": _to_int(size),
        "words": _to_int(words),
        "lines": _to_int(lines),
        "depth": depth,
        "parent_base_url": parent_base_url or None,
        "service_id": service_id or None,
    }


def _compact_evidence(evidence: dict[str, object]) -> dict[str, object]:
    compact: dict[str, object] = {}
    for key, value in evidence.items():
        if value is None:
            continue
        compact[key] = value
    return compact


def _to_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None
