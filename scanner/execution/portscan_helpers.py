from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from scanner import runner as runner_core
from scanner.adapters import nmap_runner as nmap_adapter
from scanner.models import Finding
from scanner.state import get_run, get_task

NMAP_PERCENT_RE = re.compile(r"(?P<percent>\d+(?:\.\d+)?)% done")
NMAP_REMAINING_RE = re.compile(r"\((?:(\d+):)?(\d+):(\d+)\s+remaining\)")


def estimated_remaining_min_from_stats_line(stats_line: str) -> float | None:
    match = NMAP_REMAINING_RE.search(stats_line or "")
    if match is None:
        return None
    h = int(match.group(1) or 0)
    m = int(match.group(2) or 0)
    s = int(match.group(3) or 0)
    return max(0.0, float((h * 60) + m + (s / 60.0)))


_PRIVILEGE_MARKERS = (
    "raw packet access was unavailable",
    "tcp connect scan (-st)",
)


def _is_privilege_escalation_warning(message: str) -> bool:
    lower = message.lower()
    return any(marker in lower for marker in _PRIVILEGE_MARKERS)


def nmap_scan_warning_event(
    message: str,
    result: nmap_adapter.NmapRunResult | None = None,
    *,
    requires_privilege_escalation: bool | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if result is not None:
        data = {"command": result.command, "targets": result.targets}
    is_privilege = requires_privilege_escalation if requires_privilege_escalation is not None else _is_privilege_escalation_warning(message)
    return {
        "ts": datetime.now(UTC).isoformat(),
        "message": message,
        "level": "warning",
        "module": "port_scan",
        "requires_privilege_escalation": is_privilege,
        "data": data,
    }


def record_nmap_scan_warnings(
    connection: Any,
    task_id: str,
    result: nmap_adapter.NmapRunResult,
) -> None:
    warnings = [str(item).strip() for item in getattr(result, "scan_warnings", []) if str(item).strip()]
    if not warnings:
        return
    current = get_task(connection, task_id)
    existing = []
    if isinstance(current.cursor_json, dict) and isinstance(current.cursor_json.get("nmap_scan_warnings"), list):
        existing = list(current.cursor_json["nmap_scan_warnings"])
    seen = {str(item.get("message") or "") for item in existing if isinstance(item, dict)}
    merged = list(existing)
    for warning in warnings:
        if warning in seen:
            continue
        seen.add(warning)
        merged.append(nmap_scan_warning_event(warning, result))
    runner_core._merge_task_cursor_json(connection, task_id, {"nmap_scan_warnings": merged})


def http_probe_urls_from_port_findings(findings: list[Finding]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        ev = finding.evidence_json if isinstance(finding.evidence_json, dict) else {}
        url = runner_core._candidate_http_probe_target_from_port_scan_evidence(ev)
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def run_cancelled(connection: Any, run_id: str) -> bool:
    r = get_run(connection, run_id)
    return r is not None and str(r.status) == "cancelled"


def load_port_scan_findings_for_task(
    connection: Any, run_id: str, task_id: str
) -> list[Finding]:
    rows = connection.execute(
        """
        SELECT finding_id, run_id, task_id, module, target, status, summary, evidence_json, tags_json, created_at
        FROM findings
        WHERE run_id = ? AND task_id = ? AND module = 'port_scan'
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id, task_id),
    ).fetchall()
    out: list[Finding] = []
    for row in rows:
        out.append(
            Finding(
                finding_id=row["finding_id"],
                run_id=row["run_id"],
                task_id=row["task_id"],
                module=row["module"],
                target=row["target"],
                status=row["status"],
                summary=row["summary"],
                evidence_json=json.loads(row["evidence_json"]),
                tags=json.loads(row["tags_json"] or "[]") if row["tags_json"] else [],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
        )
    return out
