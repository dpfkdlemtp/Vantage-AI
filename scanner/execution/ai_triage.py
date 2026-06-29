"""Executor for the ai_triage phase: LLM-in-the-loop risk triage and autonomous follow-up.

Flow per task:
  1. load all findings collected so far and build a compact evidence summary;
  2. ask the analyst (LLM, or deterministic heuristic offline) to score targets by risk;
  3. persist one candidate finding per scored target;
  4. in "act" mode, enqueue safe, in-scope, budgeted follow-up scans for the riskiest
     targets and (up to ai_max_iterations) re-queue ai_triage so it can react to the new
     findings -- a bounded agentic loop.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from scanner import runner as runner_core
from scanner.ai import analyze, build_evidence, plan_followups
from scanner.ai.models import FollowupAction, TriageResult
from scanner.config import classify_target, resolve_tool
from scanner.models import Finding, ScanConfig, TaskState
from scanner.state import (
    get_incomplete_tasks,
    get_tasks,
    is_run_cancelled,
    mark_run_finished,
    mark_run_running,
    mark_task_completed,
    mark_task_failed,
    mark_task_running,
)
from scanner.storage import insert_finding, insert_task


def execute_ai_triage_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = runner_core._open_run_connection(run_id, workspace=workspace)
    try:
        run = runner_core._require_run(connection, run_id)
        empty = _empty_result(run_id)
        if is_run_cancelled(connection, run_id):
            return empty

        tasks = [
            task
            for task in get_incomplete_tasks(connection, run_id)
            if task.module == "ai_triage" and task.tool == "ai_analyst"
        ]
        if not tasks:
            return empty

        mark_run_running(connection, run_id)
        completed = 0
        failed = 0
        finding_count = 0
        followup_count = 0
        summaries: list[dict[str, Any]] = []

        for task in tasks:
            if is_run_cancelled(connection, run_id):
                summaries.append({**runner_core._task_summary(task), "state": "cancelled"})
                break
            try:
                result, findings, followups = _run_one_triage(connection, run.config, run_id, task)
                finding_count += findings
                followup_count += followups
                completed += 1
                summaries.append(
                    {
                        "task_id": task.task_id,
                        "module": task.module,
                        "tool": task.tool,
                        "scope": task.scope,
                        "state": "completed",
                        "source": result.source,
                        "scored_targets": len(result.targets),
                        "finding_count": findings,
                        "followups_enqueued": followups,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - surface error on the task, keep run alive
                mark_task_failed(
                    connection, task.task_id, str(exc), cursor_json={"stage": "ai_triage_failed"}
                )
                failed += 1
                summaries.append({**runner_core._task_summary(task), "state": "failed", "last_error": str(exc)})

        if not get_incomplete_tasks(connection, run_id):
            mark_run_finished(connection, run_id, "completed")

        return {
            "run_id": run_id,
            "processed_task_count": len(tasks),
            "completed_task_count": completed,
            "failed_task_count": failed,
            "finding_count": finding_count,
            "followup_count": followup_count,
            "artifact_count": 0,
            "tasks": summaries,
        }
    finally:
        connection.close()


def _run_one_triage(
    connection: sqlite3.Connection,
    config: ScanConfig,
    run_id: str,
    task: TaskState,
) -> tuple[TriageResult, int, int]:
    runner_core._clear_task_outputs(connection, task)
    findings = _load_all_findings(connection, run_id)
    evidence = build_evidence(findings)
    mark_task_running(
        connection,
        task.task_id,
        cursor_json={"stage": "ai_triage", "input_findings": len(findings)},
    )

    if not config.ai_triage_enabled or config.ai_autonomy == "off":
        mark_task_completed(
            connection,
            task.task_id,
            cursor_json={"skipped": True, "reason": "ai_triage disabled"},
        )
        return TriageResult(summary="ai_triage disabled"), 0, 0

    result = analyze(evidence, config)
    persisted = _persist_triage_findings(connection, run_id, task.task_id, result)

    followups: list[FollowupAction] = []
    if config.ai_autonomy == "act":
        followups = _enqueue_followups(connection, config, run_id, evidence, result)
        _maybe_requeue_triage(connection, run_id, config)

    mark_task_completed(
        connection,
        task.task_id,
        cursor_json={
            "source": result.source,
            "model": result.model,
            "input_findings": len(findings),
            "scored_targets": len(result.targets),
            "finding_count": persisted,
            "followups": [a.model_dump(mode="json") for a in followups],
        },
    )
    return result, persisted, len(followups)


def _persist_triage_findings(
    connection: sqlite3.Connection, run_id: str, task_id: str, result: TriageResult
) -> int:
    count = 0
    for risk in result.targets:
        band = "high" if risk.risk_score >= 0.7 else "medium" if risk.risk_score >= 0.4 else "low"
        finding = Finding(
            finding_id=f"finding-{uuid4().hex}",
            run_id=run_id,
            task_id=task_id,
            module="ai_triage",
            target=risk.target,
            status="candidate",
            summary=f"AI risk {risk.risk_score:.2f} ({band}): {risk.rationale or 'observed surface'}",
            evidence_json={
                "risk_score": risk.risk_score,
                "rationale": risk.rationale,
                "signals": risk.signals,
                "suggested_modules": list(risk.suggested_modules),
                "analysis_source": result.source,
                "model": result.model,
                "candidate_only": True,
            },
            tags=["ai", f"risk:{band}", f"src:{result.source}"],
            created_at=datetime.now(UTC),
        )
        insert_finding(connection, finding)
        count += 1
    return count


def _enqueue_followups(
    connection: sqlite3.Connection,
    config: ScanConfig,
    run_id: str,
    evidence: dict[str, Any],
    result: TriageResult,
) -> list[FollowupAction]:
    spent = _followups_already_spent(connection, run_id)
    remaining = max(0, config.ai_max_followups - spent)
    if remaining <= 0:
        return []

    in_scope = _build_scope_predicate(config.target, evidence)
    already = {
        (str(t.module), str(t.scope))
        for t in get_tasks(connection, run_id)
        if t.module in ("http_probe", "dir_enum", "port_scan")
    }
    actions = plan_followups(
        result,
        in_scope=in_scope,
        min_risk=config.ai_min_risk_to_act,
        budget=remaining,
        already_scoped=already,
    )
    now = runner_core._now()
    enqueued: list[FollowupAction] = []
    for action in actions:
        if runner_core._task_exists(connection, run_id, action.module, action.scope):
            continue
        insert_task(
            connection,
            TaskState(
                task_id=f"task-{uuid4().hex}",
                run_id=run_id,
                module=action.module,
                tool=resolve_tool(action.module),
                scope=action.scope,
                state="pending",
                cursor_json={"origin": "ai_triage", "risk_score": action.risk_score},
                created_at=now,
                updated_at=now,
            ),
        )
        enqueued.append(action)
    return enqueued


def _maybe_requeue_triage(
    connection: sqlite3.Connection, run_id: str, config: ScanConfig
) -> None:
    """Re-queue ai_triage so it can react to follow-up findings, up to the iteration cap."""

    triage_tasks = [t for t in get_tasks(connection, run_id) if t.module == "ai_triage"]
    iterations_done = len(triage_tasks)
    if iterations_done >= config.ai_max_iterations:
        return
    has_new_work = any(
        t.state in ("pending", "running")
        for t in get_tasks(connection, run_id)
        if t.module in ("http_probe", "dir_enum", "port_scan")
    )
    if not has_new_work:
        return
    scope = f"{config.target}#ai-iter-{iterations_done + 1}"
    if runner_core._task_exists(connection, run_id, "ai_triage", scope):
        return
    now = runner_core._now()
    insert_task(
        connection,
        TaskState(
            task_id=f"task-{uuid4().hex}",
            run_id=run_id,
            module="ai_triage",
            tool="ai_analyst",
            scope=scope,
            state="pending",
            created_at=now,
            updated_at=now,
        ),
    )


def _followups_already_spent(connection: sqlite3.Connection, run_id: str) -> int:
    """Total follow-ups enqueued by all prior ai_triage tasks (budget accounting)."""

    spent = 0
    for task in get_tasks(connection, run_id):
        if task.module != "ai_triage":
            continue
        cursor = task.cursor_json or {}
        followups = cursor.get("followups") if isinstance(cursor, dict) else None
        if isinstance(followups, list):
            spent += len(followups)
    return spent


def _build_scope_predicate(target: str, evidence: dict[str, Any]):
    """Return in_scope(scope) -> bool. Only observed hosts within authorized scope pass."""

    observed = _observed_hosts(evidence)
    kind = classify_target(target)
    suffix = target.strip().lower().rstrip(".") if kind == "domain" else ""

    def in_scope(scope: str) -> bool:
        host = _host_of_scope(scope)
        if not host:
            return False
        if host not in observed:
            return False
        if suffix:
            return host == suffix or host.endswith("." + suffix)
        return True

    return in_scope


def _observed_hosts(evidence: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for host in evidence.get("subdomains", []):
        hosts.add(str(host).strip().lower())
    for item in evidence.get("live_hosts", []):
        hosts.add(_host_of_scope(str(item.get("url", ""))))
    for item in evidence.get("open_ports", []):
        hosts.add(str(item.get("host", "")).strip().lower())
    hosts.discard("")
    return hosts


def _host_of_scope(scope: str) -> str:
    scope = (scope or "").strip().lower()
    if "://" in scope:
        from urllib.parse import urlsplit

        return (urlsplit(scope).hostname or "").lower()
    return scope.split("/", 1)[0].split(":", 1)[0]


def _load_all_findings(connection: sqlite3.Connection, run_id: str) -> list[Finding]:
    rows = connection.execute(
        """
        SELECT finding_id, run_id, task_id, module, target, status, summary,
               evidence_json, tags_json, created_at
        FROM findings
        WHERE run_id = ?
          AND module IN ('subdomain_enum', 'http_probe', 'dir_enum', 'port_scan',
                         'domain_discovery', 'banner_probe', 'cve_match')
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id,),
    ).fetchall()
    return [
        Finding(
            finding_id=row["finding_id"],
            run_id=row["run_id"],
            task_id=row["task_id"],
            module=row["module"],
            target=row["target"],
            status=row["status"],
            summary=row["summary"],
            evidence_json=json.loads(row["evidence_json"]),
            tags=json.loads(row["tags_json"]) if row["tags_json"] else [],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
        for row in rows
    ]


def _empty_result(run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "processed_task_count": 0,
        "completed_task_count": 0,
        "failed_task_count": 0,
        "finding_count": 0,
        "followup_count": 0,
        "artifact_count": 0,
        "tasks": [],
    }
