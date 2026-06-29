from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner import runner as runner_core
from scanner.normalizers.cve_candidates import match_cve_candidates
from scanner.state import (
    get_incomplete_tasks,
    is_run_cancelled,
    mark_run_finished,
    mark_run_running,
    mark_task_completed,
    mark_task_failed,
    mark_task_running,
)
from scanner.storage import insert_finding


def execute_cve_match_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = runner_core._open_run_connection(run_id, workspace=workspace)
    try:
        run = runner_core._require_run(connection, run_id)
        if is_run_cancelled(connection, run_id):
            return {
                "run_id": run_id,
                "processed_task_count": 0,
                "completed_task_count": 0,
                "failed_task_count": 0,
                "finding_count": 0,
                "artifact_count": 0,
                "tasks": [],
            }
        tasks = [
            task
            for task in get_incomplete_tasks(connection, run_id)
            if task.module == "cve_match" and task.tool == "cve_matcher"
        ]
        if not tasks:
            return {
                "run_id": run_id,
                "processed_task_count": 0,
                "completed_task_count": 0,
                "failed_task_count": 0,
                "finding_count": 0,
                "artifact_count": 0,
                "tasks": [],
            }

        mark_run_running(connection, run_id)
        completed_task_count = 0
        failed_task_count = 0
        finding_count = 0
        task_summaries: list[dict[str, Any]] = []

        for task in tasks:
            if is_run_cancelled(connection, run_id):
                task_summaries.append(
                    {
                        "task_id": task.task_id,
                        "module": task.module,
                        "tool": task.tool,
                        "scope": task.scope,
                        "state": "cancelled",
                    }
                )
                break
            try:
                runner_core._clear_task_outputs(connection, task)
                source_findings = runner_core._load_cve_match_source_findings(connection, run_id)
                mark_task_running(
                    connection,
                    task.task_id,
                    cursor_json={"stage": "cve_match", "input_count": len(source_findings)},
                )
                
                if not run.config.cve_matching_enabled or not source_findings:
                    mark_task_completed(
                        connection,
                        task.task_id,
                        cursor_json={
                            "input_count": len(source_findings),
                            "finding_count": 0,
                        },
                    )
                    completed_task_count += 1
                    task_summaries.append(
                        {
                            "task_id": task.task_id,
                            "module": task.module,
                            "tool": task.tool,
                            "scope": task.scope,
                            "state": "completed",
                            "input_count": len(source_findings),
                            "finding_count": 0,
                        }
                    )
                    continue

                new_findings = match_cve_candidates(
                    source_findings,
                    run_id=run.run_id,
                    task_id=task.task_id,
                    min_confidence=run.config.cve_min_confidence,
                )
                if is_run_cancelled(connection, run_id):
                    task_summaries.append(
                        {
                            "task_id": task.task_id,
                            "module": task.module,
                            "tool": task.tool,
                            "scope": task.scope,
                            "state": "cancelled",
                            "input_count": len(source_findings),
                        }
                    )
                    break
                for finding in new_findings:
                    if is_run_cancelled(connection, run_id):
                        task_summaries.append(
                            {
                                "task_id": task.task_id,
                                "module": task.module,
                                "tool": task.tool,
                                "scope": task.scope,
                                "state": "cancelled",
                                "input_count": len(source_findings),
                            }
                        )
                        break
                    insert_finding(connection, finding)
                else:
                    mark_task_completed(
                        connection,
                        task.task_id,
                        cursor_json={
                            "input_count": len(source_findings),
                            "finding_count": len(new_findings),
                        },
                    )
                    completed_task_count += 1
                    finding_count += len(new_findings)
                    task_summaries.append(
                        {
                            "task_id": task.task_id,
                            "module": task.module,
                            "tool": task.tool,
                            "scope": task.scope,
                            "state": "completed",
                            "input_count": len(source_findings),
                            "finding_count": len(new_findings),
                        }
                    )
                    continue
                
                break
            except Exception as exc:
                mark_task_failed(
                    connection,
                    task.task_id,
                    str(exc),
                    cursor_json={"stage": "cve_match_failed"},
                )
                failed_task_count += 1
                task_summaries.append(
                    {
                        "task_id": task.task_id,
                        "module": task.module,
                        "tool": task.tool,
                        "scope": task.scope,
                        "state": "failed",
                        "last_error": str(exc),
                    }
                )

        if not get_incomplete_tasks(connection, run_id):
            mark_run_finished(connection, run_id, "completed")

        return {
            "run_id": run_id,
            "processed_task_count": len(tasks),
            "completed_task_count": completed_task_count,
            "failed_task_count": failed_task_count,
            "finding_count": finding_count,
            "artifact_count": 0,
            "tasks": task_summaries,
        }
    finally:
        connection.close()
