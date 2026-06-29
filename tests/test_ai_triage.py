from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from scanner.ai import analyze, build_evidence, heuristic_triage, plan_followups
from scanner.ai.client import (
    LLMUnavailable,
    _parse_json_object,
    complete_json,
    resolve_api_key,
    resolve_model,
)
from scanner.ai.models import TargetRisk, TriageResult
from scanner.execution import ai_triage as ai_triage_execution
from scanner.models import Finding, ScanConfig
from scanner.runner import create_scan_run
from scanner.storage import connect, insert_finding


def _finding(module: str, target: str, evidence: dict, *, summary: str = "") -> Finding:
    return Finding(
        finding_id=f"finding-{module}-{target}".replace("/", "_").replace(":", "_"),
        run_id="r1",
        module=module,  # type: ignore[arg-type]
        target=target,
        status="observed",
        summary=summary or f"{module} {target}",
        evidence_json=evidence,
        created_at=datetime.now(UTC),
    )


# --- analyst / heuristic -------------------------------------------------------


def test_build_evidence_groups_by_module() -> None:
    findings = [
        _finding("subdomain_enum", "admin.example.org", {"host": "admin.example.org"}),
        _finding("http_probe", "https://admin.example.org", {"url": "https://admin.example.org", "status_code": 403, "title": "Admin Login"}),
        _finding("port_scan", "db.example.org", {"host": "db.example.org", "port": 3306, "service": "mysql"}),
    ]
    evidence = build_evidence(findings)
    assert evidence["subdomains"] == ["admin.example.org"]
    assert evidence["live_hosts"][0]["status"] == 403
    assert evidence["open_ports"][0]["port"] == 3306


def test_heuristic_scores_high_risk_port_and_keywords() -> None:
    evidence = {
        "subdomains": ["admin.example.org", "www.example.org"],
        "live_hosts": [{"url": "https://admin.example.org", "status": 403, "title": "Admin Login"}],
        "open_ports": [{"host": "db.example.org", "port": 3306, "service": "mysql"}],
        "dir_findings": [],
        "candidate_cves": [],
    }
    result = heuristic_triage(evidence)
    assert result.source == "heuristic"
    by_target = {risk.target.lower(): risk for risk in result.targets}
    assert by_target["db.example.org"].risk_score >= 0.6
    # admin host (keyword admin + login + 403) clears the act threshold
    assert any(r.risk_score >= 0.6 for t, r in by_target.items() if "admin" in t)


def test_candidate_cve_forces_high_risk() -> None:
    evidence = {
        "subdomains": ["shop.example.org"],
        "live_hosts": [],
        "open_ports": [],
        "dir_findings": [],
        "candidate_cves": [{"target": "shop.example.org", "cve": "CVE-2021-41773"}],
    }
    result = heuristic_triage(evidence)
    risk = next(r for r in result.targets if r.target == "shop.example.org")
    assert risk.risk_score == 0.9
    assert "candidate_cve" in risk.signals


def test_analyze_falls_back_to_heuristic_without_api_key(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config = ScanConfig(target="example.org")
    evidence = {"subdomains": ["admin.example.org"], "live_hosts": [], "open_ports": [], "dir_findings": [], "candidate_cves": []}
    result = analyze(evidence, config)
    assert result.source == "heuristic"


# --- planner safety ------------------------------------------------------------


def test_plan_followups_respects_scope_threshold_and_budget() -> None:
    triage = TriageResult(
        targets=[
            TargetRisk(target="https://admin.example.org", risk_score=0.8, suggested_modules=["dir_enum"]),
            TargetRisk(target="db.example.org", risk_score=0.7, suggested_modules=["http_probe"]),
            TargetRisk(target="low.example.org", risk_score=0.2, suggested_modules=["http_probe"]),
            TargetRisk(target="evil.attacker.com", risk_score=0.99, suggested_modules=["dir_enum"]),
        ]
    )

    def in_scope(scope: str) -> bool:
        return "example.org" in scope

    actions = plan_followups(triage, in_scope=in_scope, min_risk=0.6, budget=10)
    scopes = {a.scope for a in actions}
    # out-of-scope target dropped, below-threshold dropped
    assert "https://admin.example.org" in scopes
    assert "db.example.org" in scopes
    assert not any("attacker.com" in s for s in scopes)
    assert not any("low.example.org" in s for s in scopes)


def test_plan_followups_dedupes_and_caps_budget() -> None:
    triage = TriageResult(
        targets=[
            TargetRisk(target="a.example.org", risk_score=0.9, suggested_modules=["http_probe"]),
            TargetRisk(target="b.example.org", risk_score=0.9, suggested_modules=["http_probe"]),
        ]
    )
    actions = plan_followups(
        triage,
        in_scope=lambda s: True,
        min_risk=0.6,
        budget=1,
        already_scoped=[("http_probe", "a.example.org")],
    )
    assert len(actions) == 1
    assert actions[0].scope == "b.example.org"


# --- client (offline) ----------------------------------------------------------


def test_resolve_helpers(monkeypatch) -> None:
    monkeypatch.setenv("MY_KEY", "  secret  ")
    assert resolve_api_key("MY_KEY") == "secret"
    assert resolve_api_key("MISSING_KEY") is None
    assert resolve_model("anthropic", "") == "claude-sonnet-4-6"
    assert resolve_model("openai", "gpt-x") == "gpt-x"


def test_parse_json_object_extracts_from_fenced_text() -> None:
    text = "Here you go:\n```json\n{\"summary\": \"ok\", \"targets\": []}\n```"
    parsed = _parse_json_object(text)
    assert parsed["summary"] == "ok"


def test_complete_json_anthropic_with_mock_transport() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "k"
        return httpx.Response(200, json={"content": [{"type": "text", "text": "{\"summary\": \"hi\", \"targets\": []}"}]})

    out = complete_json(
        provider="anthropic",
        model="",
        api_key="k",
        system="s",
        user="u",
        transport=httpx.MockTransport(handler),
    )
    assert out["summary"] == "hi"


def test_complete_json_raises_on_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with pytest.raises(LLMUnavailable):
        complete_json(
            provider="openai",
            model="gpt-x",
            api_key="k",
            system="s",
            user="u",
            transport=httpx.MockTransport(handler),
        )


# --- executor end-to-end (offline, act mode) -----------------------------------


def test_execute_ai_triage_enqueues_scope_locked_followups(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    now = datetime(2026, 6, 28, 9, 0, tzinfo=UTC)
    created = create_scan_run("example.org", modules=["http_probe", "ai_triage"])
    run_id = created["run_id"]
    connection = connect(Path(created["state_db_path"]))
    try:
        insert_finding(connection, Finding(
            finding_id="finding-sub-admin", run_id=run_id, module="subdomain_enum",
            target="admin.example.org", status="observed", summary="admin.example.org",
            evidence_json={"host": "admin.example.org"}, created_at=now,
        ))
        insert_finding(connection, Finding(
            finding_id="finding-http-admin", run_id=run_id, module="http_probe",
            target="https://admin.example.org", status="observed", summary="live",
            evidence_json={"url": "https://admin.example.org", "status_code": 403, "title": "Admin Login"},
            created_at=now,
        ))
        insert_finding(connection, Finding(
            finding_id="finding-port-db", run_id=run_id, module="port_scan",
            target="db.example.org", status="observed", summary="mysql",
            evidence_json={"host": "db.example.org", "port": 3306, "service": "mysql"},
            created_at=now,
        ))
    finally:
        connection.close()

    summary = ai_triage_execution.execute_ai_triage_tasks(run_id)

    assert summary["completed_task_count"] == 1
    assert summary["finding_count"] >= 2
    assert summary["followup_count"] >= 1

    connection = connect(Path(created["state_db_path"]))
    try:
        ai_findings = connection.execute(
            "SELECT target, tags_json FROM findings WHERE module = 'ai_triage'"
        ).fetchall()
        followup_tasks = connection.execute(
            "SELECT module, scope, cursor_json FROM tasks WHERE module IN ('http_probe', 'dir_enum', 'port_scan') AND cursor_json LIKE '%ai_triage%'"
        ).fetchall()
    finally:
        connection.close()

    assert ai_findings, "expected persisted ai_triage findings"
    assert followup_tasks, "expected autonomously enqueued follow-up tasks"
    for row in followup_tasks:
        # every autonomous scope stays inside the authorized domain
        assert "example.org" in row["scope"]
        assert json.loads(row["cursor_json"])["origin"] == "ai_triage"
