from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scanner.execution.access_control import (
    HttpResponse,
    analyze_unauth_response,
    run_access_control_checks,
    select_bac_candidates,
)
from scanner.models import Finding
from scanner.runner import create_scan_run
from scanner.storage import connect, insert_finding


# --- pure analyzer ---------------------------------------------------------

def test_no_response_not_exposed() -> None:
    assert analyze_unauth_response("http://x/y", None).exposed is False


def test_redirect_and_forbidden_not_exposed() -> None:
    assert analyze_unauth_response("http://x", HttpResponse(302, "text/html", "")).exposed is False
    assert analyze_unauth_response("http://x", HttpResponse(403, "text/html", "denied")).exposed is False
    assert analyze_unauth_response("http://x", HttpResponse(401, "text/html", "")).exposed is False


def test_login_page_200_not_exposed() -> None:
    body = "<html><title>Login</title><form>password</form></html>"
    verdict = analyze_unauth_response("http://x/admin", HttpResponse(200, "text/html", body))
    assert verdict.exposed is False
    assert verdict.reason == "auth_gate_page"


def test_emails_leak_is_high_exposure() -> None:
    body = "a@corp.com\nb@corp.com\nc@corp.com\nd@bank.kr"
    verdict = analyze_unauth_response("http://x/api/members", HttpResponse(200, "application/json", body))
    assert verdict.exposed is True
    assert verdict.severity == "high"
    assert any(i.startswith("emails:") for i in verdict.indicators)


def test_internal_ip_leak_is_high() -> None:
    body = "config: host=10.0.0.5 backup=192.168.0.10"
    verdict = analyze_unauth_response("http://x/system/config", HttpResponse(200, "text/plain", body))
    assert verdict.exposed is True
    assert verdict.severity == "high"
    assert any(i.startswith("internal_ips:") for i in verdict.indicators)


def test_secret_keyword_flagged() -> None:
    body = '{"client_secret": "abc123", "ok": true}'
    verdict = analyze_unauth_response("http://x/api/config", HttpResponse(200, "application/json", body))
    assert verdict.exposed is True
    assert "secret_keyword" in verdict.indicators


def test_json_record_set_medium_exposure() -> None:
    rows = [{"id": i, "name": f"row{i}", "v": "x" * 20} for i in range(40)]
    body = json.dumps(rows)
    verdict = analyze_unauth_response("http://x/api/list", HttpResponse(200, "application/json", body))
    assert verdict.exposed is True
    assert verdict.severity == "medium"


def test_benign_200_not_exposed() -> None:
    verdict = analyze_unauth_response("http://x/", HttpResponse(200, "text/html", "<h1>Welcome</h1>"))
    assert verdict.exposed is False


def test_login_page_that_leaks_data_is_still_flagged() -> None:
    # auth-gate markers present, but real records leak -> not a clean login page.
    body = "Please log in. members: a@x.com b@x.com c@x.com d@x.com"
    verdict = analyze_unauth_response("http://x/admin", HttpResponse(200, "text/html", body))
    assert verdict.exposed is True


# --- candidate selection ---------------------------------------------------

def _dir_finding(run_id: str, url: str, fid: str) -> Finding:
    return Finding(
        finding_id=fid,
        run_id=run_id,
        module="dir_enum",
        target=url,
        summary=f"hit {url}",
        evidence_json={"type": "dirscan_hit", "url": url, "status_code": 200},
        tags=["ffuf"],
        created_at=datetime(2026, 5, 1, tzinfo=UTC),
    )


def test_select_candidates_prioritizes_sensitive_paths_and_dedups(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("target.example", modules=["dir_enum"])
    run_id = summary["run_id"]
    connection = connect(Path(summary["state_db_path"]))
    try:
        insert_finding(connection, _dir_finding(run_id, "https://target.example/home", "f1"))
        insert_finding(connection, _dir_finding(run_id, "https://target.example/admin/users", "f2"))
        insert_finding(connection, _dir_finding(run_id, "https://target.example/home", "f3"))  # dup
        connection.commit()

        candidates = select_bac_candidates(connection, run_id, limit=10)
        urls = [c.url for c in candidates]
        assert urls.count("https://target.example/home") == 1  # deduped
        assert urls[0] == "https://target.example/admin/users"  # sensitive first
    finally:
        connection.close()


def test_select_candidates_respects_scope(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("target.example", modules=["dir_enum"])
    run_id = summary["run_id"]
    connection = connect(Path(summary["state_db_path"]))
    try:
        insert_finding(connection, _dir_finding(run_id, "https://target.example/admin", "f1"))
        insert_finding(connection, _dir_finding(run_id, "https://outofscope.test/admin", "f2"))
        connection.commit()

        in_scope = lambda host: host == "target.example"
        candidates = select_bac_candidates(connection, run_id, limit=10, in_scope=in_scope)
        hosts = {c.host for c in candidates}
        assert hosts == {"target.example"}
    finally:
        connection.close()


# --- end-to-end with injected fetch ---------------------------------------

def test_run_access_control_checks_records_exposure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("target.example", modules=["dir_enum"])
    run_id = summary["run_id"]
    connection = connect(Path(summary["state_db_path"]))
    try:
        insert_finding(connection, _dir_finding(run_id, "https://target.example/api/members", "f1"))
        insert_finding(connection, _dir_finding(run_id, "https://target.example/public", "f2"))
        connection.commit()
        run = __import__("scanner.state", fromlist=["get_run"]).get_run(connection, run_id)

        def fake_fetch(url: str, timeout: float):
            if url.endswith("/api/members"):
                return HttpResponse(200, "application/json", "a@x.com b@x.com c@x.com d@x.com")
            return HttpResponse(200, "text/html", "<h1>public</h1>")

        result = run_access_control_checks(
            connection, run_id, config=run.config, fetch=fake_fetch
        )
        assert result["tested"] == 2
        assert result["findings"] == 1

        rows = connection.execute(
            "SELECT target, evidence_json FROM findings WHERE module = 'access_control'",
        ).fetchall()
        assert len(rows) == 1
        evidence = json.loads(rows[0]["evidence_json"])
        assert evidence["type"] == "broken_access_control"
        assert evidence["url"].endswith("/api/members")
        assert evidence["severity"] == "high"
    finally:
        connection.close()


def test_run_access_control_checks_disabled_noop(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("target.example", modules=["dir_enum"])
    run_id = summary["run_id"]
    connection = connect(Path(summary["state_db_path"]))
    try:
        run = __import__("scanner.state", fromlist=["get_run"]).get_run(connection, run_id)
        object.__setattr__(run.config, "access_control_test_enabled", False)

        called = {"n": 0}

        def fake_fetch(url: str, timeout: float):
            called["n"] += 1
            return HttpResponse(200, "text/html", "x")

        result = run_access_control_checks(
            connection, run_id, config=run.config, fetch=fake_fetch
        )
        assert result.get("skipped") == "disabled"
        assert called["n"] == 0
    finally:
        connection.close()
