from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scanner.adapters.ffuf_runner import FfufResultEntry, FfufRunResult
from scanner.models import Finding
from scanner.normalizers.dirscan import normalize_ffuf_result, normalize_ffuf_results
from scanner.runner import create_scan_run, execute_dir_enum_tasks
from scanner.state import get_run, get_task
from scanner.storage import connect, insert_finding


def test_normalize_ffuf_results_output() -> None:
    observed_at = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    result = FfufRunResult(
        command=["ffuf", "-of", "json"],
        base_url="https://app.example.com/",
        output_path=Path("/tmp/ffuf.json"),
        raw_output="",
        matches=[
            FfufResultEntry(
                url="https://app.example.com/admin",
                status_code=200,
                length=1234,
                words=111,
                lines=25,
                content_type="text/html",
                redirect_target=None,
                host="app.example.com",
                input_value="admin",
                position=1,
                raw_entry={"url": "https://app.example.com/admin"},
            ),
            FfufResultEntry(
                url="https://app.example.com/login",
                status_code=302,
                length=0,
                words=0,
                lines=0,
                content_type=None,
                redirect_target="https://app.example.com/sign-in",
                host="app.example.com",
                input_value="login",
                position=2,
                raw_entry={"url": "https://app.example.com/login"},
            ),
        ],
    )

    findings = normalize_ffuf_results(
        result,
        run_id="run-ffuf",
        task_id="task-ffuf",
        observed_at=observed_at,
    )

    assert [finding.target for finding in findings] == [
        "https://app.example.com:443/admin",
        "https://app.example.com:443/login",
    ]
    assert findings[0].module == "dir_enum"
    assert findings[0].tags == ["dirscan", "path", "ffuf"]
    assert findings[0].evidence_json["status_code"] == 200
    assert findings[1].tags == ["dirscan", "path", "ffuf", "redirect"]
    assert findings[1].evidence_json["redirect_target"] == "https://app.example.com/sign-in"
    assert findings[1].summary == "Discovered path https://app.example.com:443/login [302]"
    assert findings[1].created_at == observed_at
    assert findings[0].evidence_json["type"] == "directory"
    assert findings[0].evidence_json["source"] == "ffuf"
    assert findings[0].evidence_json["path"] == "/admin"
    assert findings[0].evidence_json["port"] == 443
    assert findings[0].evidence_json["service_id"] == "app.example.com:443"
    assert findings[0].evidence_json["metadata_json"] == {"depth": 1, "parent": "https://app.example.com:443/"}


def test_normalize_ffuf_result_dedups_by_host_port_path() -> None:
    observed_at = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    result = FfufRunResult(
        command=["ffuf", "-of", "json"],
        base_url="https://app.example.com/",
        output_path=Path("/tmp/ffuf.json"),
        raw_output="",
        matches=[
            FfufResultEntry(
                url="https://app.example.com/admin",
                status_code=200,
                length=1234,
                words=111,
                lines=25,
                content_type="text/html",
                redirect_target=None,
                host="app.example.com",
                input_value="admin",
                position=1,
                raw_entry={"url": "https://app.example.com/admin"},
            ),
            FfufResultEntry(
                url="https://app.example.com:443/admin",
                status_code=403,
                length=333,
                words=22,
                lines=4,
                content_type="text/html",
                redirect_target=None,
                host="app.example.com",
                input_value="admin",
                position=2,
                raw_entry={"url": "https://app.example.com:443/admin"},
            ),
        ],
    )
    findings = normalize_ffuf_results(result, run_id="run-ffuf", task_id="task-ffuf", observed_at=observed_at)
    assert len(findings) == 1
    normalized = normalize_ffuf_result(result.matches[0], result.base_url)
    assert normalized["path"] == "/admin"
    assert normalized["url"] == "https://app.example.com:443/admin"
    assert normalized["depth"] == 1


def test_execute_dir_enum_tasks_uses_seeded_live_http_targets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    created = create_scan_run("example.net", modules=["dir_enum"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    state_db_path = Path(created["state_db_path"])
    configured_wordlist_path = tmp_path / "ffuf-wordlist.txt"
    configured_wordlist_path.write_text("admin\nprivate\n", encoding="utf-8")
    connection = connect(state_db_path)

    try:
        config_row = connection.execute(
            "SELECT config_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        assert config_row is not None
        config_payload = json.loads(config_row["config_json"])
        config_payload["ffuf_wordlist_path"] = str(configured_wordlist_path)
        connection.execute(
            "UPDATE runs SET config_json = ? WHERE run_id = ?",
            (json.dumps(config_payload, sort_keys=True, separators=(",", ":")), run_id),
        )

        insert_finding(
            connection,
            Finding(
                finding_id="finding-httpx-host-1",
                run_id=run_id,
                module="http_probe",
                target="api.example.net",
                summary="Observed live host api.example.net [200]",
                evidence_json={"url": "https://api.example.net/", "status_code": 200},
                tags=["httpx", "alive", "host"],
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-httpx-path-1",
                run_id=run_id,
                module="http_probe",
                target="https://www.example.net/login",
                summary="Observed live path https://www.example.net/login [302]",
                evidence_json={"url": "https://www.example.net/login", "status_code": 302},
                tags=["httpx", "alive", "path"],
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-httpx-host-2",
                run_id=run_id,
                module="http_probe",
                target="blog.example.net",
                summary="Observed live host blog.example.net [200]",
                evidence_json={"url": "http://blog.example.net/", "status_code": 200},
                tags=["httpx", "alive", "host"],
                created_at=now,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    captured_calls: list[dict[str, object]] = []

    def fake_run_ffuf_scan(
        base_url: str,
        *,
        output_path: Path,
        ffuf_bin: str,
        wordlist_path: Path,
        profile: str,
        threads: int,
        match_status_codes,
        extensions: list[str],
        auto_calibration: bool,
        per_host_auto_calibration: bool,
        filter_sizes: list[int],
    ) -> FfufRunResult:
        captured_calls.append(
            {
                "base_url": base_url,
                "wordlist_path": wordlist_path,
                "extensions": extensions,
                "auto_calibration": auto_calibration,
                "per_host_auto_calibration": per_host_auto_calibration,
                "filter_sizes": filter_sizes,
            }
        )
        assert ffuf_bin == "ffuf"
        assert profile == "safe"
        assert threads == 40
        assert list(match_status_codes) == []
        if extensions == [] and auto_calibration is False:
            canary_entries = wordlist_path.read_text(encoding="utf-8").strip().splitlines()
            assert len(canary_entries) == 20
            assert len(set(canary_entries)) == 20
            matches = [
                FfufResultEntry(
                    url=f"{base_url}{entry}",
                    status_code=200,
                    length=75002,
                    words=3679,
                    lines=31,
                    content_type="text/html",
                    redirect_target=None,
                    host=base_url.rstrip("/").split("://", 1)[-1],
                    input_value=entry,
                    position=index,
                    raw_entry={"url": f"{base_url}{entry}"},
                )
                for index, entry in enumerate(canary_entries, start=1)
            ]
        elif base_url == "https://api.example.net/":
            assert wordlist_path == configured_wordlist_path
            assert auto_calibration is True
            assert per_host_auto_calibration is True
            assert filter_sizes == [75002]
            matches = [
                FfufResultEntry(
                    url="https://api.example.net/admin",
                    status_code=200,
                    length=321,
                    words=18,
                    lines=4,
                    content_type="text/html",
                    redirect_target=None,
                    host="api.example.net",
                    input_value="admin",
                    position=1,
                    raw_entry={"url": "https://api.example.net/admin"},
                )
            ]
        else:
            assert wordlist_path == configured_wordlist_path
            assert auto_calibration is True
            assert per_host_auto_calibration is True
            assert filter_sizes == [75002]
            matches = [
                FfufResultEntry(
                    url="http://blog.example.net/private",
                    status_code=403,
                    length=98,
                    words=12,
                    lines=3,
                    content_type="text/html",
                    redirect_target=None,
                    host="blog.example.net",
                    input_value="private",
                    position=2,
                    raw_entry={"url": "http://blog.example.net/private"},
                )
            ]
        raw_output = json.dumps(
            {
                "results": [
                    {
                        "url": match.url,
                        "status": match.status_code,
                        "length": match.length,
                        "words": match.words,
                        "lines": match.lines,
                    }
                    for match in matches
                ]
            }
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(raw_output, encoding="utf-8")
        return FfufRunResult(
            command=[ffuf_bin, "-of", "json"],
            base_url=base_url,
            output_path=output_path,
            matches=matches,
            raw_output=raw_output,
        )

    monkeypatch.setattr("scanner.runner.run_ffuf_scan", fake_run_ffuf_scan)

    summary = execute_dir_enum_tasks(run_id)
    connection = connect(state_db_path)

    try:
        task = get_task(connection, task_id)
        run = get_run(connection, run_id)
        dirscan_findings = connection.execute(
            "SELECT target, summary FROM findings WHERE task_id = ? ORDER BY target ASC",
            (task_id,),
        ).fetchall()
        artifact_rows = connection.execute(
            "SELECT path, content_type FROM artifacts WHERE task_id = ? ORDER BY path ASC",
            (task_id,),
        ).fetchall()
    finally:
        connection.close()

    artifact_paths = [Path(path) for path in summary["tasks"][0]["artifact_paths"]]
    assert task.cursor_json is not None
    calibration_details = task.cursor_json["calibrations"]

    assert [call["base_url"] for call in captured_calls] == [
        "https://api.example.net/",
        "https://api.example.net/",
        "http://blog.example.net/",
        "http://blog.example.net/",
    ]
    assert summary["processed_task_count"] == 1
    assert summary["completed_task_count"] == 1
    assert summary["finding_count"] == 2
    assert summary["artifact_count"] == 2
    assert task.state == "completed"
    assert run is not None
    assert run.status == "completed"
    assert [row["target"] for row in dirscan_findings] == [
        "http://blog.example.net:80/private",
        "https://api.example.net:443/admin",
    ]
    assert len(artifact_rows) == 2
    assert all(row["content_type"] == "application/json" for row in artifact_rows)
    assert all(path.exists() for path in artifact_paths)
    assert all(json.loads(path.read_text(encoding="utf-8"))["results"] for path in artifact_paths)
    assert [item["decision"] for item in calibration_details] == ["auto_filter", "auto_filter"]
    assert all(item["suggested_filter_sizes"] == [75002] for item in calibration_details)


def test_execute_dir_enum_tasks_uses_case_insensitive_wordlist_for_windows_targets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 10, 11, 0, tzinfo=UTC)
    created = create_scan_run("example.net", modules=["dir_enum"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    state_db_path = Path(created["state_db_path"])
    configured_wordlist_path = tmp_path / "small.txt"
    configured_wordlist_path.write_text("Admin\nadmin\nLOGIN\nLogin\nmedia\n", encoding="utf-8")
    connection = connect(state_db_path)

    try:
        config_row = connection.execute(
            "SELECT config_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        assert config_row is not None
        config_payload = json.loads(config_row["config_json"])
        config_payload["ffuf_wordlist_path"] = str(configured_wordlist_path)
        connection.execute(
            "UPDATE runs SET config_json = ? WHERE run_id = ?",
            (json.dumps(config_payload, sort_keys=True, separators=(",", ":")), run_id),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-httpx-host-windows",
                run_id=run_id,
                module="http_probe",
                target="win.example.net",
                summary="Observed live host win.example.net [200]",
                evidence_json={
                    "url": "http://win.example.net/",
                    "status_code": 200,
                    "webserver": "Microsoft-IIS/10.0",
                },
                tags=["httpx", "alive", "host"],
                created_at=now,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    captured_wordlists: list[Path] = []

    def fake_run_ffuf_scan(
        base_url: str,
        *,
        output_path: Path,
        ffuf_bin: str,
        wordlist_path: Path,
        profile: str,
        threads: int,
        match_status_codes,
        extensions: list[str],
        auto_calibration: bool,
        per_host_auto_calibration: bool,
        filter_sizes: list[int],
    ) -> FfufRunResult:
        assert base_url == "http://win.example.net/"
        assert ffuf_bin == "ffuf"
        assert profile == "safe"
        assert threads == 40
        assert list(match_status_codes) == []
        if auto_calibration is False:
            canary_entries = wordlist_path.read_text(encoding="utf-8").strip().splitlines()
            assert len(canary_entries) == 20
            matches = [
                FfufResultEntry(
                    url=f"{base_url}{entry}",
                    status_code=200,
                    length=2048,
                    words=100,
                    lines=10,
                    content_type="text/html",
                    redirect_target=None,
                    host="win.example.net",
                    input_value=entry,
                    position=index,
                    raw_entry={"url": f"{base_url}{entry}"},
                )
                for index, entry in enumerate(canary_entries, start=1)
            ]
        else:
            captured_wordlists.append(wordlist_path)
            assert wordlist_path != configured_wordlist_path
            assert wordlist_path.read_text(encoding="utf-8").splitlines() == ["admin", "login", "media"]
            assert per_host_auto_calibration is True
            assert filter_sizes == [2048]
            matches = [
                FfufResultEntry(
                    url="http://win.example.net/media",
                    status_code=200,
                    length=123,
                    words=5,
                    lines=1,
                    content_type="text/html",
                    redirect_target=None,
                    host="win.example.net",
                    input_value="media",
                    position=1,
                    raw_entry={"url": "http://win.example.net/media"},
                )
            ]
        raw_output = json.dumps(
            {
                "results": [
                    {
                        "url": match.url,
                        "status": match.status_code,
                        "length": match.length,
                        "words": match.words,
                        "lines": match.lines,
                    }
                    for match in matches
                ]
            }
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(raw_output, encoding="utf-8")
        return FfufRunResult(
            command=[ffuf_bin, "-of", "json"],
            base_url=base_url,
            output_path=output_path,
            matches=matches,
            raw_output=raw_output,
        )

    monkeypatch.setattr("scanner.runner.run_ffuf_scan", fake_run_ffuf_scan)

    summary = execute_dir_enum_tasks(run_id)
    connection = connect(state_db_path)

    try:
        task = get_task(connection, task_id)
    finally:
        connection.close()

    assert summary["completed_task_count"] == 1
    assert summary["finding_count"] == 1
    assert len(captured_wordlists) == 1
    assert task.cursor_json is not None
    assert task.cursor_json["calibrations"][0]["case_insensitive_wordlist"] is True
    assert task.cursor_json["calibrations"][0]["source_wordlist_path"] == str(configured_wordlist_path)
    assert task.cursor_json["calibrations"][0]["effective_wordlist_path"] == str(captured_wordlists[0])


def test_execute_dir_enum_tasks_continues_when_only_one_target_is_ambiguous(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 10, 9, 0, tzinfo=UTC)
    created = create_scan_run("example.net", modules=["dir_enum"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    state_db_path = Path(created["state_db_path"])
    configured_wordlist_path = tmp_path / "ffuf-wordlist.txt"
    configured_wordlist_path.write_text("admin\nprivate\n", encoding="utf-8")
    connection = connect(state_db_path)

    try:
        config_row = connection.execute(
            "SELECT config_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        assert config_row is not None
        config_payload = json.loads(config_row["config_json"])
        config_payload["ffuf_wordlist_path"] = str(configured_wordlist_path)
        connection.execute(
            "UPDATE runs SET config_json = ? WHERE run_id = ?",
            (json.dumps(config_payload, sort_keys=True, separators=(",", ":")), run_id),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-httpx-host-ambiguous",
                run_id=run_id,
                module="http_probe",
                target="api.example.net",
                summary="Observed live host api.example.net [200]",
                evidence_json={"url": "https://api.example.net/", "status_code": 200},
                tags=["httpx", "alive", "host"],
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-httpx-host-clear",
                run_id=run_id,
                module="http_probe",
                target="blog.example.net",
                summary="Observed live host blog.example.net [200]",
                evidence_json={"url": "http://blog.example.net/", "status_code": 200},
                tags=["httpx", "alive", "host"],
                created_at=now,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    captured_calls: list[dict[str, object]] = []

    def fake_run_ffuf_scan(
        base_url: str,
        *,
        output_path: Path,
        ffuf_bin: str,
        wordlist_path: Path,
        profile: str,
        threads: int,
        match_status_codes,
        extensions: list[str],
        auto_calibration: bool,
        per_host_auto_calibration: bool,
        filter_sizes: list[int],
    ) -> FfufRunResult:
        captured_calls.append(
            {
                "base_url": base_url,
                "auto_calibration": auto_calibration,
                "per_host_auto_calibration": per_host_auto_calibration,
                "filter_sizes": filter_sizes,
            }
        )
        assert ffuf_bin == "ffuf"
        assert profile == "safe"
        assert threads == 40
        assert list(match_status_codes) == []
        if auto_calibration is False:
            assert extensions == []
            assert per_host_auto_calibration is False
            assert filter_sizes == []
            canary_entries = wordlist_path.read_text(encoding="utf-8").strip().splitlines()
            assert len(canary_entries) == 20
            if base_url == "https://api.example.net/":
                matches: list[FfufResultEntry] = []
                for index, entry in enumerate(canary_entries[:11], start=1):
                    matches.append(
                        FfufResultEntry(
                            url=f"https://api.example.net/{entry}",
                            status_code=200,
                            length=75002,
                            words=3679,
                            lines=31,
                            content_type="text/html",
                            redirect_target=None,
                            host="api.example.net",
                            input_value=entry,
                            position=index,
                            raw_entry={"url": f"https://api.example.net/{entry}"},
                        )
                    )
                for index, entry in enumerate(canary_entries[11:], start=12):
                    matches.append(
                        FfufResultEntry(
                            url=f"https://api.example.net/{entry}",
                            status_code=200,
                            length=64000,
                            words=2900,
                            lines=28,
                            content_type="text/html",
                            redirect_target=None,
                            host="api.example.net",
                            input_value=entry,
                            position=index,
                            raw_entry={"url": f"https://api.example.net/{entry}"},
                        )
                    )
            else:
                matches = [
                    FfufResultEntry(
                        url=f"http://blog.example.net/{entry}",
                        status_code=200,
                        length=75002,
                        words=3679,
                        lines=31,
                        content_type="text/html",
                        redirect_target=None,
                        host="blog.example.net",
                        input_value=entry,
                        position=index,
                        raw_entry={"url": f"http://blog.example.net/{entry}"},
                    )
                    for index, entry in enumerate(canary_entries, start=1)
                ]
        else:
            assert base_url == "http://blog.example.net/"
            assert per_host_auto_calibration is True
            assert filter_sizes == [75002]
            matches = [
                FfufResultEntry(
                    url="http://blog.example.net/private",
                    status_code=403,
                    length=98,
                    words=12,
                    lines=3,
                    content_type="text/html",
                    redirect_target=None,
                    host="blog.example.net",
                    input_value="private",
                    position=1,
                    raw_entry={"url": "http://blog.example.net/private"},
                )
            ]
        raw_output = json.dumps(
            {
                "results": [
                    {
                        "url": match.url,
                        "status": match.status_code,
                        "length": match.length,
                        "words": match.words,
                        "lines": match.lines,
                    }
                    for match in matches
                ]
            }
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(raw_output, encoding="utf-8")
        return FfufRunResult(
            command=[ffuf_bin, "-of", "json"],
            base_url=base_url,
            output_path=output_path,
            matches=matches,
            raw_output=raw_output,
        )

    monkeypatch.setattr("scanner.runner.run_ffuf_scan", fake_run_ffuf_scan)

    summary = execute_dir_enum_tasks(run_id)
    connection = connect(state_db_path)

    try:
        task = get_task(connection, task_id)
        run = get_run(connection, run_id)
        finding_count = connection.execute(
            "SELECT COUNT(*) AS count FROM findings WHERE task_id = ?",
            (task_id,),
        ).fetchone()["count"]
        artifact_count = connection.execute(
            "SELECT COUNT(*) AS count FROM artifacts WHERE task_id = ?",
            (task_id,),
        ).fetchone()["count"]
        finding_targets = connection.execute(
            "SELECT target FROM findings WHERE task_id = ? ORDER BY target ASC",
            (task_id,),
        ).fetchall()
    finally:
        connection.close()

    assert [call["base_url"] for call in captured_calls] == [
        "https://api.example.net/",
        "http://blog.example.net/",
        "http://blog.example.net/",
    ]
    assert summary["processed_task_count"] == 1
    assert summary["completed_task_count"] == 1
    assert summary["failed_task_count"] == 0
    assert summary["finding_count"] == 1
    assert summary["artifact_count"] == 1
    assert task.state == "completed"
    assert run is not None
    assert run.status == "completed"
    assert task.last_error is None
    assert task.cursor_json is not None
    assert task.cursor_json["scan_count"] == 1
    assert task.cursor_json["confirmation_required_count"] == 1
    assert task.cursor_json["confirmation_required_targets"][0]["stage"] == "ffuf_confirmation_required"
    assert task.cursor_json["confirmation_required_targets"][0]["base_url"] == "https://api.example.net/"
    assert task.cursor_json["confirmation_required_targets"][0]["suggested_filter_sizes"] == [75002]
    assert summary["tasks"][0]["confirmation_required_count"] == 1
    assert summary["tasks"][0]["confirmation_required_targets"][0]["base_url"] == "https://api.example.net/"
    assert finding_count == 1
    assert artifact_count == 1
    assert [row["target"] for row in finding_targets] == ["http://blog.example.net:80/private"]
