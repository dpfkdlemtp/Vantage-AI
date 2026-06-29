from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from scanner.runner import create_scan_run
from scanner.storage import (
    connect,
    delete_service_note_by_id,
    fetch_service_note_by_id,
    insert_service_note,
    list_service_notes,
    update_service_note_text,
)
from scanner.web import WebUIApp


def test_service_notes_table_created_for_new_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("10.0.0.1", modules=["port_scan"])
    run_id = summary["run_id"]
    db = tmp_path / "runs" / run_id / "state.db"
    assert db.is_file()
    connection = connect(db)
    try:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='service_notes'",
        ).fetchone()
        assert row is not None
    finally:
        connection.close()


def test_legacy_state_db_gains_service_notes_on_connect(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    raw = sqlite3.connect(db)
    try:
        raw.execute("CREATE TABLE runs (run_id TEXT PRIMARY KEY, target TEXT, status TEXT, config_json TEXT)")
        raw.commit()
    finally:
        raw.close()

    connection = connect(db)
    try:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='service_notes'",
        ).fetchone()
        assert row is not None
        assert list_service_notes(connection) == []
    finally:
        connection.close()


def test_service_note_crud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("10.0.0.2", modules=["port_scan"])
    run_id = summary["run_id"]
    db = tmp_path / "runs" / run_id / "state.db"
    connection = connect(db)
    try:
        now = "2026-04-27T12:00:00+00:00"
        insert_service_note(
            connection,
            note_id="note-aaa",
            host="10.0.0.2",
            port=443,
            protocol="tcp",
            service_name="https",
            note="first",
            created_at=now,
            updated_at=now,
        )
        notes = list_service_notes(connection)
        assert len(notes) == 1
        assert notes[0]["note"] == "first"

        assert update_service_note_text(connection, "note-aaa", "second", "2026-04-27T12:01:00+00:00") == 1
        r = fetch_service_note_by_id(connection, "note-aaa")
        assert r is not None
        assert r["note"] == "second"

        assert delete_service_note_by_id(connection, "note-aaa") == 1
        assert list_service_notes(connection) == []
    finally:
        connection.close()


def test_web_create_list_update_delete_service_notes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("10.0.0.3", modules=["port_scan"])
    run_id = summary["run_id"]
    app = WebUIApp(workspace=tmp_path)

    assert app.list_service_notes(run_id) == {"notes": []}

    created = app.create_service_note(
        run_id,
        {
            "host": "10.0.0.3",
            "port": 22,
            "protocol": "tcp",
            "service_name": "ssh",
            "note": "  jump box  ",
        },
    )
    assert created["port"] == 22
    assert created["note"] == "jump box"
    note_id = str(created["id"])

    listed = app.list_service_notes(run_id)
    assert len(listed["notes"]) == 1

    updated = app.update_service_note(run_id, note_id, {"note": "updated"})
    assert updated["note"] == "updated"
    assert app.delete_service_note(run_id, note_id) == {"success": True}


def test_web_create_rejects_invalid_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("10.0.0.4", modules=["port_scan"])
    run_id = summary["run_id"]
    app = WebUIApp(workspace=tmp_path)

    with pytest.raises(ValueError, match="host"):
        app.create_service_note(run_id, {"host": "  ", "port": 80, "note": "x"})

    with pytest.raises(ValueError, match="port"):
        app.create_service_note(run_id, {"host": "a", "port": 99999, "note": "x"})

    with pytest.raises(ValueError, match="note"):
        app.create_service_note(run_id, {"host": "a", "port": 80, "note": "  "})


def test_create_run_rerun_can_copy_service_notes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    source = create_scan_run("10.0.0.10", modules=["port_scan"])
    source_id = source["run_id"]
    source_db = tmp_path / "runs" / source_id / "state.db"
    connection = connect(source_db)
    try:
        insert_service_note(
            connection,
            note_id="note-src-1",
            host="10.0.0.10",
            port=443,
            protocol="tcp",
            service_name="https",
            note="keep this context",
            created_at="2026-04-27T12:00:00+00:00",
            updated_at="2026-04-27T12:00:00+00:00",
        )
    finally:
        connection.close()

    app = WebUIApp(workspace=tmp_path)
    cloned = app.create_run(
        {
            "target": "10.0.0.20",
            "modules": ["port_scan"],
            "source_run_id": source_id,
            "include_notes_context": True,
        }
    )
    cloned_id = str(cloned["run"]["run_id"])
    cloned_db = tmp_path / "runs" / cloned_id / "state.db"
    c2 = connect(cloned_db)
    try:
        notes = list_service_notes(c2)
    finally:
        c2.close()
    assert len(notes) == 1
    assert notes[0]["note"] == "keep this context"


def test_create_run_rerun_without_notes_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    source = create_scan_run("10.0.0.11", modules=["port_scan"])
    source_id = source["run_id"]
    source_db = tmp_path / "runs" / source_id / "state.db"
    connection = connect(source_db)
    try:
        insert_service_note(
            connection,
            note_id="note-src-2",
            host="10.0.0.11",
            port=22,
            protocol="tcp",
            service_name="ssh",
            note="do not copy",
            created_at="2026-04-27T12:00:00+00:00",
            updated_at="2026-04-27T12:00:00+00:00",
        )
    finally:
        connection.close()

    app = WebUIApp(workspace=tmp_path)
    cloned = app.create_run(
        {
            "target": "10.0.0.21",
            "modules": ["port_scan"],
            "source_run_id": source_id,
            "include_notes_context": False,
        }
    )
    cloned_id = str(cloned["run"]["run_id"])
    cloned_db = tmp_path / "runs" / cloned_id / "state.db"
    c2 = connect(cloned_db)
    try:
        notes = list_service_notes(c2)
    finally:
        c2.close()
    assert notes == []
