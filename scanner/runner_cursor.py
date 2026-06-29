from __future__ import annotations

import json
import sqlite3
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from scanner.utils.logging import get_logger

_log = get_logger(__name__)


def parse_task_cursor_json(raw: object) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            _log.warning("task cursor JSON corrupted, ignoring: %s", exc)
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}
    return {}


def normalize_dirscan_target(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def canonical_http_probe_input_key(url: str) -> str | None:
    stripped = url.strip()
    if not stripped:
        return None
    parsed = urlsplit(stripped)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        base = normalize_dirscan_target(stripped)
        return base.lower() if base else None
    return stripped.lower().rstrip("/")


def http_probe_url_keys_scheduled_or_completed(connection: sqlite3.Connection, run_id: str) -> set[str]:
    keys: set[str] = set()
    for row in connection.execute(
        "SELECT cursor_json FROM tasks WHERE run_id = ? AND module = 'http_probe'",
        (run_id,),
    ).fetchall():
        cursor = parse_task_cursor_json(row["cursor_json"])
        for bucket in (cursor.get("input_probe_urls"), cursor.get("explicit_http_probe_targets")):
            if not isinstance(bucket, list):
                continue
            for item in bucket:
                if isinstance(item, str):
                    key = canonical_http_probe_input_key(item)
                    if key:
                        keys.add(key)
    return keys


def dir_enum_url_keys_scheduled_or_completed(connection: sqlite3.Connection, run_id: str) -> set[str]:
    keys: set[str] = set()
    for row in connection.execute(
        "SELECT cursor_json FROM tasks WHERE run_id = ? AND module = 'dir_enum'",
        (run_id,),
    ).fetchall():
        cursor = parse_task_cursor_json(row["cursor_json"])
        bucket = cursor.get("input_dirscan_urls")
        if not isinstance(bucket, list):
            continue
        for item in bucket:
            if isinstance(item, str):
                key = canonical_http_probe_input_key(item)
                if key:
                    keys.add(key)
        explicit = cursor.get("explicit_dirscan_targets")
        if isinstance(explicit, list):
            for item in explicit:
                if isinstance(item, str):
                    key = canonical_http_probe_input_key(item)
                    if key:
                        keys.add(key)
    return keys


def pending_incremental_http_probe_target_keysets(
    connection: sqlite3.Connection, run_id: str
) -> list[frozenset[str]]:
    keysets: list[frozenset[str]] = []
    for row in connection.execute(
        """
        SELECT cursor_json
        FROM tasks
        WHERE run_id = ?
          AND module = 'http_probe'
          AND state = 'pending'
        """,
        (run_id,),
    ).fetchall():
        cursor = parse_task_cursor_json(row["cursor_json"])
        explicit = cursor.get("explicit_http_probe_targets")
        if not isinstance(explicit, list) or not explicit:
            continue
        keys = frozenset(
            k
            for item in explicit
            if isinstance(item, str)
            for k in (canonical_http_probe_input_key(item),)
            if k
        )
        if keys:
            keysets.append(keys)
    return keysets


def pending_incremental_dir_enum_target_keysets(
    connection: sqlite3.Connection, run_id: str
) -> list[frozenset[str]]:
    keysets: list[frozenset[str]] = []
    for row in connection.execute(
        """
        SELECT cursor_json
        FROM tasks
        WHERE run_id = ?
          AND module = 'dir_enum'
          AND state = 'pending'
        """,
        (run_id,),
    ).fetchall():
        cursor = parse_task_cursor_json(row["cursor_json"])
        explicit = cursor.get("explicit_dirscan_targets")
        if not isinstance(explicit, list) or not explicit:
            continue
        keys = frozenset(
            k
            for item in explicit
            if isinstance(item, str)
            for k in (canonical_http_probe_input_key(item),)
            if k
        )
        if keys:
            keysets.append(keys)
    return keysets


def incremental_http_probe_cursor_meta(prior: dict[str, Any]) -> dict[str, Any]:
    if not prior.get("incremental"):
        return {}
    keys = (
        "incremental",
        "triggered_by",
        "trigger_task_id",
        "new_scope_count",
        "revisit_reason",
        "explicit_http_probe_targets",
    )
    return {key: prior[key] for key in keys if key in prior}


def incremental_dir_enum_cursor_meta(prior: dict[str, Any]) -> dict[str, Any]:
    if prior.get("incremental"):
        inc_keys = (
            "incremental",
            "triggered_by",
            "trigger_task_id",
            "new_scope_count",
            "revisit_reason",
            "explicit_dirscan_targets",
        )
        return {key: prior[key] for key in inc_keys if key in prior}
    if prior.get("recursive") or "recursion_depth" in prior:
        rec_keys = (
            "incremental",
            "recursive",
            "recursion_depth",
            "lineage",
            "parent_base_url",
            "parent_path",
            "parent_target",
            "triggered_by",
            "trigger_task_id",
            "new_scope_count",
            "revisit_reason",
            "explicit_dirscan_targets",
        )
        return {key: prior[key] for key in rec_keys if key in prior}
    return {}
