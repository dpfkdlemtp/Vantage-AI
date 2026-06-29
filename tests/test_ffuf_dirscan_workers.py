from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

from scanner.config import build_scan_config, DIR_ENUM_MAX_WORKERS
from scanner.execution.dirscan import _resolve_dirscan_worker_count


def test_resolve_dirscan_workers_sequential_single_url(tmp_path: Path) -> None:
    c = build_scan_config("example.com", "r1", profile="safe", modules=["http_probe", "dir_enum"], workspace=tmp_path)
    c = c.model_copy(
        update={
            "ffuf_parallel_enabled": True,
            "ffuf_max_parallel_tasks": 5,
        }
    )
    run = SimpleNamespace(config=c)
    assert _resolve_dirscan_worker_count(run, 1) == 1


def test_resolve_dirscan_workers_sequential_when_disabled(tmp_path: Path) -> None:
    c = build_scan_config("example.com", "r2", profile="safe", modules=["http_probe", "dir_enum"], workspace=tmp_path)
    c = c.model_copy(
        update={
            "ffuf_parallel_enabled": False,
            "ffuf_max_parallel_tasks": 8,
        }
    )
    run = SimpleNamespace(config=c)
    assert _resolve_dirscan_worker_count(run, 9) == 1


def test_resolve_dirscan_workers_parallel_capped_by_max_and_dir_enum_max(tmp_path: Path) -> None:
    c = build_scan_config("example.com", "r3", profile="safe", modules=["http_probe", "dir_enum"], workspace=tmp_path)
    c = c.model_copy(
        update={
            "ffuf_parallel_enabled": True,
            "ffuf_max_parallel_tasks": 2,
            "max_concurrency": 10,
        }
    )
    run = SimpleNamespace(config=c)
    # min(5 targets, max_parallel=2, max_concurrency=10, DIR_ENUM_MAX_WORKERS) -> 2
    assert _resolve_dirscan_worker_count(run, 5) == 2
    # min(100,2,10,3) = 2
    assert _resolve_dirscan_worker_count(run, 100) == 2


def test_dir_enum_max_workers_constant() -> None:
    assert DIR_ENUM_MAX_WORKERS == 3
