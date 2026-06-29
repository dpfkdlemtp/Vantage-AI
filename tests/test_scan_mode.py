from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from scanner.config import build_scan_config
from scanner.models import ScanConfig
from scanner.scan_mode import apply_scan_mode_defaults, normalize_scan_mode


def _cfg(
    tmp_path: Path,
    *,
    scan_mode: str = "balanced",
    modules: Sequence[str] | None = None,
) -> ScanConfig:
    return build_scan_config(
        "example.com",
        "run-id-scan-mode",
        profile="safe",
        modules=list(modules) if modules is not None else ["http_probe", "port_scan", "dir_enum"],
        workspace=tmp_path,
        scan_mode=scan_mode,
    )


def test_scan_mode_default_is_balanced(tmp_path: Path) -> None:
    c = _cfg(tmp_path)
    assert c.scan_mode == "balanced"
    c2 = apply_scan_mode_defaults(c)
    assert c2.scan_mode == "balanced"


def test_fast_mode_sets_expected_fields(tmp_path: Path) -> None:
    c = _cfg(tmp_path, scan_mode="fast")
    c2 = apply_scan_mode_defaults(c)
    assert c2.nmap_ports == "top1000"
    assert c2.nmap_timing_template == "T4"
    assert c2.cidr_split_max_hosts_per_chunk == 16
    assert c2.dir_recursive_enabled is False
    assert "dir_enum" not in c2.enabled_phases


def test_deep_mode_enables_recursion(tmp_path: Path) -> None:
    c = _cfg(tmp_path, scan_mode="deep")
    c2 = apply_scan_mode_defaults(c)
    assert c2.nmap_ports == "1-65535"
    assert c2.nmap_timing_template == "T2"
    assert c2.dir_recursive_enabled is True
    assert c2.dir_recursive_max_depth == 3
    assert c2.nmap_version_detection is True
    assert "dir_enum" in c2.enabled_phases


def test_manual_override_preserved(tmp_path: Path) -> None:
    c = _cfg(tmp_path, scan_mode="fast")
    c = c.model_copy(update={"nmap_ports": "1-100"})
    c2 = apply_scan_mode_defaults(c, skip_fields=frozenset({"nmap_ports"}))
    assert c2.nmap_ports == "1-100"
    assert c2.nmap_timing_template == "T4"
    assert c2.cidr_split_max_hosts_per_chunk == 16


def test_normalize_scan_mode_invalid_falls_back() -> None:
    assert normalize_scan_mode("FAST") == "fast"
    assert normalize_scan_mode("deep") == "deep"
    assert normalize_scan_mode("nope") == "balanced"
