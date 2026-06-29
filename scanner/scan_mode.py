from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

from scanner.config import plan_enabled_phases
from scanner.models import ScanConfig, ScanMode, ScanPhase


def normalize_scan_mode(value: object) -> ScanMode:
    s = str(value or "balanced").strip().lower()
    if s in ("fast", "balanced", "deep"):
        return cast(ScanMode, s)
    return "balanced"


def apply_scan_mode_to_modules(
    target: str,
    modules: Sequence[str] | None,
    *,
    scan_mode: ScanMode,
    user_chose_modules: bool,
    any_line_is_domain: bool = False,
) -> list[ScanPhase]:
    """
    Adjust enabled phases for scan_mode when the user did not hand-pick a module list.
    If the request included an explicit `modules` array, module choices are not altered for fast/deep
    (manual override: user list wins).
    """
    base = plan_enabled_phases(
        target,
        list(modules) if modules is not None else None,
        any_line_is_domain=any_line_is_domain,
    )
    if user_chose_modules:
        return base
    if scan_mode == "fast":
        return [m for m in base if m != "dir_enum"]
    if scan_mode == "deep":
        names = [str(m) for m in base]
        if "dir_enum" not in names:
            return plan_enabled_phases(target, names + ["dir_enum"])
    return base


def _deep_copy_phases_for_mode(config: ScanConfig, scan_mode: ScanMode) -> list[ScanPhase]:
    if scan_mode != "fast":
        return list(config.enabled_phases)
    return [m for m in config.enabled_phases if m != "dir_enum"]


def apply_scan_mode_defaults(
    config: ScanConfig,
    *,
    skip_fields: frozenset[str] | None = None,
) -> ScanConfig:
    """
    Apply scan_mode-driven defaults. Fields listed in `skip_fields` are left unchanged
    (e.g. explicit user overrides from the API request).
    """
    skip = skip_fields or frozenset()
    mode = normalize_scan_mode(getattr(config, "scan_mode", "balanced"))
    if mode == "balanced":
        if "scan_mode" in skip:
            return config
        return config.model_copy(update={"scan_mode": "balanced"})

    if mode == "fast":
        updates: dict[str, Any] = {
            "scan_mode": "fast",
            "nmap_ports": "top1000",
            "nmap_timing_template": "T4",
            "nmap_version_detection": False,
            "dir_recursive_enabled": False,
            "dir_recursive_max_depth": 1,
            "cidr_split_max_hosts_per_chunk": 16,
        }
        if "enabled_phases" not in skip:
            updates["enabled_phases"] = _deep_copy_phases_for_mode(config, "fast")
        out = {k: v for k, v in updates.items() if k not in skip}
        return config.model_copy(update=out)

    # deep
    updates_deep: dict[str, Any] = {
        "scan_mode": "deep",
        "nmap_ports": "1-65535",
        "nmap_timing_template": "T2",
        "nmap_version_detection": True,
        "http_probe_all_open_ports": True,
        "dir_recursive_enabled": True,
        "dir_recursive_max_depth": 3,
        "cidr_split_max_hosts_per_chunk": 64,
        "ffuf_threads": 40,
        "ffuf_concurrency": 80,
    }
    if "enabled_phases" not in skip:
        ph_list = list(config.enabled_phases)
        names = [str(p) for p in ph_list]
        if "dir_enum" not in names:
            ph_list = plan_enabled_phases(config.target, names + ["dir_enum"])
        updates_deep["enabled_phases"] = ph_list
    out_deep = {k: v for k, v in updates_deep.items() if k not in skip}
    return config.model_copy(update=out_deep)
