from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Any

from scanner import runner as runner_core
from scanner.adapters import nmap_runner as nmap_adapter
from scanner.execution.portscan_helpers import (
    NMAP_PERCENT_RE,
    estimated_remaining_min_from_stats_line,
    nmap_scan_warning_event,
)

_log = logging.getLogger(__name__)

# Per-run dead host cache (process-level, keyed by run_id)
_DEAD_HOST_CACHE: dict[str, set[str]] = {}
_DEAD_HOST_CACHE_LOCK = Lock()


def _get_dead_cache(run_id: str) -> set[str]:
    with _DEAD_HOST_CACHE_LOCK:
        return _DEAD_HOST_CACHE.setdefault(run_id, set())


def _mark_dead(run_id: str, hosts: list[str]) -> None:
    if not hosts:
        return
    cache = _get_dead_cache(run_id)
    with _DEAD_HOST_CACHE_LOCK:
        cache.update(hosts)


def clear_dead_host_cache(run_id: str) -> None:
    with _DEAD_HOST_CACHE_LOCK:
        _DEAD_HOST_CACHE.pop(run_id, None)


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_target_to_ip(target: str) -> str | None:
    if not target:
        return None
    if _is_ip_literal(target):
        return target
    try:
        info = socket.getaddrinfo(target, None, family=socket.AF_INET)
    except (OSError, UnicodeError):
        return None
    for entry in info:
        sockaddr = entry[4]
        if isinstance(sockaddr, tuple) and sockaddr:
            return str(sockaddr[0])
    return None


def deduplicate_targets_by_ip(targets: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    """Group targets by their resolved IPv4 address.

    Returns (unique_targets_for_scan, ip_to_hostnames_map).
    Hostnames that resolve to the same IP are deduplicated; one representative
    is kept for scanning (preferring IP literal, then shortest hostname).
    Targets that fail to resolve are kept as-is (so nmap can still try them).
    """
    ip_to_hosts: dict[str, list[str]] = {}
    unresolved: list[str] = []
    for t in targets:
        t_clean = t.strip()
        if not t_clean:
            continue
        ip = _resolve_target_to_ip(t_clean)
        if ip is None:
            unresolved.append(t_clean)
            continue
        ip_to_hosts.setdefault(ip, []).append(t_clean)

    unique: list[str] = []
    for ip, hosts in ip_to_hosts.items():
        # Prefer IP literal if present in hosts, else shortest hostname
        ip_literal = next((h for h in hosts if _is_ip_literal(h) and h == ip), None)
        chosen = ip_literal or min(hosts, key=len)
        unique.append(chosen)

    return sorted(set(unique + unresolved)), ip_to_hosts


def expand_cidr_targets(targets: list[str], *, max_hosts: int = 8192) -> list[str]:
    """Expand CIDR notations into individual host IPs.

    A single CIDR string (e.g. "10.0.0.0/27") would otherwise be treated as
    "1 target" by the alive filter and bypass it entirely — causing every host
    in the range (incl. dead ones) to be full-port scanned. Expanding first lets
    the alive filter keep only responsive hosts. Networks larger than max_hosts
    are left as-is (masscan handles big ranges natively).
    """
    out: list[str] = []
    for raw in targets:
        t = raw.strip()
        if not t:
            continue
        if "/" in t and "://" not in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                out.append(t)
                continue
            if net.num_addresses > max_hosts:
                out.append(t)
                continue
            if net.num_addresses <= 2:
                out.append(str(net.network_address))
            else:
                out.extend(str(h) for h in net.hosts())
        else:
            out.append(t)
    # dedup, preserve order
    seen: set[str] = set()
    deduped: list[str] = []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    return deduped


def filter_alive_hosts(
    targets: list[str],
    *,
    ping_ports: str,
    nmap_bin: str,
    timeout_seconds: int = 10,
) -> tuple[list[str], list[str]]:
    """TCP SYN ping pre-check. Returns (alive, dead).

    Uses nmap -sn -PS{ports} for a fast aliveness sweep that bypasses ICMP filtering.
    CIDR ranges are expanded to individual hosts first (so a single /27 chunk is
    actually filtered, not passed through as "1 target"). For 0 or 1 resulting
    hosts, returns all as alive. On any nmap error, returns all as alive (fail open).
    """
    cleaned = expand_cidr_targets([t.strip() for t in targets if t.strip()])
    if len(cleaned) <= 1:
        return cleaned, []
    ports_clean = (ping_ports or "80,443").strip()
    cmd = [
        nmap_bin,
        "-sn",
        "-n",
        "-T4",
        "--max-retries", "1",
        "--host-timeout", f"{timeout_seconds}s",
        "-PS" + ports_clean,
        "-oG", "-",
    ] + cleaned
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max(30, timeout_seconds * len(cleaned)),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return cleaned, []
    if completed.returncode != 0:
        return cleaned, []
    alive: set[str] = set()
    for line in (completed.stdout or "").splitlines():
        if "Status: Up" not in line:
            continue
        # Format: "Host: <ip> (<name>)\tStatus: Up"
        parts = line.split()
        if len(parts) < 2:
            continue
        host_field = parts[1]
        alive.add(host_field)
        # Match by hostname in parens as well
        if "(" in line and ")" in line:
            try:
                name = line.split("(", 1)[1].split(")", 1)[0].strip()
                if name:
                    alive.add(name)
            except IndexError:
                pass
    alive_list = [t for t in cleaned if t in alive or _resolve_target_to_ip(t) in alive]
    dead_list = [t for t in cleaned if t not in alive_list]
    return alive_list, dead_list


def _measure_response_rate(sample_target: str, ping_ports: str, nmap_bin: str) -> float | None:
    """Quick probe to estimate network reliability (0.0~1.0).

    Sends -PS to a single representative target for ping_ports; returns
    fraction of ports that respond. None if the probe itself failed.
    """
    if not sample_target.strip():
        return None
    ports = [p.strip() for p in (ping_ports or "").split(",") if p.strip()]
    if not ports:
        return None
    cmd = [
        nmap_bin, "-Pn", "-n", "-T4",
        "--max-retries", "1", "--host-timeout", "5s",
        "-p", ",".join(ports), sample_target,
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if completed.returncode != 0:
        return None
    out = completed.stdout or ""
    responded = sum(1 for line in out.splitlines() if "/tcp" in line and ("open" in line or "closed" in line))
    total = len(ports)
    if total == 0:
        return None
    return min(1.0, responded / total)


def adaptive_rate(base_rate: int, response_rate: float | None, *, min_rate: int = 500) -> int:
    """Scale rate down when response_rate is low.

    response_rate >= 0.8 → no change
    response_rate < 0.8  → rate *= max(0.3, response_rate / 0.8)
    Returns at least min_rate.
    """
    if response_rate is None or response_rate >= 0.8:
        return base_rate
    factor = max(0.3, response_rate / 0.8)
    adjusted = int(base_rate * factor)
    return max(min_rate, adjusted)


def run_nmap_scan_with_progress(
    targets: list[str],
    *,
    run: Any,
    progress_callback: Any | None = None,
    port_override: str | None = None,
    version_detection_override: bool | None = None,
) -> nmap_adapter.NmapRunResult:
    """Run nmap with live progress. port_override replaces run.config.nmap_ports."""
    proxy_mode = str(getattr(run.config, "proxy_mode", "none") or "none").strip().lower()
    proxy_url = str(getattr(run.config, "proxy_url", "") or "").strip()
    nmap_proxies = proxy_url if proxy_mode in {"http", "socks"} and proxy_url else None
    ports = port_override if port_override is not None else run.config.nmap_ports
    version_detection = version_detection_override if version_detection_override is not None else run.config.nmap_version_detection
    nse_enabled = bool(getattr(run.config, "nmap_nse_scripts_enabled", False))
    nse_scripts = str(getattr(run.config, "nmap_nse_scripts", "") or "").strip() if nse_enabled else ""
    host_timeout = str(getattr(run.config, "nmap_host_timeout", "") or "").strip()

    if runner_core.run_nmap_scan.__module__ != "scanner.adapters.nmap_runner":
        try:
            return runner_core.run_nmap_scan(
                targets,
                nmap_bin=run.config.nmap_bin,
                profile=run.config.profile,
                ports=ports,
                timing_template=run.config.nmap_timing_template,
                version_detection=version_detection,
                proxies=nmap_proxies,
                nse_scripts=nse_scripts or None,
                host_timeout=host_timeout or None,
            )
        except TypeError:
            try:
                return runner_core.run_nmap_scan(
                    targets,
                    nmap_bin=run.config.nmap_bin,
                    profile=run.config.profile,
                    ports=ports,
                    timing_template=run.config.nmap_timing_template,
                    version_detection=version_detection,
                    proxies=nmap_proxies,
                )
            except TypeError:
                return runner_core.run_nmap_scan(
                    targets,
                    nmap_bin=run.config.nmap_bin,
                    profile=run.config.profile,
                    ports=ports,
                    timing_template=run.config.nmap_timing_template,
                    version_detection=version_detection,
                )

    normalized_targets = nmap_adapter._normalize_targets(targets)
    command = nmap_adapter._build_nmap_command(
        nmap_bin=run.config.nmap_bin,
        profile=run.config.profile,
        ports=ports,
        timing_template=run.config.nmap_timing_template,
        version_detection=version_detection,
        proxies=nmap_proxies,
        targets=normalized_targets,
        nse_scripts=nse_scripts or None,
        host_timeout=host_timeout or None,
    )
    if not normalized_targets:
        return nmap_adapter.NmapRunResult(command=command, targets=[], hosts=[], raw_output="")

    progress_state = {
        "percent": 0.0,
        "stats_line": "",
    }
    state_lock = Lock()

    def _handle_stderr(line: str) -> None:
        percent_match = NMAP_PERCENT_RE.search(line)
        stats_line = line.strip()
        with state_lock:
            if stats_line:
                progress_state["stats_line"] = stats_line
            if percent_match is not None:
                progress_state["percent"] = float(percent_match.group("percent"))

    def _snapshot() -> None:
        if progress_callback is None:
            return
        with state_lock:
            percent: float = progress_state["percent"]
            total_count = len(normalized_targets)
            processed_count = min(total_count, round((percent / 100.0) * total_count)) if total_count else 0
            stats_line: str = progress_state["stats_line"]
            snapshot = {
                "processed_count": processed_count,
                "total_targets": total_count,
                "tool_progress": {
                    "tool": "nmap",
                    "processed_count": processed_count,
                    "total_count": total_count,
                    "percent": percent,
                    "stats_line": stats_line,
                    "progress_percent": round(percent),
                    "estimated_remaining_min": estimated_remaining_min_from_stats_line(stats_line),
                },
            }
        progress_callback(snapshot)

    completed = runner_core._run_command_with_live_progress(
        command,
        stderr_handler=_handle_stderr,
        snapshot_handler=_snapshot,
    )
    scan_warnings: list[str] = []
    if completed.returncode != 0:
        retry_command = nmap_adapter._build_nmap_command(
            nmap_bin=run.config.nmap_bin,
            profile=run.config.profile,
            ports=ports,
            timing_template=run.config.nmap_timing_template,
            version_detection=version_detection,
            proxies=nmap_proxies,
            targets=normalized_targets,
            force_tcp_connect=True,
            nse_scripts=nse_scripts or None,
            host_timeout=host_timeout or None,
        )
        if retry_command != command and nmap_adapter._should_retry_with_tcp_connect(completed):
            warning = nmap_adapter._tcp_connect_retry_warning()
            scan_warnings.append(warning)
            if progress_callback is not None:
                progress_callback({"nmap_scan_warnings": [nmap_scan_warning_event(warning, requires_privilege_escalation=True)]})
            command = retry_command
            with state_lock:
                progress_state["percent"] = 0.0
                progress_state["stats_line"] = ""
            completed = runner_core._run_command_with_live_progress(
                command,
                stderr_handler=_handle_stderr,
                snapshot_handler=_snapshot,
            )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "nmap command failed"
        raise nmap_adapter.NmapError(f"nmap exited with code {completed.returncode}: {detail}")

    raw_output = completed.stdout
    if not raw_output.strip():
        return nmap_adapter.NmapRunResult(
            command=command,
            targets=normalized_targets,
            hosts=[],
            raw_output=raw_output,
            scan_warnings=scan_warnings,
        )

    return nmap_adapter.NmapRunResult(
        command=command,
        targets=normalized_targets,
        hosts=nmap_adapter._parse_xml_output(raw_output),
        raw_output=raw_output,
        scan_warnings=scan_warnings,
    )


def run_masscan_nmap_two_pass(
    targets: list[str],
    *,
    run: Any,
    progress_callback: Any | None = None,
) -> nmap_adapter.NmapRunResult:
    """
    Phase 1a — masscan discovers ports at high speed (stateless SYN).
    Phase 1b — naabu discovers ports in parallel (different detection method, with retries).
    Phase 2  — nmap runs service detection on the union of confirmed open ports.

    Each fast scanner runs only if its binary is available and enabled in config.
    Falls back gracefully when any combination of tools is missing or fails.
    """
    from scanner.adapters.masscan_runner import (
        MasscanError,
        is_masscan_available,
        open_ports_by_host as masscan_open_ports,
        run_masscan,
    )
    from scanner.adapters.naabu_runner import (
        NaabuError,
        is_naabu_available,
        open_ports_by_host as naabu_open_ports,
        run_naabu,
    )

    masscan_bin = str(getattr(run.config, "masscan_bin", "masscan") or "masscan")
    masscan_rate = int(getattr(run.config, "masscan_rate", 10000) or 10000)
    masscan_retries = int(getattr(run.config, "masscan_retries", 2) or 0)
    masscan_enabled = bool(getattr(run.config, "masscan_enabled", True))
    masscan_ok = masscan_enabled and is_masscan_available(masscan_bin)

    naabu_bin = str(getattr(run.config, "naabu_bin", "naabu") or "naabu")
    naabu_rate = int(getattr(run.config, "naabu_rate", 5000) or 5000)
    naabu_retries = int(getattr(run.config, "naabu_retries", 3) or 0)
    naabu_scan_type = str(getattr(run.config, "naabu_scan_type", "syn") or "syn")
    naabu_enabled = bool(getattr(run.config, "naabu_enabled", True))
    naabu_ok = naabu_enabled and is_naabu_available(naabu_bin)

    if not masscan_ok and not naabu_ok:
        _log.info("no fast scanner available (masscan=%s, naabu=%s) — nmap-only", masscan_bin, naabu_bin)
        return run_nmap_scan_with_progress(targets, run=run, progress_callback=progress_callback)

    # IP deduplication: collapse hostnames that resolve to the same IP.
    # The duplicates list is logged for diagnostics; finding fan-out happens
    # elsewhere via the run's resolved-host index.
    ip_dedup = bool(getattr(run.config, "portscan_ip_dedup_enabled", True))
    scan_targets: list[str] = list(targets)
    if ip_dedup and len(targets) > 1:
        scan_targets, ip_to_hosts = deduplicate_targets_by_ip(targets)
        if len(scan_targets) < len(targets):
            saved = len(targets) - len(scan_targets)
            collapsed = {ip: hosts for ip, hosts in ip_to_hosts.items() if len(hosts) > 1}
            _log.info(
                "IP dedup: %d → %d targets (saved %d duplicates); collapsed groups=%s",
                len(targets), len(scan_targets), saved, collapsed,
            )
            if progress_callback is not None:
                progress_callback({
                    "tool_progress": {
                        "tool": "preflight",
                        "stage": "ip_dedup",
                        "stats_line": f"IP dedup: {len(targets)} → {len(scan_targets)} unique targets",
                    }
                })

    # Filter dead hosts from previous probes in the same run
    dead_cache = _get_dead_cache(str(getattr(run, "run_id", "")))
    if dead_cache:
        before = len(scan_targets)
        scan_targets = [t for t in scan_targets if t not in dead_cache]
        skipped = before - len(scan_targets)
        if skipped:
            _log.info("dead-host cache: skipped %d targets known dead from previous phase", skipped)

    # Pre-alive filter: TCP SYN ping
    alive_filter_enabled = bool(getattr(run.config, "portscan_alive_filter_enabled", True))
    ping_ports = str(getattr(run.config, "portscan_alive_ping_ports", "80,443,22,3389,8080,8443") or "")
    dead_cache_enabled = bool(getattr(run.config, "portscan_dead_host_cache_enabled", True))
    # Expand CIDR chunks into individual hosts so a single "/27" string doesn't
    # bypass the alive filter (which would full-port scan every dead host).
    if alive_filter_enabled and ping_ports.strip():
        expanded = expand_cidr_targets(scan_targets)
        if len(expanded) > len(scan_targets):
            _log.info("CIDR expand for alive filter: %d → %d hosts", len(scan_targets), len(expanded))
            scan_targets = expanded
    if alive_filter_enabled and len(scan_targets) > 1 and ping_ports.strip():
        alive_list, dead_list = filter_alive_hosts(
            scan_targets,
            ping_ports=ping_ports,
            nmap_bin=run.config.nmap_bin,
        )
        if dead_list and len(alive_list) >= 1:
            _log.info("alive filter: %d alive, %d skipped", len(alive_list), len(dead_list))
            if progress_callback is not None:
                progress_callback({
                    "tool_progress": {
                        "tool": "preflight",
                        "stage": "alive_filter",
                        "stats_line": f"alive filter: {len(alive_list)}/{len(scan_targets)} hosts respond to TCP SYN ping",
                    }
                })
            scan_targets = alive_list
            if dead_cache_enabled:
                _mark_dead(str(getattr(run, "run_id", "")), dead_list)
        elif not alive_list:
            _log.info("alive filter: 0 hosts responded — keeping all targets (filter likely misleading)")

    if not scan_targets:
        _log.info("no live targets after preflight filtering — skipping port scan")
        return nmap_adapter.NmapRunResult(
            command=[], targets=list(targets), hosts=[], raw_output="",
        )

    # Adaptive rate: probe a representative target to estimate reliability
    adaptive_enabled = bool(getattr(run.config, "portscan_adaptive_rate_enabled", True))
    effective_masscan_rate = masscan_rate
    effective_naabu_rate = naabu_rate
    if adaptive_enabled and scan_targets:
        sample = scan_targets[0]
        response_rate = _measure_response_rate(sample, ping_ports, run.config.nmap_bin)
        if response_rate is not None and response_rate < 0.8:
            effective_masscan_rate = adaptive_rate(masscan_rate, response_rate)
            effective_naabu_rate = adaptive_rate(naabu_rate, response_rate, min_rate=300)
            _log.info(
                "adaptive rate: response=%.2f → masscan %d→%d, naabu %d→%d",
                response_rate, masscan_rate, effective_masscan_rate, naabu_rate, effective_naabu_rate,
            )
            if progress_callback is not None:
                progress_callback({
                    "tool_progress": {
                        "tool": "preflight",
                        "stage": "adaptive_rate",
                        "stats_line": f"adaptive rate: response={response_rate:.0%} → masscan={effective_masscan_rate}pps, naabu={effective_naabu_rate}pps",
                    }
                })

    if progress_callback is not None:
        used = [name for name, ok in [("masscan", masscan_ok), ("naabu", naabu_ok)] if ok]
        progress_callback({
            "tool_progress": {
                "tool": "+".join(used) or "fast",
                "stage": "discovery",
                "percent": 0.0,
                "stats_line": f"phase 1: parallel fast scan ({', '.join(used)}) on {run.config.nmap_ports} for {len(scan_targets)} target(s)",
            }
        })

    masscan_ports_map: dict[str, list[int]] = {}
    naabu_ports_map: dict[str, list[int]] = {}
    masscan_command: list[str] = []
    masscan_raw = ""
    masscan_targets_used: list[str] = list(scan_targets)
    warnings: list[str] = []

    def _do_masscan() -> tuple[dict[str, list[int]], list[str], str, list[str]]:
        result = run_masscan(
            scan_targets,
            masscan_bin=masscan_bin,
            ports=run.config.nmap_ports,
            rate=effective_masscan_rate,
            retries=masscan_retries,
        )
        return masscan_open_ports(result), result.command, result.raw_output, result.targets

    def _do_naabu() -> dict[str, list[int]]:
        result = run_naabu(
            scan_targets,
            naabu_bin=naabu_bin,
            ports=run.config.nmap_ports,
            rate=effective_naabu_rate,
            retries=naabu_retries,
            scan_type=naabu_scan_type,
        )
        return naabu_open_ports(result)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_masscan = pool.submit(_do_masscan) if masscan_ok else None
        fut_naabu = pool.submit(_do_naabu) if naabu_ok else None

        if fut_masscan is not None:
            try:
                masscan_ports_map, masscan_command, masscan_raw, masscan_targets_used = fut_masscan.result()
            except MasscanError as exc:
                _log.warning("masscan failed: %s", exc)
                warnings.append(f"masscan failed: {exc}")
        if fut_naabu is not None:
            try:
                naabu_ports_map = fut_naabu.result()
            except NaabuError as exc:
                _log.warning("naabu failed: %s", exc)
                warnings.append(f"naabu failed: {exc}")

    # Union open ports across both scanners
    all_open_ports: set[int] = set()
    for port_list in masscan_ports_map.values():
        all_open_ports.update(port_list)
    for port_list in naabu_ports_map.values():
        all_open_ports.update(port_list)

    if not masscan_ports_map and not naabu_ports_map and warnings:
        _log.warning("both fast scanners failed — falling back to nmap-only")
        if progress_callback is not None:
            progress_callback({"nmap_scan_warnings": [
                nmap_scan_warning_event(w) for w in warnings
            ]})
        return run_nmap_scan_with_progress(targets, run=run, progress_callback=progress_callback)

    masscan_port_count = sum(len(v) for v in masscan_ports_map.values())
    naabu_port_count = sum(len(v) for v in naabu_ports_map.values())
    union_count = len(all_open_ports)
    _log.info(
        "fast scan complete: masscan=%d naabu=%d union=%d ports",
        masscan_port_count, naabu_port_count, union_count,
    )

    if progress_callback is not None:
        stats_parts = []
        if masscan_ok:
            stats_parts.append(f"masscan={masscan_port_count}")
        if naabu_ok:
            stats_parts.append(f"naabu={naabu_port_count}")
        stats_parts.append(f"union={union_count}")
        progress_callback({
            "tool_progress": {
                "tool": "fast_scan",
                "stage": "complete",
                "percent": 50.0,
                "stats_line": "phase 1 done: " + " ".join(stats_parts) + " — running nmap service detection",
            }
        })
        if warnings:
            progress_callback({"nmap_scan_warnings": [
                nmap_scan_warning_event(w) for w in warnings
            ]})

    if not all_open_ports:
        return nmap_adapter.NmapRunResult(
            command=masscan_command or [],
            targets=masscan_targets_used,
            hosts=[],
            raw_output=masscan_raw,
            scan_warnings=warnings,
        )

    ports_str = ",".join(str(p) for p in sorted(all_open_ports))
    tcp_result = run_nmap_scan_with_progress(
        scan_targets,
        run=run,
        progress_callback=progress_callback,
        port_override=ports_str,
        version_detection_override=True,
    )

    # Optional UDP scan pass on the same targets
    if bool(getattr(run.config, "udp_scan_enabled", False)):
        udp_findings = _run_udp_scan_pass(scan_targets, run=run, progress_callback=progress_callback)
        if udp_findings:
            # Attach UDP results to the nmap result via raw_output marker;
            # the normalizer will pick them up in addition to the TCP findings.
            merged_warnings = list(tcp_result.scan_warnings) + [f"udp:{len(udp_findings)}"]
            return nmap_adapter.NmapRunResult(
                command=tcp_result.command,
                targets=tcp_result.targets,
                hosts=tcp_result.hosts + udp_findings,
                raw_output=tcp_result.raw_output,
                scan_warnings=merged_warnings,
            )
    return tcp_result


def _run_udp_scan_pass(
    targets: list[str],
    *,
    run: Any,
    progress_callback: Any | None = None,
) -> list[nmap_adapter.NmapHostResult]:
    """Run an nmap UDP pass on top-common UDP ports.

    Returns NmapHostResult list (only hosts with open|open|filtered UDP ports)
    so they can be merged into the main TCP result.
    """
    from scanner.adapters import udp_scanner as udp_adapter

    if not targets:
        return []
    if not udp_adapter.is_nmap_available(run.config.nmap_bin):
        return []
    udp_ports = str(getattr(run.config, "udp_scan_ports", udp_adapter.DEFAULT_UDP_PORTS) or udp_adapter.DEFAULT_UDP_PORTS)
    host_timeout = int(getattr(run.config, "udp_scan_host_timeout_seconds", 120) or 120)

    if progress_callback is not None:
        progress_callback({
            "tool_progress": {
                "tool": "nmap_udp",
                "stage": "udp_scan",
                "stats_line": f"UDP scan: ports={udp_ports} hosts={len(targets)}",
            }
        })
    try:
        result = udp_adapter.run_udp_scan(
            targets,
            nmap_bin=run.config.nmap_bin,
            ports=udp_ports,
            timing_template=run.config.nmap_timing_template,
            version_detection=bool(getattr(run.config, "nmap_version_detection", True)),
            host_timeout_seconds=host_timeout,
        )
    except udp_adapter.UdpScanError as exc:
        _log.warning("udp scan skipped: %s", exc)
        if progress_callback is not None:
            progress_callback({"nmap_scan_warnings": [
                nmap_scan_warning_event(f"UDP scan skipped: {exc}", requires_privilege_escalation="root" in str(exc).lower())
            ]})
        return []

    # Group UDP ports per host and wrap as NmapHostResult-compatible records
    hosts_map: dict[tuple[str, str], list[Any]] = {}
    for entry in result.ports:
        key = (entry.host or entry.ip, entry.ip)
        hosts_map.setdefault(key, []).append(
            nmap_adapter.NmapPortResult(
                protocol="udp",
                port=entry.port,
                state=entry.state,
                service=entry.service,
                product=entry.product,
                version=entry.version,
                extrainfo=None,
                raw_entry={"udp": True, "state": entry.state},
            )
        )
    out: list[nmap_adapter.NmapHostResult] = []
    for (host_name, ip_val), ports in hosts_map.items():
        out.append(nmap_adapter.NmapHostResult(
            host=host_name,
            ip=ip_val,
            status="up",
            hostnames=[host_name] if host_name and host_name != ip_val else [],
            ports=ports,
            raw_host={"udp_scan": True},
        ))
    if progress_callback is not None:
        progress_callback({
            "tool_progress": {
                "tool": "nmap_udp",
                "stage": "udp_complete",
                "stats_line": f"UDP scan done: {sum(len(v) for v in hosts_map.values())} open ports on {len(hosts_map)} hosts",
            }
        })
    return out
