"""Scan watchdog with OS-level signal awareness.

Detects real stalls (not just stale cursor_json) by combining four signals:

1. **Cursor-level** — findings count, chunk_index, processed_count, percent, running module.
   Updated by scanner code at task transitions.
2. **OS process presence** — masscan / naabu / nmap / ffuf / httpx process alive.
   Survives long phases where cursor doesn't update.
3. **OS process CPU activity** — scanner processes consuming sustained CPU.
   Distinguishes "stuck process" from "actively scanning".
4. **Task state transitions** — running task changes module.

Any of these advancing within an interval ⇒ "progress". All idle for N consecutive
intervals ⇒ stall, throttle by cancelling and starting a new run with halved rate.

Designed for single-process embedded use (called by CLI / web layer) and for
detached daemon use (write PID + log to workspace).
"""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

SCANNER_PROCESS_MARKERS: tuple[str, ...] = (
    "masscan -p",
    "naabu -p",
    "nmap -oX",
    "ffuf -u",
    "httpx ",
    "/httpx ",
    "dnsx ",
)


@dataclass
class WatchdogConfig:
    base_url: str = "http://127.0.0.1:8000"
    check_interval_seconds: int = 120
    stall_threshold: int = 15
    max_throttle_level: int = 2
    min_rate: int = 250
    cpu_activity_threshold: float = 1.0
    log_path: str = ""
    state_path: str = ""
    pid_path: str = ""


@dataclass
class Snapshot:
    timestamp: str
    status: str = ""
    running_module: str | None = None
    running_task_id: str | None = None
    chunk_index: Any = None
    chunk_total: Any = None
    processed_count: int = 0
    percent: float = 0.0
    findings_count: int = 0
    stats_line: str = ""
    scanner_procs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class StallVerdict:
    stalled: bool
    reasons: list[str]


@dataclass
class WatchdogState:
    run_id: str
    throttle_level: int = 0
    masscan_rate: int = 5000
    naabu_rate: int = 2500
    stall_streak: int = 0
    started_at: str = ""
    last_snapshot: dict[str, Any] | None = None
    history: list[dict[str, Any]] = field(default_factory=list)
    finished: bool = False
    finish_reason: str = ""


def get_scanner_processes(markers: tuple[str, ...] = SCANNER_PROCESS_MARKERS) -> list[dict[str, Any]]:
    """List active scanner processes with CPU usage (POSIX `ps`)."""
    try:
        completed = subprocess.run(
            ["ps", "-axo", "pid,pcpu,command"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if completed.returncode != 0:
        return []
    procs: list[dict[str, Any]] = []
    for line in (completed.stdout or "").splitlines()[1:]:
        line = line.rstrip()
        if not line:
            continue
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        pid_s, cpu_s, cmd = parts
        if not any(marker in cmd for marker in markers):
            continue
        try:
            procs.append({"pid": int(pid_s), "cpu": float(cpu_s), "cmd": cmd[:120]})
        except ValueError:
            continue
    return procs


def fetch_run_state(run_id: str, base_url: str) -> dict[str, Any] | None:
    try:
        req = urllib.request.Request(f"{base_url}/api/runs/{run_id}")
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        _log.debug("fetch_run_state failed: %s", exc)
        return None


def take_snapshot(run_id: str, base_url: str) -> Snapshot:
    snap = Snapshot(timestamp=datetime.now().strftime("%H:%M:%S"))
    data = fetch_run_state(run_id, base_url)
    if data is None:
        snap.scanner_procs = get_scanner_processes()
        return snap
    run = data.get("run", {}) or {}
    snap.status = str(run.get("status") or "")
    snap.findings_count = len(data.get("findings", []) or [])
    for task in data.get("tasks", []) or []:
        if task.get("state") == "running":
            cj = task.get("cursor_json") or {}
            tp = cj.get("tool_progress") or {}
            snap.running_task_id = str(task.get("task_id") or "")
            snap.running_module = str(task.get("module") or "")
            snap.processed_count = int(tp.get("processed_count") or 0)
            try:
                snap.percent = float(tp.get("percent") or 0)
            except (TypeError, ValueError):
                snap.percent = 0.0
            snap.chunk_index = cj.get("chunk_index")
            snap.chunk_total = cj.get("chunk_total")
            snap.stats_line = str(tp.get("stats_line") or "")[:120]
            break
    snap.scanner_procs = get_scanner_processes()
    return snap


def detect_progress(prev: Snapshot | None, curr: Snapshot, *, cpu_threshold: float) -> StallVerdict:
    """Return (stalled, reasons) — reasons list explains decision."""
    if prev is None:
        return StallVerdict(stalled=False, reasons=["baseline"])

    reasons: list[str] = []
    progressed = False

    if curr.findings_count > prev.findings_count:
        reasons.append(f"findings {prev.findings_count}→{curr.findings_count}")
        progressed = True
    if curr.chunk_index != prev.chunk_index:
        reasons.append(f"chunk {prev.chunk_index}→{curr.chunk_index}")
        progressed = True
    if curr.processed_count > prev.processed_count:
        reasons.append(f"processed {prev.processed_count}→{curr.processed_count}")
        progressed = True
    if curr.percent > prev.percent + 1.0:
        reasons.append(f"percent {prev.percent:.0f}→{curr.percent:.0f}")
        progressed = True
    if curr.running_module != prev.running_module:
        reasons.append(f"module {prev.running_module}→{curr.running_module}")
        progressed = True

    active_procs = [p for p in curr.scanner_procs if p.get("cpu", 0.0) >= cpu_threshold]
    if active_procs:
        top = max(active_procs, key=lambda p: p.get("cpu", 0.0))
        reasons.append(f"OS: {len(active_procs)} scanner proc(s) active ({top['cpu']:.1f}% CPU)")
        progressed = True

    if not progressed:
        reasons.append("no signal across cursor + OS")
    return StallVerdict(stalled=not progressed, reasons=reasons)


def cancel_run(run_id: str, base_url: str) -> bool:
    try:
        req = urllib.request.Request(f"{base_url}/api/runs/{run_id}/cancel", method="POST")
        urllib.request.urlopen(req, timeout=10).read()
    except (urllib.error.URLError, OSError) as exc:
        _log.warning("cancel failed: %s", exc)
        return False
    for marker in ("masscan -p", "naabu -p", "nmap -oX"):
        subprocess.run(["pkill", "-9", "-f", marker], capture_output=True)
    return True


def start_run(payload: dict[str, Any], base_url: str) -> str:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base_url}/api/runs",
        data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
            return str(data.get("run", {}).get("run_id") or "")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        _log.warning("start_run failed: %s", exc)
        return ""


def build_throttled_payload(original_data: dict[str, Any], masscan_rate: int, naabu_rate: int) -> dict[str, Any]:
    """Clone original run config, override rates, force auto_start."""
    cfg = dict((original_data.get("run", {}) or {}).get("config") or {})
    cfg["masscan_rate"] = masscan_rate
    cfg["naabu_rate"] = naabu_rate
    cfg["auto_start"] = True
    # The web API distinguishes target+modules from arbitrary config fields,
    # so we just pass everything; unknown fields are filtered by PATCHABLE_CONFIG_FIELDS.
    payload = dict(cfg)
    # required top-level fields for create-run endpoint
    payload["target"] = cfg.get("target", "")
    payload["profile"] = cfg.get("profile", "balanced")
    payload["scan_mode"] = cfg.get("scan_mode", "balanced")
    enabled_phases = cfg.get("enabled_phases") or ["port_scan", "http_probe", "banner_probe", "dir_enum"]
    payload["modules"] = list(enabled_phases)
    payload["auto_start"] = True
    return payload


class Watchdog:
    """Embeddable monitor; can be driven by CLI or daemonised."""

    def __init__(self, run_id: str, config: WatchdogConfig | None = None) -> None:
        self.run_id = run_id
        self.cfg = config or WatchdogConfig()
        self.state = WatchdogState(run_id=run_id, started_at=datetime.now().isoformat())
        self._stop = False
        if self.cfg.pid_path:
            try:
                Path(self.cfg.pid_path).write_text(str(os.getpid()))
            except OSError:
                pass

    # -- public API -----------------------------------------------------------

    def run(self) -> WatchdogState:
        # Initialize throttle baseline from the RUN's actual configured rate, so
        # throttling can only slow the scan down — never speed it up past the
        # operator's intended rate (previous bug: hardcoded 5000 default).
        initial = fetch_run_state(self.run_id, self.cfg.base_url) or {}
        cfg = (initial.get("run", {}) or {}).get("config") or {}
        try:
            self.state.masscan_rate = int(cfg.get("masscan_rate") or self.state.masscan_rate)
            self.state.naabu_rate = int(cfg.get("naabu_rate") or self.state.naabu_rate)
        except (TypeError, ValueError):
            pass
        self._log("=== watchdog started "
                  f"run={self.run_id} interval={self.cfg.check_interval_seconds}s "
                  f"stall_threshold={self.cfg.stall_threshold} "
                  f"baseline_rate=masscan:{self.state.masscan_rate}/naabu:{self.state.naabu_rate} ===")
        import time as _time
        prev: Snapshot | None = None
        last_tick = _time.monotonic()
        while not self._stop:
            # Sleep-gap detection: if wall-clock between checks is far longer than
            # the configured interval (e.g. laptop sleep/suspend), skip stall
            # accounting for this cycle to avoid false-positive throttling.
            now_tick = _time.monotonic()
            gap = now_tick - last_tick
            last_tick = now_tick
            sleep_gap = gap > self.cfg.check_interval_seconds * 3
            snap = take_snapshot(self.run_id, self.cfg.base_url)
            self._record_snapshot(snap)
            if snap.status in ("completed", "failed"):
                self._finish(f"run finished status={snap.status} findings={snap.findings_count}")
                break
            if snap.status == "cancelled":
                self._finish("run cancelled externally")
                break
            verdict = detect_progress(prev, snap, cpu_threshold=self.cfg.cpu_activity_threshold)
            if sleep_gap:
                self._log(f"  ⏸ sleep-gap detected ({gap:.0f}s ≫ interval) — skipping stall accounting")
            elif verdict.stalled:
                self.state.stall_streak += 1
            else:
                if self.state.stall_streak:
                    self._log(f"  ↑ progress: {'; '.join(verdict.reasons)} — reset stall")
                self.state.stall_streak = 0
            self._log(self._format_snap_line(snap, verdict))
            if self.state.stall_streak >= self.cfg.stall_threshold:
                if not self._maybe_throttle():
                    # max throttle reached, reset stall counter to avoid loop
                    self.state.stall_streak = 0
            prev = snap
            self._sleep(self.cfg.check_interval_seconds)
        self._persist_state()
        return self.state

    def stop(self) -> None:
        self._stop = True

    # -- internals ------------------------------------------------------------

    def _format_snap_line(self, s: Snapshot, v: StallVerdict) -> str:
        chunk = f"{s.chunk_index}/{s.chunk_total}" if s.chunk_index is not None else "?"
        proc_summary = ""
        if s.scanner_procs:
            top = max(s.scanner_procs, key=lambda p: p.get("cpu", 0.0))
            proc_summary = f"top={top.get('cmd','')[:35]} cpu={top.get('cpu',0):.1f}%"
        return (
            f"status={s.status} mod={s.running_module} chunk={chunk} "
            f"proc={s.processed_count} pct={s.percent:.0f} "
            f"findings={s.findings_count} stall={self.state.stall_streak}/{self.cfg.stall_threshold} "
            f"thr={self.state.throttle_level} | {proc_summary} | {s.stats_line}"
        )

    def _record_snapshot(self, snap: Snapshot) -> None:
        self.state.last_snapshot = asdict(snap)
        self.state.history.append({
            "ts": snap.timestamp,
            "status": snap.status,
            "module": snap.running_module,
            "chunk_index": snap.chunk_index,
            "processed_count": snap.processed_count,
            "percent": snap.percent,
            "findings": snap.findings_count,
            "active_procs": len(snap.scanner_procs),
            "max_cpu": max((p.get("cpu", 0.0) for p in snap.scanner_procs), default=0.0),
        })
        # cap history size
        if len(self.state.history) > 500:
            self.state.history = self.state.history[-500:]

    def _maybe_throttle(self) -> bool:
        if self.state.throttle_level >= self.cfg.max_throttle_level:
            self._log(f"throttle maxed (level={self.state.throttle_level}) — leaving as-is")
            return False
        new_m = max(self.cfg.min_rate, self.state.masscan_rate // 2)
        new_n = max(self.cfg.min_rate, self.state.naabu_rate // 2)
        self._log(f"===== THROTTLE level={self.state.throttle_level+1} "
                  f"masscan {self.state.masscan_rate}→{new_m} naabu {self.state.naabu_rate}→{new_n} =====")
        data = fetch_run_state(self.run_id, self.cfg.base_url) or {}
        cancel_run(self.run_id, self.cfg.base_url)
        time.sleep(3)
        payload = build_throttled_payload(data, masscan_rate=new_m, naabu_rate=new_n)
        new_id = start_run(payload, self.cfg.base_url)
        if not new_id:
            self._log("failed to start throttled run — aborting watchdog")
            self._finish("throttle restart failed")
            self._stop = True
            return False
        self._log(f"new throttled run: {new_id}")
        self.run_id = new_id
        self.state.run_id = new_id
        self.state.throttle_level += 1
        self.state.masscan_rate = new_m
        self.state.naabu_rate = new_n
        self.state.stall_streak = 0
        self._persist_state()
        return True

    def _finish(self, reason: str) -> None:
        self.state.finished = True
        self.state.finish_reason = reason
        self._log(f"=== watchdog exiting: {reason} ===")
        self._stop = True

    def _persist_state(self) -> None:
        if not self.cfg.state_path:
            return
        try:
            Path(self.cfg.state_path).write_text(json.dumps(asdict(self.state), default=str))
        except OSError as exc:
            _log.warning("persist state failed: %s", exc)

    def _log(self, msg: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"{stamp} {msg}"
        if self.cfg.log_path:
            try:
                with open(self.cfg.log_path, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass
        else:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def _sleep(self, seconds: int) -> None:
        slept = 0
        while not self._stop and slept < seconds:
            chunk = min(2, seconds - slept)
            time.sleep(chunk)
            slept += chunk


# -- Daemon helpers (CLI use) ------------------------------------------------


def default_workspace_paths(run_id: str, workspace: Path | None = None) -> dict[str, Path]:
    ws = (workspace or Path.cwd()).resolve()
    run_dir = ws / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return {
        "log": run_dir / "watchdog.log",
        "state": run_dir / "watchdog.state.json",
        "pid": run_dir / "watchdog.pid",
    }


def daemonize_and_run(run_id: str, config: WatchdogConfig) -> int:
    """Fork a detached child and run the watchdog there. Returns child PID."""
    if os.name != "posix":
        # Fallback for Windows / non-POSIX: just run in same process (caller can
        # background via Popen with creationflags). We still write the PID file.
        Watchdog(run_id, config).run()
        return os.getpid()
    pid = os.fork()
    if pid > 0:
        return pid  # parent returns
    # child
    os.setsid()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    # close stdio
    try:
        sys.stdin.close()
    except OSError:
        pass
    devnull = open(os.devnull, "rb+")
    os.dup2(devnull.fileno(), 0)
    os.dup2(devnull.fileno(), 1)
    os.dup2(devnull.fileno(), 2)
    try:
        Watchdog(run_id, config).run()
    finally:
        os._exit(0)


def read_pid(pid_path: Path) -> int | None:
    try:
        return int(pid_path.read_text().strip())
    except (OSError, ValueError):
        return None


def is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def stop_daemon(pid_path: Path) -> bool:
    pid = read_pid(pid_path)
    if pid is None or not is_alive(pid):
        try:
            pid_path.unlink()
        except OSError:
            pass
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return False
    # wait briefly
    for _ in range(10):
        time.sleep(0.3)
        if not is_alive(pid):
            break
    if is_alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        pid_path.unlink()
    except OSError:
        pass
    return True


def watchdog_status(pid_path: Path, state_path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"running": False, "pid": None, "state": None}
    pid = read_pid(pid_path)
    if pid is not None and is_alive(pid):
        out["running"] = True
        out["pid"] = pid
    try:
        if state_path.exists():
            out["state"] = json.loads(state_path.read_text())
    except (OSError, ValueError):
        pass
    return out
