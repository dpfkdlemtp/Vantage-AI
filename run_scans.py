import subprocess
import json
import sys
from scanner.runner import (
    execute_port_scan_tasks,
    execute_http_probe_tasks,
    execute_subdomain_enum_tasks,
    execute_dir_enum_tasks,
    execute_banner_probe_tasks,
    execute_domain_discovery_tasks,
)


def run_target(target: str) -> None:
    print(f"[*] Starting scan for {target}")
    result = subprocess.run(
        [sys.executable, "-m", "scanner.cli", "scan", target],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[!] Failed to create run for {target}:\n{result.stderr}")
        return

    try:
        data = json.loads(result.stdout)
        run_id = data.get("run_id")
    except Exception as exc:
        print(f"[!] Failed to parse run_id for {target}: {exc}\n{result.stdout}")
        return

    if not run_id:
        print(f"[!] No run_id in response for {target}: {result.stdout}")
        return

    print(f"[*] Run created: {run_id}")

    modules = [
        ("subdomain_enum", execute_subdomain_enum_tasks),
        ("port_scan",      execute_port_scan_tasks),
        ("http_probe",     execute_http_probe_tasks),
        ("domain_discovery", execute_domain_discovery_tasks),
        ("banner_probe",   execute_banner_probe_tasks),
        ("dir_enum",       execute_dir_enum_tasks),
    ]
    for phase_name, executor in modules:
        print(f"[*] Running {phase_name} for {run_id}...")
        try:
            summary = executor(run_id)
            completed = summary.get("completed_task_count", 0)
            failed = summary.get("failed_task_count", 0)
            findings = summary.get("finding_count", 0)
            print(f"    done — tasks: {completed} ok / {failed} failed, findings: {findings}")
        except Exception as exc:
            print(f"[!] {phase_name} raised an exception: {exc}")

    print(f"[+] Finished {target} (run_id={run_id})")


if __name__ == "__main__":
    targets = ["114.31.114.0/26", "211.117.106.96/27"]
    for t in targets:
        run_target(t)
