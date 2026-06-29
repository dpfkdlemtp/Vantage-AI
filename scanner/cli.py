from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from scanner.ser.cli import ser_app

from scanner.report import write_html_report
from scanner.runner import (
    create_scan_run,
    extend_scan_run,
    generate_report_summary,
    render_summary_json,
    resume_run,
)
from scanner.web import serve_ui

app = typer.Typer(
    help=(
        "Defensive scanning orchestrator for authorized targets only. Create runs, inspect "
        "resumable state, and render reports from persisted findings."
    )
)
app.add_typer(ser_app, name="ser")


@app.command(
    help=(
        "Create a new run, persist config/state, and enqueue pending tasks for the selected "
        "modules. This command does not execute external scanners."
    )
)
def scan(
    target: str = typer.Argument(..., help="Authorized target root domain or host."),
    module: list[str] | None = typer.Option(
        None,
        "--module",
        "-m",
        help="Module to enqueue. Repeat the option or pass comma-separated values.",
    ),
    profile: str = typer.Option(
        "safe",
        "--profile",
        help="Speed profile for later phase runners: safe, balanced, or fast.",
    ),
) -> None:
    _emit_command(lambda: create_scan_run(target, modules=module, profile=profile))


@app.command(help="Load an existing run and print the incomplete tasks that can be resumed.")
def resume(run_id: str = typer.Argument(..., help="Run identifier to inspect.")) -> None:
    _emit_command(lambda: resume_run(run_id))


@app.command(help="Add new modules to an existing run so later phases can continue from saved state.")
def extend(
    run_id: str = typer.Argument(..., help="Run identifier to extend."),
    module: list[str] = typer.Option(
        ...,
        "--module",
        "-m",
        help="Module to add. Repeat the option or pass comma-separated values.",
    ),
) -> None:
    _emit_command(lambda: extend_scan_run(run_id, modules=module))


@app.command(
    help=(
        "Print the persisted JSON report summary for a run and optionally write an HTML "
        "report file."
    )
)
def report(
    run_id: str = typer.Argument(..., help="Run identifier to summarize."),
    html: Path | None = typer.Option(
        None,
        "--html",
        help="Optional HTML output path. JSON is still printed to stdout.",
    ),
) -> None:
    def action() -> dict[str, Any]:
        summary = generate_report_summary(run_id)
        if html is not None:
            written_path = write_html_report(summary, html.resolve())
            summary["html_report_path"] = str(written_path)
        return summary

    _emit_command(action)


@app.command(
    help=(
        "Start the local web UI for run creation, execution control, progress polling, and "
        "partial-result inspection."
    )
)
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for the web UI."),
    port: int = typer.Option(8000, "--port", help="TCP port for the web UI."),
    workspace: Path | None = typer.Option(
        None,
        "--workspace",
        help="Optional workspace root. Defaults to the current directory.",
    ),
) -> None:
    try:
        serve_ui(host=host, port=port, workspace=workspace)
    except OSError as exc:
        typer.secho(str(exc), err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc


@app.command(help="Start the scan watchdog (OS-aware stall detection + auto-throttle).")
def watchdog_start(
    run_id: str = typer.Option(..., "--run-id", help="Run ID to monitor."),
    background: bool = typer.Option(True, "--background/--foreground", help="Run as detached daemon."),
    base_url: str = typer.Option("http://127.0.0.1:8000", "--base-url"),
    interval: int = typer.Option(120, "--interval", help="Seconds between checks."),
    stall_threshold: int = typer.Option(15, "--stall-threshold", help="Consecutive stalls before throttle."),
    workspace: Path | None = typer.Option(None, "--workspace"),
) -> None:
    from scanner.watchdog import (
        WatchdogConfig, Watchdog, daemonize_and_run, default_workspace_paths,
    )
    paths = default_workspace_paths(run_id, workspace)
    cfg = WatchdogConfig(
        base_url=base_url,
        check_interval_seconds=interval,
        stall_threshold=stall_threshold,
        log_path=str(paths["log"]),
        state_path=str(paths["state"]),
        pid_path=str(paths["pid"]),
    )
    if background:
        pid = daemonize_and_run(run_id, cfg)
        typer.secho(f"watchdog daemon started pid={pid}", fg=typer.colors.GREEN)
        typer.echo(f"  log:   {paths['log']}")
        typer.echo(f"  state: {paths['state']}")
        typer.echo(f"  pid:   {paths['pid']}")
    else:
        Watchdog(run_id, cfg).run()


@app.command(help="Stop a running watchdog daemon.")
def watchdog_stop(
    run_id: str = typer.Option(..., "--run-id"),
    workspace: Path | None = typer.Option(None, "--workspace"),
) -> None:
    from scanner.watchdog import default_workspace_paths, stop_daemon
    paths = default_workspace_paths(run_id, workspace)
    ok = stop_daemon(paths["pid"])
    if ok:
        typer.secho("watchdog stopped", fg=typer.colors.GREEN)
    else:
        typer.secho("no running watchdog found", fg=typer.colors.YELLOW)


@app.command(help="Show watchdog status and last snapshot.")
def watchdog_status(
    run_id: str = typer.Option(..., "--run-id"),
    workspace: Path | None = typer.Option(None, "--workspace"),
) -> None:
    from scanner.watchdog import default_workspace_paths, watchdog_status as _status
    paths = default_workspace_paths(run_id, workspace)
    status = _status(paths["pid"], paths["state"])
    typer.echo(json.dumps(status, indent=2, default=str))


@app.command(help="Tail the watchdog log for a run.")
def watchdog_tail(
    run_id: str = typer.Option(..., "--run-id"),
    lines: int = typer.Option(30, "--lines", "-n"),
    workspace: Path | None = typer.Option(None, "--workspace"),
) -> None:
    from scanner.watchdog import default_workspace_paths
    paths = default_workspace_paths(run_id, workspace)
    log_path = paths["log"]
    if not log_path.exists():
        typer.secho(f"no log at {log_path}", fg=typer.colors.YELLOW)
        return
    with open(log_path) as f:
        all_lines = f.readlines()
    for line in all_lines[-lines:]:
        typer.echo(line.rstrip())


@app.command(help="Check installation status of all required external tools.")
def tools_check() -> None:
    from scanner.installer import check_all_tools, detect_platform, is_go_available

    platform_name = detect_platform()
    go_ok, go_version = is_go_available()
    typer.secho(f"Platform: {platform_name}", fg=typer.colors.CYAN)
    typer.secho(
        f"Go runtime: {go_version if go_ok else 'NOT FOUND'}",
        fg=typer.colors.GREEN if go_ok else typer.colors.YELLOW,
    )
    typer.echo("")
    summary = check_all_tools()
    width_name = max(len(item["name"]) for item in summary)
    for item in summary:
        status = "OK " if item["installed"] else "MISS"
        color = typer.colors.GREEN if item["installed"] else typer.colors.RED
        line = f"  [{status}] {item['name']:<{width_name}}  {item['version'] or item['install_hint']}"
        typer.secho(line, fg=color)


@app.command(help="Install missing external tools (Go-based via `go install`, native via brew/winget/choco).")
def tools_install(
    tool: list[str] = typer.Option(
        [],
        "--tool",
        "-t",
        help="Specific tool name(s). Repeat to install multiple. Omit to install all missing tools.",
    ),
    force: bool = typer.Option(False, "--force", help="Reinstall even if already present."),
) -> None:
    from scanner.installer import TOOL_SPECS, install_tool

    names = tool if tool else list(TOOL_SPECS.keys())
    unknown = [n for n in names if n not in TOOL_SPECS]
    if unknown:
        typer.secho(f"Unknown tool(s): {', '.join(unknown)}", fg=typer.colors.RED, err=True)
        typer.secho(f"Available: {', '.join(TOOL_SPECS.keys())}", err=True)
        raise typer.Exit(code=2)

    overall_success = True
    for name in names:
        typer.secho(f"\n→ {name}", fg=typer.colors.CYAN, bold=True)
        result = install_tool(name, force=force)
        color = typer.colors.GREEN if result.success else typer.colors.RED
        typer.secho(f"   method: {result.method}", fg=color)
        typer.secho(f"   status: {'OK' if result.success else 'FAIL'}", fg=color)
        if result.path:
            typer.echo(f"   path:   {result.path}")
        if result.version:
            typer.echo(f"   version: {result.version}")
        if result.message:
            typer.echo(f"   note:   {result.message}")
        if not result.success and result.install_commands:
            typer.secho("   manual command(s):", fg=typer.colors.YELLOW)
            for cmd in result.install_commands:
                typer.echo(f"     {cmd}")
        if not result.success:
            overall_success = False
    if not overall_success:
        raise typer.Exit(code=1)


def _emit_command(action: CommandAction) -> None:
    try:
        typer.echo(render_summary_json(action()))
    except (FileNotFoundError, LookupError, RuntimeError, ValueError) as exc:
        typer.secho(str(exc), err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc


CommandAction = Callable[[], dict[str, Any]]


if __name__ == "__main__":
    app()
