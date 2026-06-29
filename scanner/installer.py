"""Installer for external scanner tools (Go-based + native).

Supports macOS (Homebrew + go install), Linux (apt + go install),
and Windows (winget/Chocolatey + go install).

Each tool descriptor declares:
- name: tool identifier (matches config bin keys)
- type: "go" or "native"
- go_module: full module path for `go install` (Go-based only)
- mac_brew / linux_apt / win_winget / win_choco: package names (native only)
- check_args: arguments for version probe (defaults to --version)
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


def _python_executable() -> str:
    return sys.executable or "python3"


@dataclass
class ToolSpec:
    name: str
    type: str  # "go" | "native"
    go_module: str = ""
    mac_brew: str = ""
    linux_apt: str = ""
    win_winget: str = ""
    win_choco: str = ""
    check_args: tuple[str, ...] = ("--version",)
    notes: str = ""


TOOL_SPECS: dict[str, ToolSpec] = {
    "subfinder": ToolSpec(
        name="subfinder",
        type="go",
        go_module="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        check_args=("-version",),
    ),
    "assetfinder": ToolSpec(
        name="assetfinder",
        type="go",
        go_module="github.com/tomnomnom/assetfinder@latest",
        check_args=("--help",),
    ),
    "httpx": ToolSpec(
        name="httpx",
        type="go",
        go_module="github.com/projectdiscovery/httpx/cmd/httpx@latest",
        check_args=("-version",),
    ),
    "ffuf": ToolSpec(
        name="ffuf",
        type="go",
        go_module="github.com/ffuf/ffuf/v2@latest",
        check_args=("-V",),
    ),
    "naabu": ToolSpec(
        name="naabu",
        type="go",
        go_module="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        check_args=("-version",),
        notes="SYN scan mode requires root/CAP_NET_RAW on Linux.",
    ),
    "dnsx": ToolSpec(
        name="dnsx",
        type="go",
        go_module="github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        check_args=("-version",),
    ),
    "subzy": ToolSpec(
        name="subzy",
        type="go",
        go_module="github.com/PentestPad/subzy@latest",
        check_args=("--help",),
    ),
    "gau": ToolSpec(
        name="gau",
        type="go",
        go_module="github.com/lc/gau/v2/cmd/gau@latest",
        check_args=("--version",),
    ),
    "nmap": ToolSpec(
        name="nmap",
        type="native",
        mac_brew="nmap",
        linux_apt="nmap",
        win_winget="Insecure.Nmap",
        win_choco="nmap",
        check_args=("--version",),
        notes="SYN scan requires root/Administrator.",
    ),
    "masscan": ToolSpec(
        name="masscan",
        type="native",
        mac_brew="masscan",
        linux_apt="masscan",
        win_choco="masscan",
        check_args=("--version",),
        notes="Requires root/Administrator. On Windows, install via Chocolatey or download release.",
    ),
    "playwright": ToolSpec(
        name="playwright",
        type="pip",
        notes="Python package + Chromium browser (~150MB). Used for JS rendering, SPA crawl, and auth login.",
    ),
}


@dataclass
class InstallResult:
    name: str
    success: bool
    path: str = ""
    version: str = ""
    method: str = ""  # "go", "brew", "apt", "winget", "choco", "skipped"
    stdout: str = ""
    stderr: str = ""
    message: str = ""
    install_commands: list[str] = field(default_factory=list)


def detect_platform() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "darwin"
    if system == "windows":
        return "windows"
    return "linux"


def is_tool_installed(name: str) -> tuple[bool, str]:
    """Return (installed, resolved_path). Looks in PATH and standard Go bin dirs."""
    if name == "playwright":
        import importlib.util
        if importlib.util.find_spec("playwright") is not None:
            return True, "python:playwright"
        return False, ""
    direct = shutil.which(name)
    if direct:
        return True, direct
    # Fallback: check ~/go/bin and %USERPROFILE%\go\bin
    home = Path(os.path.expanduser("~"))
    candidates = [home / "go" / "bin" / name]
    if detect_platform() == "windows":
        candidates.extend([
            home / "go" / "bin" / f"{name}.exe",
            Path(os.getenv("GOPATH") or "") / "bin" / f"{name}.exe",
        ])
    else:
        candidates.append(Path("/usr/local/bin") / name)
    for candidate in candidates:
        try:
            if candidate.is_file():
                return True, str(candidate)
        except OSError:
            continue
    return False, ""


def get_tool_version(name: str, spec: ToolSpec | None = None) -> str:
    spec = spec or TOOL_SPECS.get(name)
    if spec is None:
        return ""
    if name == "playwright":
        import importlib.util
        if importlib.util.find_spec("playwright") is None:
            return ""
        try:
            completed = subprocess.run(
                [_python_executable(), "-m", "playwright", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            out = (completed.stdout or completed.stderr or "").strip()
            return out[:200]
        except (subprocess.TimeoutExpired, OSError):
            return "installed"
    path = shutil.which(name) or ""
    if not path:
        # Try go bin
        installed, path = is_tool_installed(name)
        if not installed:
            return ""
    try:
        completed = subprocess.run(
            [path, *spec.check_args],
            capture_output=True, text=True, timeout=5,
        )
        out = (completed.stdout + "\n" + completed.stderr).strip()
        # Take first non-empty line; cap length
        for line in out.splitlines():
            line = line.strip()
            if line:
                return line[:200]
        return ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def is_go_available() -> tuple[bool, str]:
    go_path = shutil.which("go")
    if not go_path:
        return False, ""
    try:
        completed = subprocess.run(
            [go_path, "version"], capture_output=True, text=True, timeout=5
        )
        return True, (completed.stdout or "").strip()
    except (subprocess.TimeoutExpired, OSError):
        return False, ""


def install_tool(name: str, *, force: bool = False, timeout_seconds: int = 600) -> InstallResult:
    spec = TOOL_SPECS.get(name)
    if spec is None:
        return InstallResult(name=name, success=False, message=f"unknown tool '{name}'")

    if not force:
        installed, path = is_tool_installed(name)
        if installed:
            return InstallResult(
                name=name, success=True, path=path,
                version=get_tool_version(name, spec), method="skipped",
                message="already installed",
            )

    if spec.type == "go":
        return _install_go_tool(spec, timeout_seconds=timeout_seconds)
    if spec.type == "pip":
        return _install_pip_tool(spec, timeout_seconds=timeout_seconds)
    return _install_native_tool(spec, timeout_seconds=timeout_seconds)


def _install_pip_tool(spec: ToolSpec, *, timeout_seconds: int) -> InstallResult:
    """Special-case Playwright: pip install + browser binary download."""
    if spec.name != "playwright":
        return InstallResult(
            name=spec.name, success=False, method="pip",
            message=f"pip install not supported for {spec.name}",
        )
    python = _python_executable()
    pip_cmd = [python, "-m", "pip", "install", "--upgrade", "playwright"]
    install_hints = [
        f"{python} -m pip install --upgrade playwright",
        f"{python} -m playwright install chromium",
    ]
    pip_stdout = pip_stderr = ""
    try:
        completed = subprocess.run(pip_cmd, capture_output=True, text=True, timeout=timeout_seconds)
        pip_stdout, pip_stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        return InstallResult(
            name=spec.name, success=False, method="pip",
            install_commands=install_hints,
            message=f"pip install timed out: {exc}",
        )
    if completed.returncode != 0:
        # Retry with --break-system-packages on PEP 668 systems
        retry_cmd = pip_cmd + ["--break-system-packages"]
        try:
            completed_retry = subprocess.run(retry_cmd, capture_output=True, text=True, timeout=timeout_seconds)
            if completed_retry.returncode == 0:
                completed = completed_retry
                pip_stdout, pip_stderr = completed_retry.stdout, completed_retry.stderr
        except subprocess.TimeoutExpired:
            pass
    if completed.returncode != 0:
        return InstallResult(
            name=spec.name, success=False, method="pip",
            stdout=pip_stdout, stderr=pip_stderr,
            install_commands=install_hints,
            message=f"pip install failed (returncode={completed.returncode})",
        )
    # Install Chromium browser binary
    try:
        browser_cmd = [python, "-m", "playwright", "install", "chromium"]
        browser_completed = subprocess.run(browser_cmd, capture_output=True, text=True, timeout=max(120, timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        return InstallResult(
            name=spec.name, success=False, method="pip",
            stdout=pip_stdout, stderr=pip_stderr,
            install_commands=install_hints,
            message=f"playwright install chromium timed out: {exc}",
        )
    if browser_completed.returncode != 0:
        return InstallResult(
            name=spec.name, success=False, method="pip",
            stdout=pip_stdout + "\n" + browser_completed.stdout,
            stderr=pip_stderr + "\n" + browser_completed.stderr,
            install_commands=install_hints,
            message="pip ok but chromium download failed",
        )
    installed_after, path_after = is_tool_installed(spec.name)
    return InstallResult(
        name=spec.name, success=installed_after,
        path=path_after,
        version=get_tool_version(spec.name, spec),
        method="pip",
        stdout=pip_stdout + "\n" + browser_completed.stdout,
        stderr=pip_stderr + "\n" + browser_completed.stderr,
        install_commands=install_hints,
        message="playwright + chromium installed" if installed_after else "install completed but module not importable",
    )


def _install_go_tool(spec: ToolSpec, *, timeout_seconds: int) -> InstallResult:
    has_go, _go_version = is_go_available()
    install_cmd = f"go install -v {spec.go_module}"
    if not has_go:
        return InstallResult(
            name=spec.name, success=False, method="go",
            install_commands=[
                "# Install Go first:",
                "#   macOS:   brew install go",
                "#   Windows: winget install GoLang.Go    (or download from https://go.dev/dl)",
                "#   Linux:   sudo apt install golang-go  (or download from https://go.dev/dl)",
                install_cmd,
            ],
            message="Go is not installed. Install Go, then re-run.",
        )

    go_path = shutil.which("go") or "go"
    try:
        completed = subprocess.run(
            [go_path, "install", "-v", spec.go_module],
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return InstallResult(
            name=spec.name, success=False, method="go",
            install_commands=[install_cmd], message=f"go install timed out: {exc}",
        )
    success = completed.returncode == 0
    installed_after, path_after = is_tool_installed(spec.name)
    if success and installed_after:
        return InstallResult(
            name=spec.name, success=True, path=path_after,
            version=get_tool_version(spec.name, spec), method="go",
            stdout=completed.stdout, stderr=completed.stderr,
            install_commands=[install_cmd],
            message="installed via go install",
        )
    return InstallResult(
        name=spec.name, success=False, method="go",
        stdout=completed.stdout, stderr=completed.stderr,
        install_commands=[install_cmd],
        message=f"go install failed (returncode={completed.returncode})",
    )


def _install_native_tool(spec: ToolSpec, *, timeout_seconds: int) -> InstallResult:
    platform_name = detect_platform()
    commands: list[list[str]] = []
    install_hints: list[str] = []
    method = ""

    if platform_name == "darwin" and spec.mac_brew:
        brew = shutil.which("brew")
        if brew:
            commands.append([brew, "install", spec.mac_brew])
            method = "brew"
        install_hints.append(f"brew install {spec.mac_brew}")
    elif platform_name == "linux" and spec.linux_apt:
        # We do NOT auto-sudo. We only execute apt without sudo (will fail if not root).
        # Provide the command as hint for manual run.
        install_hints.append(f"sudo apt install -y {spec.linux_apt}")
        apt = shutil.which("apt-get") or shutil.which("apt")
        # Only attempt if running as root (uid 0).
        try:
            if apt and os.geteuid() == 0:
                commands.append([apt, "install", "-y", spec.linux_apt])
                method = "apt"
        except AttributeError:
            pass
    elif platform_name == "windows":
        winget = shutil.which("winget")
        choco = shutil.which("choco")
        if winget and spec.win_winget:
            commands.append([winget, "install", "--silent", "--accept-source-agreements",
                             "--accept-package-agreements", spec.win_winget])
            method = "winget"
            install_hints.append(f"winget install {spec.win_winget}")
        if choco and spec.win_choco:
            if not commands:
                commands.append([choco, "install", "-y", spec.win_choco])
                method = "choco"
            install_hints.append(f"choco install -y {spec.win_choco}")

    if not commands:
        return InstallResult(
            name=spec.name, success=False, method="native",
            install_commands=install_hints or [f"# install {spec.name} manually"],
            message=(
                f"No supported package manager found for {platform_name}. "
                "Run the suggested command manually."
            ),
        )

    last_stdout = ""
    last_stderr = ""
    success = False
    used_method = method
    for cmd in commands:
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            last_stderr = str(exc)
            continue
        last_stdout = completed.stdout
        last_stderr = completed.stderr
        if completed.returncode == 0:
            success = True
            break

    installed_after, path_after = is_tool_installed(spec.name)
    if success and installed_after:
        return InstallResult(
            name=spec.name, success=True, path=path_after,
            version=get_tool_version(spec.name, spec), method=used_method,
            stdout=last_stdout, stderr=last_stderr,
            install_commands=install_hints,
            message=f"installed via {used_method}",
        )
    return InstallResult(
        name=spec.name, success=False, method=used_method,
        stdout=last_stdout, stderr=last_stderr,
        install_commands=install_hints,
        message=f"native install failed; try: {'; '.join(install_hints)}",
    )


def check_all_tools() -> list[dict]:
    """Return per-tool status summary suitable for API response."""
    summary: list[dict] = []
    for name, spec in TOOL_SPECS.items():
        installed, path = is_tool_installed(name)
        version = get_tool_version(name, spec) if installed else ""
        summary.append({
            "name": name,
            "type": spec.type,
            "installed": installed,
            "path": path,
            "version": version,
            "notes": spec.notes,
            "install_hint": _hint_for(spec),
        })
    return summary


def install_missing_tools(*, names: list[str] | None = None) -> list[InstallResult]:
    """Install all missing tools (or a specific subset). Skips already-installed."""
    target_names = names if names else list(TOOL_SPECS.keys())
    results: list[InstallResult] = []
    for name in target_names:
        results.append(install_tool(name))
    return results


def _hint_for(spec: ToolSpec) -> str:
    if spec.type == "go" and spec.go_module:
        return f"go install -v {spec.go_module}"
    if spec.type == "pip" and spec.name == "playwright":
        return "pip install playwright && python -m playwright install chromium"
    platform_name = detect_platform()
    if platform_name == "darwin" and spec.mac_brew:
        return f"brew install {spec.mac_brew}"
    if platform_name == "linux" and spec.linux_apt:
        return f"sudo apt install -y {spec.linux_apt}"
    if platform_name == "windows":
        parts = []
        if spec.win_winget:
            parts.append(f"winget install {spec.win_winget}")
        if spec.win_choco:
            parts.append(f"choco install -y {spec.win_choco}")
        if parts:
            return " | ".join(parts)
    return f"install {spec.name} manually"
