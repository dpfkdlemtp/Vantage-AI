from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path


def resolve_default_binary_path(binary_name: str) -> Path | None:
    for candidate in default_binary_candidates(binary_name):
        if candidate.exists():
            return candidate
    discovered = shutil.which(binary_name)
    if discovered:
        return Path(discovered).resolve()
    return None


def default_binary_candidates(binary_name: str) -> list[Path]:
    system_name = platform.system()
    if system_name == "Windows":
        return windows_binary_candidates(binary_name)
    if system_name == "Darwin":
        return darwin_binary_candidates(binary_name)
    return []


def windows_binary_candidates(binary_name: str) -> list[Path]:
    local_appdata = os.getenv("LOCALAPPDATA")
    if not local_appdata:
        return []
    tools_root = Path(local_appdata) / "web-scanner-tools"
    if binary_name == "nmap":
        return [tools_root / "nmap" / "nmap.exe"]
    return [tools_root / "bin" / f"{binary_name}.exe"]


def darwin_binary_candidates(binary_name: str) -> list[Path]:
    home_dir = Path(os.getenv("HOME") or Path.home())
    return [
        home_dir / "go" / "bin" / binary_name,
        Path("/usr/local/bin") / binary_name,
    ]
