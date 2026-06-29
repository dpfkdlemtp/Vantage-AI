"""UDP port scanner using nmap -sU.

UDP scanning is inherently slow and unreliable (no SYN-ACK equivalent),
so this targets a curated set of common UDP services by default and
uses nmap's protocol-specific probes (which masscan UDP lacks).
"""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass

from scanner.utils.process import run_text_capture


# Common UDP ports that often reveal misconfigurations
DEFAULT_UDP_PORTS = "53,67,68,69,123,137,138,161,500,514,520,623,1434,1900,4500,5353,11211"


class UdpScanError(RuntimeError):
    pass


@dataclass(frozen=True)
class UdpPortResult:
    host: str
    ip: str
    port: int
    state: str  # open | open|filtered | closed
    service: str
    product: str
    version: str


@dataclass(frozen=True)
class UdpScanRunResult:
    command: list[str]
    targets: list[str]
    ports: list[UdpPortResult]
    raw_output: str


def is_nmap_available(nmap_bin: str = "nmap") -> bool:
    return shutil.which(nmap_bin) is not None


def run_udp_scan(
    targets: Sequence[str],
    *,
    nmap_bin: str = "nmap",
    ports: str = DEFAULT_UDP_PORTS,
    timing_template: str = "T4",
    version_detection: bool = True,
    host_timeout_seconds: int = 120,
) -> UdpScanRunResult:
    """Run nmap UDP scan. Requires root/Administrator on most systems."""
    normalized = sorted({t.strip() for t in targets if t.strip()})
    if not normalized:
        return UdpScanRunResult(command=[], targets=[], ports=[], raw_output="")

    command = [
        nmap_bin,
        "-sU", "-Pn", "-n",
        "-T", timing_template.lstrip("T"),
        "-p", ports,
        "--max-retries", "2",
        "--host-timeout", f"{host_timeout_seconds}s",
        "-oX", "-",
    ]
    if version_detection:
        command.extend(["-sV", "--version-intensity", "0"])
    command.extend(normalized)
    try:
        completed = run_text_capture(command)
    except FileNotFoundError as exc:
        raise UdpScanError(f"nmap binary not found: {exc}") from exc

    if completed.returncode != 0:
        # UDP requires root; surface this clearly
        detail = (completed.stderr or "").strip() or "udp scan failed"
        if "requires root" in detail.lower() or "operation not permitted" in detail.lower():
            raise UdpScanError(
                "UDP scan requires root/Administrator privileges. "
                "Run with elevated permissions or disable udp_scan_enabled."
            )
        raise UdpScanError(f"nmap UDP exited {completed.returncode}: {detail}")

    raw = completed.stdout
    return UdpScanRunResult(
        command=command,
        targets=normalized,
        ports=_parse_xml(raw) if raw.strip() else [],
        raw_output=raw,
    )


def can_run_udp_unprivileged(nmap_bin: str = "nmap") -> bool:
    """Probe whether nmap can run UDP scan without elevation (CAP_NET_RAW / setuid)."""
    try:
        completed = subprocess.run(
            [nmap_bin, "-sU", "-p", "53", "--unprivileged", "127.0.0.1"],
            capture_output=True, text=True, timeout=10,
        )
        return completed.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _parse_xml(raw: str) -> list[UdpPortResult]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []
    out: list[UdpPortResult] = []
    for host_el in root.findall("host"):
        ip = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr_el.get("addr") or ""
                break
        host_name = ""
        for hn in host_el.findall("./hostnames/hostname"):
            name = hn.get("name")
            if name:
                host_name = name
                break
        host_name = host_name or ip
        for port_el in host_el.findall("./ports/port"):
            if port_el.get("protocol") != "udp":
                continue
            port_id = port_el.get("portid")
            if not port_id or not port_id.isdigit():
                continue
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state not in ("open", "open|filtered"):
                continue
            service_el = port_el.find("service")
            service = (service_el.get("name") if service_el is not None else "") or ""
            product = (service_el.get("product") if service_el is not None else "") or ""
            version = (service_el.get("version") if service_el is not None else "") or ""
            out.append(UdpPortResult(
                host=host_name, ip=ip, port=int(port_id),
                state=state or "open", service=service, product=product, version=version,
            ))
    return out
