from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from scanner.utils.process import run_text_capture

NmapRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class NmapError(RuntimeError):
    pass


@dataclass(frozen=True)
class NmapPortResult:
    protocol: str
    port: int
    state: str | None
    service: str | None
    product: str | None
    version: str | None
    extrainfo: str | None
    raw_entry: dict[str, Any]


@dataclass(frozen=True)
class NmapHostResult:
    host: str
    ip: str | None
    status: str | None
    hostnames: list[str]
    ports: list[NmapPortResult]
    raw_host: dict[str, Any]


@dataclass(frozen=True)
class NmapRunResult:
    command: list[str]
    targets: list[str]
    hosts: list[NmapHostResult]
    raw_output: str
    scan_warnings: list[str] = field(default_factory=list)


def run_nmap_scan(
    targets: Sequence[str],
    *,
    nmap_bin: str = "nmap",
    profile: str = "safe",
    ports: str = "1-65535",
    timing_template: str = "T4",
    version_detection: bool = False,
    proxies: str | None = None,
    runner: NmapRunner | None = None,
    nse_scripts: str | None = None,
    host_timeout: str | None = None,
) -> NmapRunResult:
    normalized_targets = _normalize_targets(targets)
    command = _build_nmap_command(
        nmap_bin=nmap_bin,
        profile=profile,
        ports=ports,
        timing_template=timing_template,
        version_detection=version_detection,
        proxies=proxies,
        targets=normalized_targets,
        force_tcp_connect=False,
        nse_scripts=nse_scripts,
        host_timeout=host_timeout,
    )
    if not normalized_targets:
        return NmapRunResult(command=command, targets=[], hosts=[], raw_output="")

    active_runner = runner or _default_runner
    scan_warnings: list[str] = []
    completed = active_runner(command)
    if completed.returncode != 0:
        retry_command = _build_nmap_command(
            nmap_bin=nmap_bin,
            profile=profile,
            ports=ports,
            timing_template=timing_template,
            version_detection=version_detection,
            proxies=proxies,
            targets=normalized_targets,
            force_tcp_connect=True,
            nse_scripts=nse_scripts,
            host_timeout=host_timeout,
        )
        if retry_command != command and _should_retry_with_tcp_connect(completed):
            scan_warnings.append(_tcp_connect_retry_warning())
            command = retry_command
            completed = active_runner(command)
        if completed.returncode == 0:
            raw_output = completed.stdout
            if not raw_output.strip():
                return NmapRunResult(
                    command=command,
                    targets=normalized_targets,
                    hosts=[],
                    raw_output=raw_output,
                    scan_warnings=scan_warnings,
                )
            return NmapRunResult(
                command=command,
                targets=normalized_targets,
                hosts=_parse_xml_output(raw_output),
                raw_output=raw_output,
                scan_warnings=scan_warnings,
            )
        detail = completed.stderr.strip() or completed.stdout.strip() or "nmap command failed"
        raise NmapError(f"nmap exited with code {completed.returncode}: {detail}")

    raw_output = completed.stdout
    if not raw_output.strip():
        return NmapRunResult(
            command=command,
            targets=normalized_targets,
            hosts=[],
            raw_output=raw_output,
            scan_warnings=scan_warnings,
        )

    return NmapRunResult(
        command=command,
        targets=normalized_targets,
        hosts=_parse_xml_output(raw_output),
        raw_output=raw_output,
        scan_warnings=scan_warnings,
    )


def _build_nmap_command(
    *,
    nmap_bin: str,
    profile: str,
    ports: str,
    timing_template: str,
    version_detection: bool,
    proxies: str | None,
    targets: Sequence[str],
    force_tcp_connect: bool = False,
    nse_scripts: str | None = None,
    host_timeout: str | None = None,
) -> list[str]:
    command: list[str] = [
        nmap_bin,
        "-oX",
        "-",
        "-v",
        "--stats-every",
        "10s",
        "-Pn",
        "-n",
        "--max-retries",
        "1",
        "--disable-arp-ping",
    ]
    host_timeout_value = (host_timeout or "").strip()
    if host_timeout_value:
        command.extend(["--host-timeout", host_timeout_value])
    if force_tcp_connect:
        command.append("-sT")
    else:
        command.extend(["--send-ip", "-sS"])
    command.append(_derive_timing_template(profile, timing_template))
    pnorm = str(ports).strip().lower()
    if pnorm in ("top1000", "top-1000"):
        command.extend(["--top-ports", "1000"])
    elif pnorm in ("well-known", "well_known", "iana-well-known", "1-1023"):
        command.extend(["-p", "1-1023"])
    else:
        command.extend(["-p", ports])
    if version_detection:
        command.append("-sV")
    nse_value = (nse_scripts or "").strip()
    if nse_value:
        command.extend(["--script", nse_value])
    proxy_value = str(proxies or "").strip()
    if proxy_value:
        command.extend(["--proxies", proxy_value])
    command.extend(targets)
    return command


def _should_retry_with_tcp_connect(completed: subprocess.CompletedProcess[str]) -> bool:
    output = f"{completed.stderr}\n{completed.stdout}".lower()
    raw_socket_markers = (
        "raw socket",
        "requires root privileges",
        "couldn't open a raw socket",
        "does not have adequate raw socket support",
        "operation not permitted",
        "you requested a scan type which requires root",
    )
    return any(marker in output for marker in raw_socket_markers)


def _tcp_connect_retry_warning() -> str:
    return (
        "nmap SYN scan (-sS) failed because raw packet access was unavailable; "
        "retried with TCP connect scan (-sT)."
    )


def _derive_timing_template(profile: str, timing_template: str) -> str:
    configured_level = _timing_level(timing_template)
    normalized_profile = profile.strip().lower()
    if normalized_profile == "safe":
        level = min(configured_level, 2)
    elif normalized_profile == "balanced":
        level = min(configured_level, 3)
    else:
        level = configured_level
    return f"-T{level}"


def _timing_level(value: str) -> int:
    normalized = value.strip().upper()
    if normalized.startswith("T") and normalized[1:].isdigit():
        return max(2, min(int(normalized[1:]), 4))
    return 3


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return run_text_capture(command)


def _parse_xml_output(raw_output: str) -> list[NmapHostResult]:
    try:
        root = ET.fromstring(raw_output)
    except ET.ParseError as exc:
        raise NmapError("nmap returned invalid XML output") from exc

    hosts: list[NmapHostResult] = []
    for host_element in root.findall("host"):
        hosts.append(_parse_host(host_element))
    return hosts


def _parse_host(host_element: ET.Element) -> NmapHostResult:
    hostnames = _hostnames(host_element)
    ip = _ip_address(host_element)
    status_element = host_element.find("status")
    ports = _parse_ports(host_element)
    host = hostnames[0] if hostnames else ip or ""
    return NmapHostResult(
        host=host,
        ip=ip,
        status=status_element.get("state") if status_element is not None else None,
        hostnames=hostnames,
        ports=ports,
        raw_host={
            "host": host,
            "ip": ip,
            "status": status_element.get("state") if status_element is not None else None,
            "hostnames": hostnames,
            "port_count": len(ports),
        },
    )


def _parse_ports(host_element: ET.Element) -> list[NmapPortResult]:
    ports: list[NmapPortResult] = []
    for port_element in host_element.findall("./ports/port"):
        protocol = port_element.get("protocol")
        port = _coerce_int(port_element.get("portid"))
        if protocol is None or port is None:
            continue
        state_element = port_element.find("state")
        service_element = port_element.find("service")
        ports.append(
            NmapPortResult(
                protocol=protocol,
                port=port,
                state=state_element.get("state") if state_element is not None else None,
                service=service_element.get("name") if service_element is not None else None,
                product=service_element.get("product") if service_element is not None else None,
                version=service_element.get("version") if service_element is not None else None,
                extrainfo=service_element.get("extrainfo") if service_element is not None else None,
                raw_entry={
                    "protocol": protocol,
                    "port": port,
                    "state": state_element.get("state") if state_element is not None else None,
                    "service": service_element.get("name") if service_element is not None else None,
                    "product": service_element.get("product") if service_element is not None else None,
                    "version": service_element.get("version") if service_element is not None else None,
                    "extrainfo": service_element.get("extrainfo") if service_element is not None else None,
                },
            )
        )
    return ports


def _hostnames(host_element: ET.Element) -> list[str]:
    names = {
        name
        for hostname_element in host_element.findall("./hostnames/hostname")
        if (name := hostname_element.get("name"))
    }
    return sorted(names)


def _ip_address(host_element: ET.Element) -> str | None:
    for address_element in host_element.findall("address"):
        if address_element.get("addrtype") in {"ipv4", "ipv6"}:
            return address_element.get("addr")
    first_address = host_element.find("address")
    return first_address.get("addr") if first_address is not None else None


def _normalize_targets(targets: Sequence[str]) -> list[str]:
    return sorted({target.strip() for target in targets if target.strip()})


def _coerce_int(value: str | None) -> int | None:
    if value is not None and value.isdigit():
        return int(value)
    return None
