from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass

from scanner.utils.process import run_text_capture


class MasscanError(RuntimeError):
    pass


@dataclass(frozen=True)
class MasscanPortResult:
    protocol: str
    port: int
    state: str


@dataclass(frozen=True)
class MasscanHostResult:
    ip: str
    ports: list[MasscanPortResult]


@dataclass(frozen=True)
class MasscanRunResult:
    command: list[str]
    targets: list[str]
    hosts: list[MasscanHostResult]
    raw_output: str


def is_masscan_available(masscan_bin: str = "masscan") -> bool:
    return shutil.which(masscan_bin) is not None


def run_masscan(
    targets: Sequence[str],
    *,
    masscan_bin: str = "masscan",
    ports: str = "1-65535",
    rate: int = 10000,
    wait: int = 5,
    retries: int = 2,
) -> MasscanRunResult:
    normalized = sorted({t.strip() for t in targets if t.strip()})
    if not normalized:
        return MasscanRunResult(command=[], targets=[], hosts=[], raw_output="")

    command = [
        masscan_bin,
        "-p", ports,
        "--rate", str(rate),
        "--wait", str(wait),
        "--retries", str(retries),
        "-oX", "-",
    ] + normalized

    completed = run_text_capture(command)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "masscan failed"
        raise MasscanError(f"masscan exited {completed.returncode}: {detail}")

    raw = completed.stdout
    return MasscanRunResult(
        command=command,
        targets=normalized,
        hosts=_parse_xml(raw) if raw.strip() else [],
        raw_output=raw,
    )


def open_ports_by_host(result: MasscanRunResult) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for host in result.hosts:
        ports = sorted({p.port for p in host.ports if p.state == "open"})
        if ports:
            out[host.ip] = ports
    return out


def _parse_xml(raw: str) -> list[MasscanHostResult]:
    # masscan may emit a comment line before XML; strip it
    lines = raw.splitlines()
    xml_lines = [ln for ln in lines if not ln.startswith("#")]
    xml_text = "\n".join(xml_lines)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    hosts: list[MasscanHostResult] = []
    for host_el in root.findall("host"):
        ip: str | None = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr_el.get("addr")
                break
        if not ip:
            continue
        ports: list[MasscanPortResult] = []
        for port_el in host_el.findall("./ports/port"):
            proto = port_el.get("protocol") or "tcp"
            portid = port_el.get("portid")
            if not portid or not portid.isdigit():
                continue
            state_el = port_el.find("state")
            state = (state_el.get("state") if state_el is not None else None) or "open"
            ports.append(MasscanPortResult(protocol=proto, port=int(portid), state=state))
        if ports:
            hosts.append(MasscanHostResult(ip=ip, ports=ports))
    return hosts
