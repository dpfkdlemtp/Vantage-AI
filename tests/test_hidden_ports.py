from __future__ import annotations

from scanner.ai.analyst import heuristic_triage
from scanner.runner import _candidate_http_probe_target_from_port_scan_evidence


def _port_ev(port: int, *, service: str = "", host: str = "10.0.0.5") -> dict:
    return {"state": "open", "host": host, "port": port, "service": service}


def test_non_standard_open_port_skipped_without_flag() -> None:
    # A hidden HTTP service on :10002 with no nmap service label is NOT probed by default.
    assert _candidate_http_probe_target_from_port_scan_evidence(_port_ev(10002)) is None


def test_non_standard_open_port_probed_with_flag() -> None:
    # With http_probe_all_open_ports, the hidden port becomes an http_probe target.
    url = _candidate_http_probe_target_from_port_scan_evidence(
        _port_ev(10002), probe_all_open_ports=True
    )
    assert url == "http://10.0.0.5:10002/"


def test_nmap_http_label_recognized_even_without_flag() -> None:
    # When nmap -sV labels the service http, the hidden port is recognized regardless.
    url = _candidate_http_probe_target_from_port_scan_evidence(_port_ev(10002, service="http"))
    assert url == "http://10.0.0.5:10002/"


def test_closed_port_never_probed_even_with_flag() -> None:
    ev = {"state": "closed", "host": "10.0.0.5", "port": 10002}
    assert _candidate_http_probe_target_from_port_scan_evidence(ev, probe_all_open_ports=True) is None


def test_heuristic_flags_non_standard_port_for_http_probe() -> None:
    evidence = {
        "subdomains": [],
        "live_hosts": [],
        "open_ports": [{"host": "10.0.0.5", "port": 10002, "service": ""}],
        "dir_findings": [],
        "candidate_cves": [],
    }
    result = heuristic_triage(evidence)
    risk = next(r for r in result.targets if r.target == "10.0.0.5")
    assert risk.risk_score >= 0.6
    assert any("non_standard_port:10002" in s for s in risk.signals)
    assert "http_probe" in risk.suggested_modules
