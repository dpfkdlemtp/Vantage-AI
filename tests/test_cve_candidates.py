from __future__ import annotations

from datetime import UTC, datetime

from scanner.models import Finding
from scanner.normalizers.cve_candidates import match_cve_candidates


def test_match_cve_candidates_exact_matches_from_persisted_evidence() -> None:
    observed_at = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    findings = [
        Finding(
            finding_id="finding-portscan-1",
            run_id="run-cve",
            module="port_scan",
            target="api.example.com:tcp/80",
            summary="Observed tcp/80 open on api.example.com [http]",
            evidence_json={
                "product": "Apache httpd",
                "version": "2.4.49",
                "service": "http",
            },
            tags=["portscan", "open"],
            created_at=observed_at,
        ),
        Finding(
            finding_id="finding-httpx-1",
            run_id="run-cve",
            module="http_probe",
            target="https://blog.example.com/",
            summary="Observed live host blog.example.com [200]",
            evidence_json={
                "title": "Apache httpd 2.4.50",
                "technologies": ["Apache httpd 2.4.50"],
            },
            tags=["httpx", "alive", "host"],
            created_at=observed_at,
        ),
    ]

    candidates = match_cve_candidates(
        findings,
        run_id="run-cve",
        task_id="task-cve",
        observed_at=observed_at,
    )

    assert [candidate.evidence_json["cve_id"] for candidate in candidates] == [
        "CVE-2021-41773",
        "CVE-2021-42013",
    ]
    assert candidates[0].status == "candidate"
    assert candidates[0].evidence_json["matched_field"] == "product_version"
    assert candidates[0].evidence_json["matched_value"] == "Apache httpd 2.4.49"
    assert candidates[0].evidence_json["candidate_only"] is True
    assert candidates[0].evidence_json["evidence_source"]["finding_id"] == "finding-portscan-1"
    assert candidates[1].evidence_json["matched_field"] == "title"
    assert candidates[1].created_at == observed_at


def test_match_cve_candidates_filters_low_confidence_and_no_match() -> None:
    observed_at = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    findings = [
        Finding(
            finding_id="finding-portscan-low",
            run_id="run-cve",
            module="port_scan",
            target="api.example.com:tcp/22",
            summary="Observed tcp/22 open on api.example.com [ssh]",
            evidence_json={
                "product": "OpenSSH",
                "version": "7.2p2",
                "service": "ssh",
            },
            tags=["portscan", "open"],
            created_at=observed_at,
        ),
        Finding(
            finding_id="finding-httpx-none",
            run_id="run-cve",
            module="http_probe",
            target="https://www.example.com/",
            summary="Observed live host www.example.com [200]",
            evidence_json={"title": "Welcome to nginx"},
            tags=["httpx", "alive", "host"],
            created_at=observed_at,
        ),
        Finding(
            finding_id="finding-portscan-no-version",
            run_id="run-cve",
            module="port_scan",
            target="blog.example.com:tcp/80",
            summary="Observed tcp/80 open on blog.example.com [http]",
            evidence_json={"product": "Apache httpd", "service": "http"},
            tags=["portscan", "open"],
            created_at=observed_at,
        ),
    ]

    high_threshold_candidates = match_cve_candidates(
        findings,
        run_id="run-cve",
        task_id="task-cve",
        min_confidence=0.9,
        observed_at=observed_at,
    )

    default_threshold_candidates = match_cve_candidates(
        findings,
        run_id="run-cve",
        task_id="task-cve",
        observed_at=observed_at,
    )

    assert high_threshold_candidates == []
    assert [candidate.evidence_json["cve_id"] for candidate in default_threshold_candidates] == [
        "CVE-2016-0777"
    ]
