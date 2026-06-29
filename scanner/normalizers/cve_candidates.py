from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Literal

from scanner.models import CveMatchedField, Finding


@dataclass(frozen=True)
class CveSignature:
    cve_id: str
    aliases: tuple[str, ...]
    versions: tuple[str, ...]
    match_mode: Literal["exact", "prefix"]
    confidence_by_field: dict[CveMatchedField, float]


@dataclass(frozen=True)
class EvidenceObservation:
    matched_field: CveMatchedField
    matched_value: str


SIGNATURES: tuple[CveSignature, ...] = (
    CveSignature(
        cve_id="CVE-2021-41773",
        aliases=("apache httpd", "apache"),
        versions=("2.4.49",),
        match_mode="exact",
        confidence_by_field={
            "product_version": 0.98,
            "title": 0.92,
            "technology": 0.9,
            "webserver": 0.88,
            "product": 0.55,
        },
    ),
    CveSignature(
        cve_id="CVE-2021-42013",
        aliases=("apache httpd", "apache"),
        versions=("2.4.50",),
        match_mode="exact",
        confidence_by_field={
            "product_version": 0.98,
            "title": 0.92,
            "technology": 0.9,
            "webserver": 0.88,
            "product": 0.55,
        },
    ),
    CveSignature(
        cve_id="CVE-2016-0777",
        aliases=("openssh",),
        versions=("7.2",),
        match_mode="prefix",
        confidence_by_field={
            "product_version": 0.83,
            "title": 0.78,
            "technology": 0.76,
            "product": 0.5,
            "service": 0.4,
        },
    ),
)


def match_cve_candidates(
    findings: list[Finding],
    *,
    run_id: str,
    task_id: str,
    min_confidence: float = 0.7,
    observed_at: datetime | None = None,
) -> list[Finding]:
    created_at = observed_at or datetime.now(UTC)
    candidates: list[Finding] = []
    seen_candidates: set[tuple[str, str, str]] = set()

    for finding in findings:
        for observation in _extract_observations(finding):
            normalized_value = observation.matched_value.lower()
            for signature in SIGNATURES:
                if observation.matched_field not in signature.confidence_by_field:
                    continue
                if not _alias_matches(normalized_value, signature.aliases):
                    continue
                if not _version_matches(
                    normalized_value,
                    signature.versions,
                    signature.match_mode,
                ):
                    continue
                confidence = signature.confidence_by_field[observation.matched_field]
                if confidence < min_confidence:
                    continue
                dedupe_key = (finding.target, finding.finding_id, signature.cve_id)
                if dedupe_key in seen_candidates:
                    continue
                seen_candidates.add(dedupe_key)
                candidates.append(
                    Finding(
                        finding_id=_build_candidate_id(
                            run_id,
                            task_id,
                            finding.finding_id,
                            signature.cve_id,
                            observation.matched_field,
                        ),
                        run_id=run_id,
                        task_id=task_id,
                        module="cve_match",
                        target=finding.target,
                        status="candidate",
                        summary=(
                            f"Candidate {signature.cve_id} matched on {finding.target} "
                            f"via {observation.matched_field} '{observation.matched_value}'"
                        ),
                        evidence_json={
                            "source_tool": "cve_matcher",
                            "cve_id": signature.cve_id,
                            "matched_value": observation.matched_value,
                            "matched_field": observation.matched_field,
                            "confidence": confidence,
                            "candidate_only": True,
                            "evidence_source": {
                                "finding_id": finding.finding_id,
                                "module": finding.module,
                                "target": finding.target,
                                "summary": finding.summary,
                            },
                        },
                        tags=["cve", "candidate", finding.module],
                        created_at=created_at,
                    )
                )

    return candidates


def _extract_observations(finding: Finding) -> list[EvidenceObservation]:
    evidence = finding.evidence_json if isinstance(finding.evidence_json, dict) else {}
    observations: list[EvidenceObservation] = []
    seen_values: set[tuple[CveMatchedField, str]] = set()

    def add(field: CveMatchedField, value: object) -> None:
        if not isinstance(value, str):
            return
        normalized = value.strip()
        if not normalized:
            return
        key = (field, normalized)
        if key in seen_values:
            return
        seen_values.add(key)
        observations.append(EvidenceObservation(matched_field=field, matched_value=normalized))

    add("title", evidence.get("title"))
    add("webserver", evidence.get("webserver"))
    add("service", evidence.get("service"))
    add("product", evidence.get("product"))
    add("version", evidence.get("version"))

    technologies = evidence.get("technologies")
    if isinstance(technologies, list):
        for technology in technologies:
            add("technology", technology)

    product = evidence.get("product")
    version = evidence.get("version")
    if isinstance(product, str) and product.strip() and isinstance(version, str) and version.strip():
        add("product_version", f"{product.strip()} {version.strip()}")

    return observations


def _alias_matches(normalized_value: str, aliases: tuple[str, ...]) -> bool:
    for alias in aliases:
        if not alias:
            continue
        pattern = re.compile(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])")
        if pattern.search(normalized_value):
            return True
    return False


def _version_matches(
    normalized_value: str,
    versions: tuple[str, ...],
    match_mode: Literal["exact", "prefix"],
) -> bool:
    for version in versions:
        if match_mode == "exact" and _contains_exact_version(normalized_value, version):
            return True
        if match_mode == "prefix" and _contains_version_prefix(normalized_value, version):
            return True
    return False


def _contains_exact_version(normalized_value: str, version: str) -> bool:
    pattern = re.compile(rf"(?<![0-9]){re.escape(version)}(?![0-9])")
    return bool(pattern.search(normalized_value))


def _contains_version_prefix(normalized_value: str, version: str) -> bool:
    pattern = re.compile(rf"(?<![0-9]){re.escape(version)}(?:[a-z0-9._-]*)")
    return bool(pattern.search(normalized_value))


def _build_candidate_id(
    run_id: str,
    task_id: str,
    source_finding_id: str,
    cve_id: str,
    matched_field: CveMatchedField,
) -> str:
    digest = sha256(
        f"{run_id}:{task_id}:{source_finding_id}:{cve_id}:{matched_field}".encode("utf-8")
    ).hexdigest()
    return f"finding-{digest[:24]}"
