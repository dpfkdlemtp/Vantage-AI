from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from scanner.adapters.ffuf_runner import FfufResultEntry
from scanner.config import DEFAULT_FFUF_WORDLIST
from scanner.wordlist_recommendations import getRecommendedWordlists

CALIBRATION_SAMPLE_COUNT = 20
DOMINANT_LENGTH_RATIO = 0.9
# Status codes safe to treat as a wildcard/catch-all when canary paths return
# them near-uniformly. Restricted to redirects: a per-path redirect wildcard
# (e.g. every path 301s to its own Location, so bodies differ and the length
# filter never stabilizes) is rarely a real finding. 200/401/403 are excluded
# on purpose -- filtering those would hide legitimate content/protected dirs,
# so an all-200 (or all-403) baseline stays confirmation-required.
CATCH_ALL_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
WINDOWS_HTTPX_INDICATORS: tuple[str, ...] = ("iis", "asp.net", "microsoft-httpapi")
WINDOWS_PORTSCAN_INDICATORS: tuple[str, ...] = (
    "iis",
    "microsoft",
    "windows",
    "httpapi",
    "microsoft-ds",
    "msrpc",
    "netbios",
)


class DirscanConfirmationRequired(RuntimeError):
    def __init__(self, message: str, *, cursor_json: dict[str, Any]) -> None:
        super().__init__(message)
        self.cursor_json = cursor_json


@dataclass(frozen=True)
class DirscanCalibrationDecision:
    filter_sizes: list[int]
    details: dict[str, Any]
    filter_codes: list[int] = field(default_factory=list)


def dirscan_note_key(item: dict[str, Any]) -> tuple[str, str]:
    base_url = str(item.get("base_url") or "")
    effective_wordlist_path = str(item.get("effective_wordlist_path") or "")
    return (base_url, effective_wordlist_path)


def first_existing_wordlist(candidates: list[str]) -> Path | None:
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return path
    return None


def is_user_defined_wordlist(run: Any, source_wordlist_path: Path) -> bool:
    try:
        configured = Path(source_wordlist_path).resolve()
    except Exception:
        configured = Path(source_wordlist_path)
    output_root = Path(getattr(run.config, "output_root", Path.cwd()))
    workspace_root = output_root.parent.parent if len(output_root.parts) >= 2 else Path.cwd()
    default_path = (workspace_root / DEFAULT_FFUF_WORDLIST).resolve()
    return configured != default_path


def casefold_wordlist_entries(source_wordlist_path: Path) -> list[str]:
    entries: list[str] = []
    seen_entries: set[str] = set()
    for line in source_wordlist_path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry:
            continue
        casefolded_entry = entry.casefold()
        if casefolded_entry in seen_entries:
            continue
        seen_entries.add(casefolded_entry)
        entries.append(casefolded_entry)
    return entries


def ensure_case_insensitive_wordlist(run: Any, source_wordlist_path: Path) -> Path:
    derived_dir = run.config.output_root / "derived-wordlists"
    derived_dir.mkdir(parents=True, exist_ok=True)
    suffix = source_wordlist_path.suffix or ".txt"
    token = sha256(str(source_wordlist_path.resolve()).encode("utf-8")).hexdigest()[:12]
    derived_wordlist_path = derived_dir / f"{source_wordlist_path.stem}-{token}-casefold{suffix}"
    casefolded_entries = casefold_wordlist_entries(source_wordlist_path)
    derived_wordlist_path.write_text(
        "\n".join(casefolded_entries) + ("\n" if casefolded_entries else ""),
        encoding="utf-8",
    )
    return derived_wordlist_path


def matches_http_probe_host(evidence: dict[str, Any], host: str) -> bool:
    evidence_host = str(evidence.get("host") or "").casefold()
    evidence_ip = str(evidence.get("ip") or "").casefold()
    url_host = urlsplit(str(evidence.get("url") or "")).hostname
    normalized_host = host.casefold()
    return normalized_host in {evidence_host, evidence_ip, (url_host or "").casefold()}


def matches_port_scan_host(evidence: dict[str, Any], host: str) -> bool:
    evidence_host = str(evidence.get("host") or "").casefold()
    evidence_ip = str(evidence.get("ip") or "").casefold()
    normalized_host = host.casefold()
    return normalized_host in {evidence_host, evidence_ip}


def contains_indicator(values: list[str], indicators: tuple[str, ...]) -> bool:
    for value in values:
        normalized_value = value.casefold()
        if any(indicator in normalized_value for indicator in indicators):
            return True
    return False


def build_canary_paths(task_id: str, base_url: str) -> list[str]:
    return [
        f"__scanner_canary__{sha256(f'{task_id}:{base_url}:{index}'.encode('utf-8')).hexdigest()[:24]}"
        for index in range(CALIBRATION_SAMPLE_COUNT)
    ]


def dominant_length(length_counts: Counter[int]) -> tuple[int | None, int]:
    if not length_counts:
        return None, 0
    dominant, dominant_count = length_counts.most_common(1)[0]
    return dominant, dominant_count


def login_gate_fingerprint(match: FfufResultEntry) -> tuple[int | None, int | None, int | None, int | None, str, str]:
    return (
        match.status_code,
        match.length,
        match.words,
        match.lines,
        match.redirect_target or "",
        match.content_type or "",
    )


def estimate_ffuf_total_count(wordlist_path: Path, extensions: list[str]) -> int:
    word_count = sum(1 for line in wordlist_path.read_text(encoding="utf-8").splitlines() if line.strip())
    if word_count <= 0:
        return 0
    extension_multiplier = max(1, len(extensions) + 1) if extensions else 1
    return word_count * extension_multiplier


def is_likely_windows_target(connection: Any, run_id: str, base_url: str) -> bool:
    host = urlsplit(base_url).hostname
    if not host:
        return False

    rows = connection.execute(
        """
        SELECT module, evidence_json
        FROM findings
        WHERE run_id = ?
          AND module IN ('http_probe', 'port_scan')
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id,),
    ).fetchall()
    for row in rows:
        evidence = json.loads(row["evidence_json"])
        if not isinstance(evidence, dict):
            continue
        module = str(row["module"])
        if module == "http_probe" and matches_http_probe_host(evidence, host):
            values = [
                str(evidence.get("webserver") or ""),
                str(evidence.get("title") or ""),
                *[
                    item
                    for item in evidence.get("technologies", [])
                    if isinstance(item, str)
                ],
            ]
            if contains_indicator(values, WINDOWS_HTTPX_INDICATORS):
                return True
        if module == "port_scan" and matches_port_scan_host(evidence, host):
            values = [
                str(evidence.get("service") or ""),
                str(evidence.get("product") or ""),
                str(evidence.get("version") or ""),
            ]
            if contains_indicator(values, WINDOWS_PORTSCAN_INDICATORS):
                return True
    return False


def get_portscan_service_text(connection: Any, run_id: str, host: str) -> str:
    """Best-effort nmap service / product / version text for the host (for extension hints)."""
    if not host:
        return ""
    parts: list[str] = []
    rows = connection.execute(
        """
        SELECT evidence_json
        FROM findings
        WHERE run_id = ?
          AND module = 'port_scan'
        ORDER BY created_at ASC
        """,
        (run_id,),
    ).fetchall()
    for row in rows:
        evidence = json.loads(row["evidence_json"])
        if not isinstance(evidence, dict):
            continue
        if not matches_port_scan_host(evidence, host):
            continue
        for key in ("service", "product", "version", "extrainfo"):
            val = str(evidence.get(key) or "").strip()
            if val and val not in parts:
                parts.append(val)
    return " ".join(parts)


def get_target_technologies(connection: Any, run_id: str, base_url: str) -> list[str]:
    host = urlsplit(base_url).hostname
    if not host:
        return []

    rows = connection.execute(
        """
        SELECT evidence_json
        FROM findings
        WHERE run_id = ?
          AND module = 'http_probe'
        ORDER BY created_at ASC
        """,
        (run_id,),
    ).fetchall()

    technologies: list[str] = []
    seen: set[str] = set()
    for row in rows:
        evidence = json.loads(row["evidence_json"])
        if not isinstance(evidence, dict):
            continue
        if matches_http_probe_host(evidence, host):
            webserver = str(evidence.get("webserver") or "").strip()
            if webserver and webserver not in seen:
                seen.add(webserver)
                technologies.append(webserver)
            for tech in evidence.get("technologies", []):
                if isinstance(tech, str) and tech.strip() and tech not in seen:
                    seen.add(tech)
                    technologies.append(tech)
    return technologies


def get_dirscan_auth_detection(connection: Any, run_id: str, base_url: str) -> dict[str, Any] | None:
    host = urlsplit(base_url).hostname
    if not host:
        return None
    rows = connection.execute(
        """
        SELECT evidence_json
        FROM findings
        WHERE run_id = ?
          AND module = 'http_probe'
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id,),
    ).fetchall()
    best_review: dict[str, Any] | None = None
    for row in rows:
        evidence = json.loads(row["evidence_json"])
        if not isinstance(evidence, dict) or not matches_http_probe_host(evidence, host):
            continue
        auth_detection = evidence.get("auth_detection")
        if not isinstance(auth_detection, dict):
            continue
        if auth_detection.get("likely_auth_required"):
            return auth_detection
        if auth_detection.get("auth_state") == "review":
            best_review = auth_detection
    return best_review


def resolve_dirscan_wordlist(
    connection: Any,
    run_id: str,
    run: Any,
    base_url: str,
    source_wordlist_path: Path,
    *,
    technologies: list[str] | None = None,
    auto_recommendation_enabled: bool = True,
) -> tuple[Path, dict[str, Any]]:
    user_wordlist = is_user_defined_wordlist(run, source_wordlist_path)
    auto_candidates = getRecommendedWordlists(technologies or []) if auto_recommendation_enabled else []
    auto_selected = first_existing_wordlist(auto_candidates)
    chosen_wordlist_path = source_wordlist_path if user_wordlist or auto_selected is None else auto_selected

    if not is_likely_windows_target(connection, run_id, base_url):
        return chosen_wordlist_path, {
            "effective_wordlist_path": str(chosen_wordlist_path),
            "source_wordlist_path": str(source_wordlist_path),
            "case_insensitive_wordlist": False,
            "user_selected_wordlist": user_wordlist,
            "recommended_wordlists": auto_candidates,
            "using_recommended_wordlist": bool((not user_wordlist) and auto_selected),
        }

    derived_wordlist_path = ensure_case_insensitive_wordlist(run, chosen_wordlist_path)
    return derived_wordlist_path, {
        "effective_wordlist_path": str(derived_wordlist_path),
        "source_wordlist_path": str(source_wordlist_path),
        "case_insensitive_wordlist": True,
        "user_selected_wordlist": user_wordlist,
        "recommended_wordlists": auto_candidates,
        "using_recommended_wordlist": bool((not user_wordlist) and auto_selected),
    }


def derive_calibration_decision(
    base_url: str,
    canary_paths: list[str],
    matches: list[FfufResultEntry],
) -> DirscanCalibrationDecision:
    lengths = [match.length for match in matches if isinstance(match.length, int)]
    status_codes = [match.status_code for match in matches if isinstance(match.status_code, int)]
    length_counts = Counter(lengths)
    status_counts = Counter(status_codes)
    dominant, dominant_count = dominant_length(length_counts)
    dominant_ratio = dominant_count / len(lengths) if lengths else 0.0
    dominant_status, dominant_status_count = (
        status_counts.most_common(1)[0] if status_counts else (None, 0)
    )
    dominant_status_ratio = (
        dominant_status_count / len(status_codes) if status_codes else 0.0
    )
    details = {
        "base_url": base_url,
        "sample_count": len(canary_paths),
        "match_count": len(matches),
        "length_counts": [
            {"length": length, "count": count}
            for length, count in sorted(length_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        "status_counts": [
            {"status_code": status_code, "count": count}
            for status_code, count in sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        "suggested_filter_sizes": [dominant] if dominant is not None else [],
        "suggested_filter_codes": [dominant_status] if dominant_status is not None else [],
    }
    if not lengths:
        return DirscanCalibrationDecision(
            filter_sizes=[],
            details={
                **details,
                "decision": "no_filter",
                "reason": "no_soft_response_matches",
            },
        )

    repeated_non_dominant = [
        count
        for length, count in length_counts.items()
        if dominant is not None and length != dominant and count > 1
    ]
    dominant_status_counts = Counter(
        match.status_code
        for match in matches
        if match.length == dominant and isinstance(match.status_code, int)
    )
    stable_soft_response = (
        dominant is not None
        and dominant_ratio >= DOMINANT_LENGTH_RATIO
        and not repeated_non_dominant
        and len(dominant_status_counts) == 1
    )
    if stable_soft_response:
        assert dominant is not None
        return DirscanCalibrationDecision(
            filter_sizes=[dominant],
            details={
                **details,
                "decision": "auto_filter",
                "reason": "stable_soft_response_length",
                "dominant_length": dominant,
                "dominant_length_count": dominant_count,
                "dominant_ratio": round(dominant_ratio, 3),
            },
        )

    # Status-code catch-all (e.g. wildcard 301 redirects whose Location/body
    # differs per path, so the length filter above never stabilizes). Canary
    # paths are guaranteed non-existent, so a near-uniform status code across
    # them means the server answers everything the same way -> filter that code.
    status_catch_all = (
        dominant_status is not None
        and dominant_status in CATCH_ALL_STATUS_CODES
        and dominant_status_ratio >= DOMINANT_LENGTH_RATIO
    )
    if status_catch_all:
        assert dominant_status is not None
        return DirscanCalibrationDecision(
            filter_sizes=[],
            filter_codes=[dominant_status],
            details={
                **details,
                "decision": "auto_filter",
                "reason": "stable_soft_response_status",
                "dominant_status_code": dominant_status,
                "dominant_status_count": dominant_status_count,
                "dominant_status_ratio": round(dominant_status_ratio, 3),
            },
        )

    raise DirscanConfirmationRequired(
        (
            f"Ambiguous ffuf soft-response baseline for {base_url}; "
            "confirmation required before applying an automatic -fs filter"
        ),
        cursor_json={
            "stage": "ffuf_confirmation_required",
            **details,
            "decision": "confirmation_required",
            "reason": "ambiguous_soft_response_baseline",
            "dominant_length": dominant,
            "dominant_length_count": dominant_count,
            "dominant_ratio": round(dominant_ratio, 3),
        },
    )
