from __future__ import annotations

import json
import re
import sqlite3
from typing import Any
from urllib.parse import urlsplit


def load_findings(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    sql = """
        SELECT finding_id, module, target, status, summary, evidence_json, tags_json, created_at
        FROM findings
        WHERE run_id = ?
        ORDER BY created_at ASC, finding_id ASC
    """
    params: tuple[Any, ...] = (run_id,)
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params = (run_id, limit, offset)
    rows = connection.execute(sql, params).fetchall()
    return [
        {
            "finding_id": row["finding_id"],
            "module": row["module"],
            "target": row["target"],
            "status": row["status"],
            "summary": row["summary"],
            "evidence": json.loads(row["evidence_json"]),
            "tags": json.loads(row["tags_json"]) if row["tags_json"] else [],
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def load_artifacts(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    sql = """
        SELECT artifact_id, module, tool, path, sha256, size_bytes, content_type, metadata_json, created_at
        FROM artifacts
        WHERE run_id = ?
        ORDER BY created_at ASC, artifact_id ASC
    """
    params: tuple[Any, ...] = (run_id,)
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params = (run_id, limit, offset)
    rows = connection.execute(sql, params).fetchall()
    return [
        {
            "artifact_id": row["artifact_id"],
            "module": row["module"],
            "tool": row["tool"],
            "path": row["path"],
            "sha256": row["sha256"],
            "size_bytes": row["size_bytes"],
            "content_type": row["content_type"],
            "metadata": json.loads(row["metadata_json"]) if row["metadata_json"] else {},
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def load_report_errors(connection: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT task_id, module, tool, state, last_error, updated_at
        FROM tasks
        WHERE run_id = ?
          AND last_error IS NOT NULL
        ORDER BY updated_at DESC, task_id ASC
        """,
        (run_id,),
    ).fetchall()
    return [
        {
            "task_id": row["task_id"],
            "module": row["module"],
            "tool": row["tool"],
            "state": row["state"],
            "last_error": row["last_error"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def build_report_sections(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    sections: dict[str, list[dict[str, Any]]] = {
        "subdomains": [],
        "http_probe_results": [],
        "domain_mappings": [],
        "directory_findings": [],
        "open_ports": [],
        "banner_findings": [],
        "candidate_cves": [],
    }
    for finding in findings:
        module = str(finding["module"])
        if module == "subdomain_enum":
            sections["subdomains"].append(finding)
        elif module == "http_probe":
            sections["http_probe_results"].append(finding)
        elif module == "domain_discovery":
            ev = finding.get("evidence")
            if isinstance(ev, dict) and str(ev.get("type") or "") == "domain_mapping":
                sections["domain_mappings"].append(finding)
        elif module == "dir_enum":
            sections["directory_findings"].append(finding)
        elif module == "port_scan":
            evidence = finding.get("evidence")
            tags = finding.get("tags")
            state = ""
            if isinstance(evidence, dict):
                state = str(evidence.get("state") or "").strip().lower()
            tag_values = [str(item).strip().lower() for item in tags] if isinstance(tags, list) else []
            if state == "open" or "open" in tag_values:
                sections["open_ports"].append(finding)
        elif module == "banner_probe":
            ev = finding.get("evidence")
            if isinstance(ev, dict) and str(ev.get("type") or "") == "banner":
                sections["banner_findings"].append(finding)
        elif module == "cve_match" or str(finding["status"]) == "candidate":
            sections["candidate_cves"].append(finding)
    for key, items in sections.items():
        sections[key] = sorted(items, key=report_item_sort_key)
    return sections


def build_host_groups(
    sections: dict[str, list[dict[str, Any]]],
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    host_map: dict[str, dict[str, Any]] = {}

    def ensure_group(host_key: str) -> dict[str, Any]:
        group = host_map.get(host_key)
        if group is not None:
            return group
        group = {
            "host": host_key,
            "alive": False,
            "ip_addresses": set(),
            "technologies": set(),
            "http_probe": [],
            "open_ports": [],
            "directory_findings": [],
            "domain_mappings": [],
            "banner_findings": [],
            "candidate_cves": [],
            "subdomains": [],
            "artifacts": [],
        }
        host_map[host_key] = group
        return group

    for item in sections.get("domain_mappings", []):
        ev = evidence_dict(item)
        host_key = str(ev.get("ip") or "").strip() or host_key_from_finding(item, default="unknown")
        ensure_group(host_key)["domain_mappings"].append(item)
    for item in sections.get("banner_findings", []):
        ev = evidence_dict(item)
        host_key = str(ev.get("host") or "").strip() or host_key_from_finding(item, default="unknown")
        ensure_group(host_key)["banner_findings"].append(item)
    for item in sections.get("http_probe_results", []):
        host_key = host_key_from_finding(item, default="unknown")
        group = ensure_group(host_key)
        evidence = evidence_dict(item)
        group["http_probe"].append(item)
        group["alive"] = True
        for technology in string_list(evidence.get("technologies")):
            group["technologies"].add(technology)
        ip_value = str(evidence.get("ip") or "").strip()
        if ip_value:
            group["ip_addresses"].add(ip_value)

    for item in sections.get("open_ports", []):
        host_key = host_key_from_finding(item, default="unknown")
        group = ensure_group(host_key)
        evidence = evidence_dict(item)
        group["open_ports"].append(item)
        ip_value = str(evidence.get("ip") or "").strip()
        if ip_value:
            group["ip_addresses"].add(ip_value)

    for item in sections.get("directory_findings", []):
        host_key = host_key_from_finding(item, default="unknown")
        ensure_group(host_key)["directory_findings"].append(item)

    for item in sections.get("candidate_cves", []):
        host_key = host_key_from_finding(item, default="unknown")
        ensure_group(host_key)["candidate_cves"].append(item)

    for item in sections.get("subdomains", []):
        evidence = evidence_dict(item)
        root_domain = normalize_host_key(evidence.get("root_domain"))
        host_key = root_domain or host_key_from_finding(item, default="unknown")
        ensure_group(host_key)["subdomains"].append(item)

    for artifact in artifacts:
        artifact_host = artifact_host_key(artifact)
        if artifact_host is None:
            continue
        ensure_group(artifact_host)["artifacts"].append(artifact)

    results: list[dict[str, Any]] = []
    for host_key in sorted(host_map):
        group = host_map[host_key]
        directory_findings = sorted(group["directory_findings"], key=report_item_sort_key)
        open_ports = sorted(group["open_ports"], key=report_item_sort_key)
        http_probe = sorted(group["http_probe"], key=report_item_sort_key)
        candidate_cves = sorted(group["candidate_cves"], key=report_item_sort_key)
        subdomains = sorted(group["subdomains"], key=report_item_sort_key)
        domain_mappings = sorted(group["domain_mappings"], key=report_item_sort_key)
        banner_findings = sorted(group["banner_findings"], key=report_item_sort_key)
        host_artifacts = sorted(group["artifacts"], key=artifact_sort_key)
        auth_required_count = sum(
            1
            for item in directory_findings
            if status_code(item) in {401, 403}
        )
        redirect_count = sum(
            1
            for item in directory_findings
            if status_code(item) in {301, 302, 307, 308}
        )
        representative_ports = [
            {
                "port": evidence_dict(item).get("port"),
                "protocol": evidence_dict(item).get("protocol"),
                "service": evidence_dict(item).get("service"),
                "product": evidence_dict(item).get("product"),
                "version": evidence_dict(item).get("version"),
                "summary": item.get("summary"),
            }
            for item in open_ports[:5]
        ]
        representative_paths = [
            {
                "target": item.get("target"),
                "summary": item.get("summary"),
                "status_code": status_code(item),
            }
            for item in directory_findings[:5]
        ]
        results.append(
            {
                "host": host_key,
                "alive": bool(group["alive"]),
                "ip_addresses": sorted(str(item) for item in group["ip_addresses"]),
                "technologies": sorted(str(item) for item in group["technologies"]),
                "open_ports_count": len(open_ports),
                "directory_findings_count": len(directory_findings),
                "candidate_cve_count": len(candidate_cves),
                "auth_required_path_count": auth_required_count,
                "redirecting_path_count": redirect_count,
                "representative_ports": representative_ports,
                "representative_paths": representative_paths,
                "http_probe": http_probe,
                "open_ports": open_ports,
                "directory_findings": directory_findings,
                "domain_mappings": domain_mappings,
                "banner_findings": banner_findings,
                "candidate_cves": candidate_cves,
                "subdomains": subdomains,
                "artifacts": host_artifacts,
            }
        )
    return results


def report_item_sort_key(item: dict[str, Any]) -> tuple[str, str, str]:
    target = str(item.get("target") or "")
    created_at = str(item.get("created_at") or "")
    finding_id = str(item.get("finding_id") or "")
    return (target, created_at, finding_id)


def artifact_sort_key(item: dict[str, Any]) -> tuple[str, str, str]:
    path = str(item.get("path") or "")
    created_at = str(item.get("created_at") or "")
    artifact_id = str(item.get("artifact_id") or "")
    return (path, created_at, artifact_id)


def evidence_dict(item: dict[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def status_code(item: dict[str, Any]) -> int | None:
    evidence = evidence_dict(item)
    raw_value = evidence.get("status_code")
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, str) and raw_value.isdigit():
        return int(raw_value)
    return None


def host_key_from_finding(item: dict[str, Any], *, default: str) -> str:
    evidence = evidence_dict(item)
    if str(evidence.get("type") or "") == "domain_mapping":
        for key in ("ip", "host", "hostname"):
            normalized = normalize_host_key(evidence.get(key))
            if normalized:
                return normalized
    candidates = [
        evidence.get("host"),
        evidence.get("hostname"),
        evidence.get("url"),
        item.get("target"),
    ]
    for candidate in candidates:
        normalized = normalize_host_key(candidate)
        if normalized:
            return normalized
    return default


def artifact_host_key(artifact: dict[str, Any]) -> str | None:
    metadata = artifact.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    candidates: list[object] = [metadata.get("base_url")]
    command = metadata.get("command")
    if isinstance(command, list):
        candidates.extend(artifact_command_candidates(command))
    for candidate in candidates:
        normalized = normalize_host_key(candidate)
        if normalized:
            return normalized
    return None


def artifact_command_candidates(command: list[Any]) -> list[str]:
    candidates: list[str] = []
    for item in command:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if not candidate or candidate.startswith("-"):
            continue
        lowered = candidate.lower()
        if "://" in candidate or lowered == "localhost" or ":" in candidate or "." in candidate:
            candidates.append(candidate)
    return candidates


def normalize_host_key(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw_value = value.strip()
    if not raw_value:
        return None
    parsed = urlsplit(raw_value if "://" in raw_value else f"http://{raw_value}")
    host = parsed.hostname or raw_value
    normalized = host.strip().lower().rstrip(".")
    if ":tcp/" in normalized:
        normalized = normalized.split(":tcp/", maxsplit=1)[0]
    return normalized or None


def diff_section(
    section_name: str,
    baseline_summary: dict[str, Any],
    current_summary: dict[str, Any],
) -> dict[str, Any]:
    baseline_items = dict_items(baseline_summary.get("sections", {}).get(section_name))
    current_items = dict_items(current_summary.get("sections", {}).get(section_name))
    baseline_map = {
        finding_diff_key(section_name, item): item
        for item in baseline_items
    }
    current_map = {
        finding_diff_key(section_name, item): item
        for item in current_items
    }
    baseline_keys = set(baseline_map)
    current_keys = set(current_map)
    added_keys = sorted(current_keys - baseline_keys)
    removed_keys = sorted(baseline_keys - current_keys)
    unchanged_keys = sorted(current_keys & baseline_keys)
    return {
        "added_count": len(added_keys),
        "removed_count": len(removed_keys),
        "unchanged_count": len(unchanged_keys),
        "added": [current_map[key] for key in added_keys],
        "removed": [baseline_map[key] for key in removed_keys],
        "unchanged": [current_map[key] for key in unchanged_keys],
    }


def finding_diff_key(section_name: str, item: dict[str, Any]) -> str:
    target = str(item.get("target") or "").strip().lower()
    evidence = item.get("evidence")
    evidence_dct = evidence if isinstance(evidence, dict) else {}
    if section_name == "candidate_cves":
        cve_id = str(evidence_dct.get("cve_id") or "").strip().upper()
        return f"{target}|{cve_id}"
    if section_name == "directory_findings":
        url = str(evidence_dct.get("url") or "").strip().lower()
        path = str(evidence_dct.get("path") or "").strip().lower()
        if not path:
            parsed_path = urlsplit(url or target).path.strip().lower()
            path = parsed_path or "/"
        status = str(evidence_dct.get("status_code") or "").strip()
        return f"{target}|{url}|{path}|{status}"
    if section_name == "open_ports":
        protocol, port = open_port_diff_parts(target, evidence_dct)
        service = str(evidence_dct.get("service") or "").strip().lower()
        product = str(evidence_dct.get("product") or "").strip().lower()
        version = str(evidence_dct.get("version") or "").strip().lower()
        return f"{target}|{protocol}|{port}|{service}|{product}|{version}"
    return target


def dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def open_port_diff_parts(target: str, evidence_dct: dict[str, Any]) -> tuple[str, str]:
    protocol = str(evidence_dct.get("protocol") or "").strip().lower()
    port = str(evidence_dct.get("port") or "").strip()
    if protocol and port:
        return (protocol, port)
    match = re.search(r":([a-z0-9_-]+)/(\d+)$", target)
    if match:
        return (protocol or match.group(1).lower(), port or match.group(2))
    return (protocol, port)
