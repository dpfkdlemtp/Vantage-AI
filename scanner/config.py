from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence, cast
from urllib.parse import urlsplit

from scanner.models import ScanConfig, ScanPhase, SpeedProfile, ToolName

DEFAULT_MODULES: tuple[ScanPhase, ...] = (
    "subdomain_enum",
    "http_probe",
    "domain_discovery",
    "dir_enum",
    "port_scan",
    "banner_probe",
)

MODULE_TO_TOOL: dict[ScanPhase, ToolName] = {
    "subdomain_enum": "securitytrails",
    "http_probe": "httpx",
    "domain_discovery": "orchestrator",
    "dir_enum": "ffuf",
    "port_scan": "nmap",
    "banner_probe": "orchestrator",
    "cve_match": "cve_matcher",
    "ai_triage": "ai_analyst",
}

# ai_triage is selectable and orders last, but is intentionally NOT in DEFAULT_MODULES:
# it only runs when explicitly requested (via --module ai_triage or a UI preset), so
# default runs keep their existing phase set and behavior.
SELECTABLE_MODULES: tuple[ScanPhase, ...] = (*DEFAULT_MODULES, "cve_match", "ai_triage")

TECH_EXTENSION_MAPPING: dict[str, list[str]] = {
    "php": [".php"],
    "asp.net": [".aspx", ".asp", ".ashx"],
    "iis": [".aspx", ".asp", ".ashx"],
    "java": [".jsp", ".jspx", ".do", ".action"],
    "spring": [".jsp", ".jspx", ".do", ".action"],
    "coldfusion": [".cfm", ".cfc"],
    "ruby": [".rb", ".erb"],
    "python": [".py"],
    "perl": [".pl", ".cgi"],
}
MAX_EXTENSIONS = 5
DIR_ENUM_MAX_WORKERS = 3
DEFAULT_FFUF_WORDLIST = Path("wordlists/test.txt")
BROWSER_HEADER_DEFAULTS: tuple[tuple[str, str], ...] = (
    ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Cache-Control", "no-cache"),
    ("Pragma", "no-cache"),
    ("Upgrade-Insecure-Requests", "1"),
)
AUTH_HEADER_KEYS = {"authorization", "cookie"}

VALID_PROFILES = {"safe", "balanced", "fast"}
TargetKind = Literal["ipv4", "localhost", "private_internal", "domain"]
UI_RUN_PRESETS: dict[str, dict[str, Any]] = {
    "quick": {
        "label": "Quick",
        "description": "Passive discovery plus live-host validation for a fast first pass.",
        "modules": ["subdomain_enum", "http_probe"],
        "profile": "safe",
        "defaults": {},
    },
    "web": {
        "label": "Web",
        "description": "Passive discovery, web probing, and directory triage.",
        "modules": ["subdomain_enum", "http_probe", "dir_enum"],
        "profile": "balanced",
        "defaults": {
            "ffuf_wordlist_path": str(DEFAULT_FFUF_WORDLIST),
            "ffuf_threads": 20,
        },
    },
    "full": {
        "label": "Full",
        "description": "Full passive discovery, web triage, port scanning (all 65535), and directory enumeration.",
        "modules": ["subdomain_enum", "http_probe", "dir_enum", "port_scan", "banner_probe"],
        "profile": "balanced",
        "defaults": {
            "ffuf_wordlist_path": str(DEFAULT_FFUF_WORDLIST),
            "nmap_ports": "1-65535",
            "ffuf_threads": 20,
        },
    },
    "ai": {
        "label": "AI-driven",
        "description": "Full recon plus an LLM analyst that risk-scores findings and autonomously enqueues deeper, scope-locked scans.",
        "modules": [
            "subdomain_enum",
            "http_probe",
            "dir_enum",
            "port_scan",
            "banner_probe",
            "ai_triage",
        ],
        "profile": "balanced",
        "defaults": {
            "ffuf_wordlist_path": str(DEFAULT_FFUF_WORDLIST),
            "nmap_ports": "1-65535",
            "ffuf_threads": 20,
            "ai_triage_enabled": True,
            "ai_autonomy": "act",
        },
    },
}


@dataclass(frozen=True)
class RunPaths:
    workspace: Path
    output_root: Path
    state_db_path: Path
    artifacts_dir: Path
    report_json_path: Path


def build_scan_config(
    target: str,
    run_id: str,
    *,
    profile: str,
    modules: Sequence[str] | None = None,
    workspace: Path | None = None,
    scan_mode: str = "balanced",
    any_line_is_domain: bool = False,
) -> ScanConfig:
    from scanner.scan_mode import normalize_scan_mode

    workspace_path = _resolve_workspace(workspace)
    run_paths = build_run_paths(run_id, workspace=workspace_path)
    selected_modules = plan_enabled_phases(target, modules, any_line_is_domain=any_line_is_domain)
    selected_profile = normalize_profile(profile)
    return ScanConfig(
        target=target,
        profile=selected_profile,
        scan_mode=normalize_scan_mode(scan_mode),
        enabled_phases=selected_modules,
        output_root=run_paths.output_root,
        state_db_path=run_paths.state_db_path,
        artifacts_dir=run_paths.artifacts_dir,
        report_json_path=run_paths.report_json_path,
        subfinder_bin="subfinder",
        assetfinder_bin="assetfinder",
        ffuf_wordlist_path=(workspace_path / DEFAULT_FFUF_WORDLIST).resolve(),
    )


def build_run_paths(run_id: str, *, workspace: Path | None = None) -> RunPaths:
    workspace_path = _resolve_workspace(workspace)
    output_root = workspace_path / "runs" / run_id
    return RunPaths(
        workspace=workspace_path,
        output_root=output_root,
        state_db_path=output_root / "state.db",
        artifacts_dir=output_root / "artifacts",
        report_json_path=workspace_path / "reports" / f"{run_id}.json",
    )


def resolve_state_db_path(run_id: str, *, workspace: Path | None = None) -> Path:
    return build_run_paths(run_id, workspace=workspace).state_db_path


def resolve_scope_controls_path(run_id: str, *, workspace: Path | None = None) -> Path:
    return build_run_paths(run_id, workspace=workspace).output_root / "scope.json"


def resolve_tool(module: ScanPhase) -> ToolName:
    return MODULE_TO_TOOL[module]


def classify_target(target: str) -> TargetKind:
    host = _extract_target_host(target)
    lowered = host.lower()
    if lowered == "localhost":
        return "localhost"
    parsed_network = _parse_ipv4_network(host)
    if parsed_network is not None:
        if (
            parsed_network.is_private
            or parsed_network.is_loopback
            or parsed_network.is_link_local
            or parsed_network.is_reserved
            or parsed_network.is_unspecified
        ):
            return "private_internal"
        return "ipv4"
    parsed_ip = _parse_ipv4(host)
    if parsed_ip is not None:
        if (
            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_reserved
            or parsed_ip.is_unspecified
        ):
            return "private_internal"
        return "ipv4"
    if _is_private_hostname(lowered):
        return "private_internal"
    return "domain"


def derive_extensions_from_tech(technologies: Sequence[str]) -> list[str]:
    extensions: list[str] = []
    seen: set[str] = set()
    for tech in technologies:
        lowered = tech.strip().lower()
        for known_tech, mapped_exts in TECH_EXTENSION_MAPPING.items():
            if known_tech in lowered:
                for ext in mapped_exts:
                    if ext not in seen:
                        seen.add(ext)
                        extensions.append(ext)
    return extensions[:MAX_EXTENSIONS]


def plan_enabled_phases(
    target: str,
    modules: Sequence[str] | None,
    *,
    any_line_is_domain: bool = False,
) -> list[ScanPhase]:
    selected_modules = normalize_modules(modules)
    if classify_target(target) == "domain" or any_line_is_domain:
        return selected_modules
    # Non-domain targets (IP / CIDR / private hostname): port_scan and
    # http_probe are mandatory prerequisites; subdomain_enum is dropped because
    # it requires a domain. The remaining optional modules follow a fixed
    # phase order (discovery -> banner -> dir) regardless of how the
    # user listed them, so phase ordering stays consistent.
    selected_set = set(selected_modules)
    planned: list[ScanPhase] = [cast(ScanPhase, "port_scan"), cast(ScanPhase, "http_probe")]
    for module in ("domain_discovery", "banner_probe", "dir_enum", "cve_match", "ai_triage"):
        typed_module = cast(ScanPhase, module)
        if typed_module in selected_set and typed_module not in planned:
            planned.append(typed_module)
    return planned


def normalize_modules(modules: Sequence[str] | None) -> list[ScanPhase]:
    if not modules:
        return list(DEFAULT_MODULES)

    selected = {_normalize_module_name(item) for raw in modules for item in raw.split(",") if item.strip()}
    if not selected:
        raise ValueError("at least one module must be selected")
    # Deterministic ordering: SELECTABLE_MODULES fixes the phase order (ai_triage last so it
    # can triage everything before it), then any remaining selected module is appended stably.
    ordered = [module for module in SELECTABLE_MODULES if module in selected]
    for module in sorted(selected):
        if module not in ordered:
            ordered.append(module)
    return ordered


def normalize_profile(profile: str) -> SpeedProfile:
    normalized = profile.strip().lower()
    if normalized not in VALID_PROFILES:
        values = ", ".join(sorted(VALID_PROFILES))
        raise ValueError(f"unsupported profile '{profile}'. expected one of: {values}")
    return cast(SpeedProfile, normalized)


def get_ui_run_presets() -> dict[str, dict[str, Any]]:
    return {
        key: {
            "label": value["label"],
            "description": value["description"],
            "modules": list(value["modules"]),
            "profile": value["profile"],
            "defaults": dict(value["defaults"]),
        }
        for key, value in UI_RUN_PRESETS.items()
    }


def normalize_bulk_target_lines(raw: str) -> list[str]:
    """Deduplicated target lines (domains, URLs, IPs, CIDR) for multi-target single-run input."""
    return parse_scope_entries(raw)


def classify_bulk_line(line: str) -> TargetKind:
    """Classify one line of a bulk target block (used to keep domain modules when primary is non-domain)."""
    s = (line or "").strip()
    if not s:
        return "domain"
    host = _extract_target_host(s)
    try:
        net = ipaddress.ip_network(host, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            return classify_target(str(net.network_address))
    except ValueError:
        pass
    return classify_target(host)


def subdomain_scope_for_line(line: str) -> str | None:
    """
    Hostname suitable for a subdomain_enum task scope, or None if the line is not a domain target.
    """
    s = (line or "").strip()
    if not s:
        return None
    host = _extract_target_host(s)
    try:
        net = ipaddress.ip_network(host, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            return None
    except ValueError:
        pass
    if classify_target(host) != "domain":
        return None
    return host.lower().rstrip(".")


def parse_scope_entries(value: str | Sequence[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = value.replace("\r", "\n").replace(",", "\n").split("\n")
    else:
        raw_items = [str(item) for item in value]
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_item in raw_items:
        item = raw_item.strip()
        if not item:
            continue
        lowered = item.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        normalized.append(item)
    return normalized


def parse_header_lines(value: str | Sequence[str] | None) -> dict[str, str]:
    if value is None:
        return {}
    raw_lines = value.splitlines() if isinstance(value, str) else [str(item) for item in value]
    headers: dict[str, str] = {}
    for raw_line in raw_lines:
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        name, raw_header_value = line.split(":", 1)
        header_name = name.strip()
        header_value = raw_header_value.strip()
        if not header_name or not header_value:
            continue
        headers[header_name] = header_value
    return headers


def build_web_headers(
    extra_headers: Mapping[str, str] | None = None,
    *,
    cookies: str | None = None,
    bearer_token: str | None = None,
    host_header: str | None = None,
    referer: str | None = None,
) -> dict[str, str]:
    headers = {name: value for name, value in BROWSER_HEADER_DEFAULTS}
    if extra_headers:
        for name, value in extra_headers.items():
            normalized_name = str(name).strip()
            normalized_value = str(value).strip()
            if not normalized_name or not normalized_value:
                continue
            headers[normalized_name] = normalized_value
    if cookies and cookies.strip():
        headers["Cookie"] = cookies.strip()
    if bearer_token and bearer_token.strip():
        headers["Authorization"] = f"Bearer {bearer_token.strip()}"
    if host_header and host_header.strip():
        headers["Host"] = host_header.strip()
    # Same-origin Referer. Some servers (e.g. Next.js _next/static asset routes)
    # reject requests lacking a Referer with empty/zero-length bodies. Only set
    # it when the caller hasn't already supplied one via extra_headers.
    if referer and referer.strip() and not any(name.strip().lower() == "referer" for name in headers):
        headers["Referer"] = referer.strip()
    return headers


def split_auth_header_fields(headers: Mapping[str, str] | None) -> dict[str, str]:
    if not headers:
        return {"cookies": "", "bearer_token": "", "host_header": "", "extra_headers_text": ""}
    extra_lines: list[str] = []
    cookies = ""
    bearer_token = ""
    host_header = ""
    for name, value in headers.items():
        lowered = name.strip().lower()
        if lowered == "cookie":
            cookies = value
        elif lowered == "authorization" and value.startswith("Bearer "):
            bearer_token = value.removeprefix("Bearer ").strip()
        elif lowered == "host":
            host_header = value
        elif (name, value) not in BROWSER_HEADER_DEFAULTS:
            extra_lines.append(f"{name}: {value}")
    return {
        "cookies": cookies,
        "bearer_token": bearer_token,
        "host_header": host_header,
        "extra_headers_text": "\n".join(sorted(extra_lines)),
    }


def detect_auth_from_probe(
    *,
    url: str,
    status_code: int | None,
    title: str | None,
    content_type: str | None,
) -> dict[str, Any]:
    signals: list[str] = []
    lowered_url = url.casefold()
    lowered_title = (title or "").casefold()
    lowered_content_type = (content_type or "").casefold()
    if status_code in {401, 403}:
        signals.append(f"http_{status_code}")
    if any(token in lowered_url for token in ("login", "signin", "auth", "sso")):
        signals.append("url_login_marker")
    if any(token in lowered_title for token in ("login", "sign in", "signin", "authentication", "unauthorized", "forbidden")):
        signals.append("title_login_marker")
    if lowered_content_type.startswith("text/html") and status_code in {401, 403}:
        signals.append("html_auth_gate")
    likely_auth_required = any(signal.startswith("http_") for signal in signals) or len(signals) >= 2
    auth_state = "public"
    if likely_auth_required:
        auth_state = "auth_required"
    elif signals:
        auth_state = "review"
    return {
        "auth_state": auth_state,
        "likely_auth_required": likely_auth_required,
        "signals": signals,
    }


def choose_dirscan_strategy(
    *,
    headers: Mapping[str, str],
    auth_detection: Mapping[str, Any] | None,
) -> str:
    lowered_header_names = {name.casefold() for name in headers}
    has_session_material = bool(lowered_header_names & AUTH_HEADER_KEYS)
    likely_auth_required = bool(auth_detection and auth_detection.get("likely_auth_required"))
    if has_session_material:
        return "session-aware"
    if likely_auth_required:
        return "auth-limited"
    if headers:
        return "browser-header"
    return "public"


def summarize_web_headers(headers: Mapping[str, str] | None) -> dict[str, Any]:
    normalized_headers = {str(name).strip(): str(value).strip() for name, value in (headers or {}).items() if str(name).strip() and str(value).strip()}
    lowered_names = {name.casefold() for name in normalized_headers}
    return {
        "header_names": sorted(normalized_headers),
        "has_cookie": "cookie" in lowered_names,
        "has_authorization": "authorization" in lowered_names,
        "has_host_override": "host" in lowered_names,
    }


def _normalize_module_name(value: str) -> ScanPhase:
    normalized = value.strip().lower()
    if normalized not in MODULE_TO_TOOL:
        values = ", ".join(DEFAULT_MODULES)
        raise ValueError(f"unsupported module '{value}'. expected one of: {values}")
    return cast(ScanPhase, normalized)


def _resolve_workspace(workspace: Path | None) -> Path:
    return (workspace or Path.cwd()).resolve()


def _extract_target_host(target: str) -> str:
    stripped = target.strip()
    if "://" in stripped:
        parsed = urlsplit(stripped)
        stripped = parsed.hostname or stripped
    if stripped.startswith("[") and "]" in stripped:
        stripped = stripped[1:stripped.index("]")]
    if ":" in stripped and stripped.count(":") == 1:
        host, port = stripped.rsplit(":", 1)
        if port.isdigit():
            stripped = host
    return stripped.strip().rstrip(".")


def _parse_ipv4(host: str) -> ipaddress.IPv4Address | None:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv4Address):
        return parsed
    return None


def _is_private_hostname(host: str) -> bool:
    if not host:
        return False
    private_suffixes = (
        ".local",
        ".localdomain",
        ".internal",
        ".intranet",
        ".lan",
        ".home",
        ".home.arpa",
        ".corp",
        ".internal.arpa",
    )
    return host.endswith(private_suffixes)


def _parse_ipv4_network(host: str) -> ipaddress.IPv4Network | None:
    try:
        parsed = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv4Network):
        return parsed
    return None


def _is_ipv4_cidr_target(target: str) -> bool:
    host = _extract_target_host(target)
    return "/" in host and _parse_ipv4_network(host) is not None
