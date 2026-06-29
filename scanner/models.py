from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

RunStatus: TypeAlias = Literal["pending", "running", "completed", "failed", "cancelled"]
TaskStatus: TypeAlias = Literal[
    "pending",
    "running",
    "completed",
    "failed",
    "skipped",
    "cancelled",
]
SpeedProfile: TypeAlias = Literal["safe", "balanced", "fast"]
ScanMode: TypeAlias = Literal["fast", "balanced", "deep"]
ProxyMode: TypeAlias = Literal["none", "http", "socks"]
ScanPhase: TypeAlias = Literal[
    "subdomain_enum",
    "http_probe",
    "domain_discovery",
    "dir_enum",
    "port_scan",
    "banner_probe",
    "cve_match",
    "access_control",
    "ai_triage",
]
PhaseName: TypeAlias = Literal[
    "subdomain_enum",
    "http_probe",
    "domain_discovery",
    "dir_enum",
    "port_scan",
    "banner_probe",
    "cve_match",
    "access_control",
    "ai_triage",
    "report",
]
ToolName: TypeAlias = Literal["securitytrails", "httpx", "ffuf", "nmap", "masscan", "naabu", "dnsx", "subzy", "gau", "playwright", "cve_matcher", "orchestrator", "ai_analyst"]
AiAutonomy: TypeAlias = Literal["off", "advise", "act"]
AiProvider: TypeAlias = Literal["anthropic", "openai"]
FindingStatus: TypeAlias = Literal["observed", "candidate"]
CveMatchedField: TypeAlias = Literal[
    "title",
    "technology",
    "webserver",
    "service",
    "product",
    "product_version",
    "version",
]
LogLevel: TypeAlias = Literal["info", "warning", "error"]


def _default_enabled_phases() -> list[ScanPhase]:
    return [
        "subdomain_enum",
        "http_probe",
        "domain_discovery",
        "dir_enum",
        "port_scan",
        "banner_probe",
    ]


def _default_http_schemes() -> list[Literal["http", "https"]]:
    return ["https", "http"]


def _default_probe_ports() -> list[int]:
    return [80, 443]


def _default_ffuf_match_status_codes() -> list[int]:
    return [200, 204, 301, 302, 307, 401, 403]


class BaseSchemaModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanConfig(BaseSchemaModel):
    target: str
    profile: SpeedProfile = "safe"
    scan_mode: ScanMode = "balanced"
    enabled_phases: list[ScanPhase] = Field(default_factory=_default_enabled_phases)
    resume: bool = True
    output_root: Path = Path("runs")
    state_db_path: Path = Path("runs/state.db")
    artifacts_dir: Path = Path("runs/artifacts")
    report_json_path: Path = Path("reports/report.json")
    report_html_path: Path | None = None
    securitytrails_api_key_env: str | None = "SECURITYTRAILS_API_KEY"
    subfinder_bin: str = "subfinder"
    assetfinder_bin: str = "assetfinder"
    httpx_bin: str = "httpx"
    ffuf_bin: str = "ffuf"
    nmap_bin: str = "nmap"
    max_concurrency: int = Field(default=4, ge=1)
    proxy_mode: ProxyMode = "none"
    proxy_url: str | None = None
    http_schemes: list[Literal["http", "https"]] = Field(default_factory=_default_http_schemes)
    probe_ports: list[int] = Field(default_factory=_default_probe_ports)
    httpx_timeout_seconds: int = Field(default=10, ge=1)
    httpx_threads: int = Field(default=10, ge=1)
    httpx_rate_limit_per_second: int | None = Field(default=None, ge=1)
    ffuf_wordlist_path: Path | None = None
    ffuf_extensions: list[str] = Field(default_factory=list)
    auto_recommendation_enabled: bool = True
    ffuf_threads: int = Field(default=20, ge=1)
    ffuf_concurrency: int = Field(default=40, ge=1, le=200)
    ffuf_parallel_enabled: bool = True
    ffuf_max_parallel_tasks: int = Field(default=3, ge=1, le=64)
    ffuf_replay_proxy: str | None = None
    ffuf_match_status_codes: list[int] = Field(default_factory=_default_ffuf_match_status_codes)
    nmap_ports: str = "1-65535"
    nmap_timing_template: Literal["T2", "T3", "T4"] = "T4"
    nmap_version_detection: bool = True
    masscan_bin: str = "masscan"
    masscan_enabled: bool = True
    masscan_rate: int = Field(default=10000, ge=100, le=10_000_000)
    masscan_retries: int = Field(default=2, ge=0, le=10)
    naabu_bin: str = "naabu"
    naabu_enabled: bool = True
    naabu_rate: int = Field(default=5000, ge=100, le=1_000_000)
    naabu_retries: int = Field(default=3, ge=0, le=10)
    naabu_scan_type: Literal["syn", "connect"] = "syn"
    portscan_ip_dedup_enabled: bool = True
    portscan_alive_filter_enabled: bool = True
    portscan_alive_ping_ports: str = "80,443,22,3389,8080,8443"
    portscan_dead_host_cache_enabled: bool = True
    portscan_adaptive_rate_enabled: bool = True
    nmap_nse_scripts_enabled: bool = True
    nmap_nse_scripts: str = "http-title,http-headers,ssl-cert,banner,http-server-header"
    nmap_host_timeout: str = ""
    subzy_bin: str = "subzy"
    subzy_enabled: bool = True
    gau_bin: str = "gau"
    gau_enabled: bool = True
    gau_max_urls_per_host: int = Field(default=500, ge=1, le=100_000)
    tls_san_discovery_enabled: bool = True
    udp_scan_enabled: bool = False
    udp_scan_ports: str = "53,67,68,69,123,137,138,161,500,514,520,623,1434,1900,4500,5353,11211"
    udp_scan_host_timeout_seconds: int = Field(default=120, ge=10, le=3600)
    js_render_enabled: bool = False
    js_render_timeout_seconds: int = Field(default=15, ge=3, le=120)
    js_render_max_hosts: int = Field(default=50, ge=1, le=10_000)
    spa_crawl_enabled: bool = False
    spa_crawl_max_depth: int = Field(default=2, ge=0, le=8)
    spa_crawl_max_pages: int = Field(default=50, ge=1, le=10_000)
    spa_crawl_same_origin_only: bool = True
    auth_login_enabled: bool = False
    auth_login_url: str = ""
    auth_username: str = ""
    auth_password: str = ""
    auth_username_field_hints: str = "username,email,user,login,userid,id"
    auth_password_field_hints: str = "password,passwd,pwd,pass"
    auth_login_success_keyword: str = ""
    dnsx_bin: str = "dnsx"
    subdomain_bruteforce_enabled: bool = True
    cve_matching_enabled: bool = True
    cve_min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    access_control_test_enabled: bool = True
    access_control_max_endpoints: int = Field(default=50, ge=1, le=1000)
    access_control_request_timeout_seconds: int = Field(default=8, ge=2, le=60)
    extra_headers: dict[str, str] = Field(default_factory=dict)
    dir_recursive_enabled: bool = False
    dir_recursive_max_depth: int = Field(default=1, ge=0, le=32)
    dir_recursive_max_paths_per_host: int = Field(default=100, ge=1, le=1_000_000)
    dir_recursive_same_host_only: bool = True
    cidr_split_enabled: bool = True
    cidr_split_max_hosts_per_chunk: int = Field(default=32, ge=1, le=256)
    cidr_split_target_interval_minutes: int = Field(default=10, ge=1, le=1440)
    cidr_split_adaptive_enabled: bool = True
    cidr_resume_enabled: bool = True
    cidr_split_min_prefix: int | None = Field(default=None, ge=0, le=32)
    cidr_split_strategy: Literal["host_count", "time_estimate"] = "host_count"
    # --- LLM-in-the-loop triage (ai_triage phase) ---
    # When the ai_triage phase is enabled, an LLM analyst scores observed hosts/subdomains
    # by risk and (in "act" mode) autonomously enqueues deeper, scope-locked safe scans.
    # Degrades gracefully to a deterministic heuristic when no API key is configured.
    ai_triage_enabled: bool = True
    ai_autonomy: AiAutonomy = "act"
    ai_provider: AiProvider = "anthropic"
    ai_model: str = ""
    ai_api_key_env: str = "ANTHROPIC_API_KEY"
    ai_min_risk_to_act: float = Field(default=0.6, ge=0.0, le=1.0)
    ai_max_followups: int = Field(default=8, ge=0, le=200)
    ai_max_iterations: int = Field(default=3, ge=1, le=10)
    ai_request_timeout_seconds: int = Field(default=60, ge=1, le=600)


class ArtifactRef(BaseSchemaModel):
    artifact_id: str
    run_id: str
    task_id: str | None = None
    phase_name: PhaseName
    source_tool: ToolName
    artifact_type: Literal[
        "request",
        "response",
        "stdout",
        "stderr",
        "raw_json",
        "raw_jsonl",
        "raw_xml",
        "normalized_json",
        "report_json",
        "report_html",
        "state_snapshot",
        "log",
    ]
    path: Path
    sha256: str
    size_bytes: int = Field(ge=0)
    content_type: str
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseSchemaModel):
    finding_id: str
    run_id: str
    task_id: str | None = None
    module: ScanPhase
    target: str
    status: FindingStatus = "observed"
    summary: str
    evidence_json: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime


class TaskState(BaseSchemaModel):
    task_id: str
    run_id: str
    module: PhaseName
    tool: ToolName
    scope: str
    state: TaskStatus = "pending"
    cursor_json: dict[str, Any] | None = None
    attempts: int = Field(default=0, ge=0)
    last_error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class TaskProgress(BaseSchemaModel):
    task_id: str
    module: PhaseName
    state: TaskStatus
    current_phase: str | None = None
    total_targets: int | None = None
    queued_count: int | None = None
    running_count: int | None = None
    completed_count: int | None = None
    processed_count: int | None = None
    finding_count: int | None = None
    artifact_count: int | None = None
    last_error: str | None = None
    chunk_index: int | None = None
    chunk_total: int | None = None
    chunk_label: str | None = None
    last_checkpoint_at: str | None = None
    cidr_estimated_remaining_min: float | None = None
    cidr_avg_chunk_min: float | None = None
    cidr_downstream_stage: str | None = None


class ExecutionLogEntry(BaseSchemaModel):
    timestamp: datetime
    level: LogLevel = "info"
    message: str
    module: PhaseName | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class RunState(BaseSchemaModel):
    run_id: str
    target: str
    status: RunStatus = "pending"
    current_phase: PhaseName | None = None
    phase_statuses: dict[PhaseName, TaskStatus] = Field(default_factory=dict)
    config: ScanConfig
    task_ids: list[str] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    last_error: str | None = None


class ScanReport(BaseSchemaModel):
    run_id: str
    target: str
    status: RunStatus
    generated_at: datetime
    config: ScanConfig
    started_at: datetime | None = None
    completed_at: datetime | None = None
    subdomain_count: int = Field(default=0, ge=0)
    host_count: int = Field(default=0, ge=0)
    path_count: int = Field(default=0, ge=0)
    port_count: int = Field(default=0, ge=0)
    candidate_cve_count: int = Field(default=0, ge=0)
    artifact_count: int = Field(default=0, ge=0)
    subdomains: list[Finding] = Field(default_factory=list)
    hosts: list[Finding] = Field(default_factory=list)
    paths: list[Finding] = Field(default_factory=list)
    ports: list[Finding] = Field(default_factory=list)
    candidate_cves: list[Finding] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
