CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    config_json TEXT NOT NULL CHECK (json_valid(config_json)),
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    module TEXT NOT NULL CHECK (module IN ('subdomain_enum', 'http_probe', 'domain_discovery', 'dir_enum', 'port_scan', 'banner_probe', 'cve_match', 'access_control', 'ai_triage', 'report')),
    tool TEXT NOT NULL,
    scope TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'completed', 'failed', 'skipped', 'cancelled')),
    cursor_json TEXT CHECK (cursor_json IS NULL OR json_valid(cursor_json)),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    UNIQUE (run_id, module, tool, scope)
);

CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    task_id TEXT,
    module TEXT NOT NULL CHECK (module IN ('subdomain_enum', 'http_probe', 'domain_discovery', 'dir_enum', 'port_scan', 'banner_probe', 'cve_match', 'access_control', 'ai_triage')),
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
    tags_json TEXT CHECK (tags_json IS NULL OR json_valid(tags_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE SET NULL
);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    task_id TEXT,
    module TEXT NOT NULL CHECK (module IN ('subdomain_enum', 'http_probe', 'domain_discovery', 'dir_enum', 'port_scan', 'banner_probe', 'cve_match', 'access_control', 'ai_triage', 'report')),
    tool TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    content_type TEXT,
    metadata_json TEXT CHECK (metadata_json IS NULL OR json_valid(metadata_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE SET NULL,
    UNIQUE (run_id, path)
);

CREATE INDEX idx_runs_status ON runs(status);
CREATE INDEX idx_runs_target ON runs(target);

CREATE INDEX idx_tasks_run_id ON tasks(run_id);
CREATE INDEX idx_tasks_run_module_state ON tasks(run_id, module, state);
CREATE INDEX idx_tasks_state ON tasks(state);

CREATE INDEX idx_findings_run_id ON findings(run_id);
CREATE INDEX idx_findings_run_module ON findings(run_id, module);
CREATE INDEX idx_findings_task_id ON findings(task_id);
CREATE INDEX idx_findings_target ON findings(target);

CREATE INDEX idx_artifacts_run_id ON artifacts(run_id);
CREATE INDEX idx_artifacts_task_id ON artifacts(task_id);
CREATE INDEX idx_artifacts_run_module_tool ON artifacts(run_id, module, tool);
CREATE INDEX idx_artifacts_sha256 ON artifacts(sha256);

CREATE TABLE IF NOT EXISTS service_notes (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT,
    service_name TEXT,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_service_notes_host_port ON service_notes (host, port);
