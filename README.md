# Web Scanner

`web-scanner` is a CLI-first defensive scanning orchestrator for authorized targets only.
It wraps established external tools, stores resumable state in SQLite, saves raw artifacts,
and normalizes findings into a consistent evidence-driven format.

## Safety Scope

- Authorized defensive assessment only.
- Safe defaults only.
- No exploit delivery.
- No credential attacks.
- No stealth, evasion, persistence, or destructive checks.
- CVE matches are candidate-only. They are not confirmed vulnerabilities.

## Current Capabilities

- `subdomain_enum`: free-tool-first subdomain discovery with `subfinder`, `assetfinder`, and `crt.sh`
- `http_probe`: `httpx` probing for reachability, titles, and basic HTTP evidence
- `dir_enum`: `ffuf` directory enumeration against live HTTP targets
- `port_scan`: `nmap` TCP port and service detection
- `cve_match`: offline candidate-only CVE matching from previously observed evidence

## Requirements

- Python 3.12+
- `subfinder` installed and available on `PATH`
- `assetfinder` installed and available on `PATH`
- Access to `crt.sh` for certificate-transparency lookups
- `httpx` installed and available on `PATH`
- `ffuf` installed and available on `PATH`
- `nmap` installed and available on `PATH`
- A local wordlist for `ffuf` if you plan to run `dir_enum`

Install external binaries with your package manager or the official installation method for
each tool, then confirm they are available in your shell:

```bash
httpx -version
ffuf -V
nmap --version
```

## Installation

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Environment Variables

Copy the example file and export the values in your shell before running phase workers.
The project does not auto-load `.env` files.

```bash
cp .env.example .env
set -a
source .env
set +a
```

No environment variables are required for the default passive subdomain flow.

## Wordlists

The repository intentionally does not ship real directory wordlists. Put your own safe,
licensed, authorized wordlists under `wordlists/` or another path you control.

Important:

- `dir_enum` needs `ffuf_wordlist_path` to be configured before that phase runs.
- The current CLI does not expose a `--wordlist` flag yet.
- If you execute `dir_enum`, make sure the run config points to a valid local wordlist path.

See `wordlists/README.md` for the expected usage.

## CLI Workflow

The current CLI surface is intentionally small and safe:

- `scan` creates a new run, persists config/state, and enqueues pending tasks
- `extend` adds new modules to an existing run while preserving saved findings, artifacts, and completed tasks
- `resume` loads an existing run and shows incomplete tasks
- `report` reads persisted findings/artifacts and prints a JSON summary
- `report --html` writes a readable HTML report in addition to the JSON summary

Important:

- `scan` does not immediately execute external scanners.
- `resume` does not execute tasks either.
- Phase execution is handled by the phase runners in the application layer.

For subdomain discovery, the default source order is:

- `subfinder`
- `assetfinder`
- `crt.sh`

## Running Phase Workers Today

Dedicated CLI commands for phase execution are not exposed yet. To execute the queued phases,
run the phase helpers from the same workspace where you created the run:

```bash
python - <<'PY'
from scanner.runner import (
    execute_cve_match_tasks,
    execute_dir_enum_tasks,
    execute_http_probe_tasks,
    execute_port_scan_tasks,
    execute_subdomain_enum_tasks,
)

run_id = "run-20260409123000-ab12cd34"

print(execute_subdomain_enum_tasks(run_id))
print(execute_http_probe_tasks(run_id))
print(execute_dir_enum_tasks(run_id))
print(execute_port_scan_tasks(run_id))
print(execute_cve_match_tasks(run_id))
PY
```

Run phases in order. Each phase is resumable and reads persisted outputs from earlier phases.
If you plan to run `dir_enum`, make sure `ffuf_wordlist_path` is configured first.

## Example Commands

Create a run with the default module set:

```bash
python -m scanner.cli scan example.com
```

Create a run with a specific module set and speed profile:

```bash
python -m scanner.cli scan example.com \
  --module subdomain_enum \
  --module http_probe \
  --profile balanced
```

Inspect resumable state for an existing run:

```bash
python -m scanner.cli resume run-20260409123000-ab12cd34
```

Extend an existing run with later phases while keeping previously saved results:

```bash
python -m scanner.cli extend run-20260409123000-ab12cd34 \
  --module subdomain_enum \
  --module dir_enum
```

Print the JSON report summary for a run:

```bash
python -m scanner.cli report run-20260409123000-ab12cd34
```

Write an HTML report while still printing the JSON summary to stdout:

```bash
python -m scanner.cli report run-20260409123000-ab12cd34 \
  --html reports/run-20260409123000-ab12cd34.html
```

## Outputs

### `runs/`

Each run gets its own directory:

```text
runs/<run_id>/
├── state.db
└── artifacts/
```

- `state.db`: SQLite database for run state, tasks, findings, and artifact references
- `artifacts/`: raw output files saved from passive discovery and wrapped tools such as
  `subfinder`, `assetfinder`, `crt.sh`, `httpx`, `ffuf`, and `nmap`

### `reports/`

- HTML reports written by `report --html`
- Reserved location for generated report files

Note: the CLI currently prints JSON summaries to stdout. It does not automatically write a
JSON report file to disk.

### Artifacts

Raw tool outputs are saved under `runs/<run_id>/artifacts/` and referenced from SQLite.
The database stores metadata such as path, hash, size, and content type. Raw content is not
embedded in SQLite rows.

### Incremental Follow-up

Runs can be continued from saved state. A common flow is:

1. Create a low-impact first pass such as `port_scan`.
2. Execute that phase and inspect the saved findings/artifacts.
3. Add later modules with `extend` or from the Progress page run options.
4. Resume execution so the newly added pending tasks continue from the same run.

Existing findings, artifacts, and completed tasks stay attached to the same run.

### Findings

Normalized findings are stored in SQLite and returned by the `report` command. They are
evidence-driven and grouped in reports as:

- subdomains
- live hosts / HTTP probe results
- directory findings
- open ports / services
- candidate CVEs

## Candidate CVEs

CVE matches in this project are inference-only. They are generated from previously observed
evidence such as titles, products, versions, or service banners.

Every candidate should be treated as a lead for manual verification, not as a confirmed
vulnerability.
