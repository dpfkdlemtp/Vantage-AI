# Vantage-AI

**An LLM-in-the-loop, resumable reconnaissance & web-assessment orchestrator for *authorized* targets.**

Vantage-AI wraps battle-tested external tools (subfinder, httpx, ffuf, nmap, masscan, naabu, dnsx, …), normalizes everything into a single evidence-driven `Finding` model, persists resumable state in SQLite, and adds an **AI analyst inside the scan loop**: it risk-scores what recon discovers and — in autonomous mode — enqueues deeper, **scope-locked, safe** scans on the targets that matter most.

> ⚠️ **Authorized defensive use only.** No exploit delivery, no credential attacks, no stealth/evasion/persistence. CVE matches are *candidate-only* leads for manual verification, never confirmed vulnerabilities. Only scan assets you own or are explicitly authorized to test.

---

## Table of Contents

- [Why Vantage-AI](#why-vantage-ai)
- [Architecture](#architecture)
- [Capabilities (scan phases)](#capabilities-scan-phases)
- [The `ai_triage` phase (LLM-in-the-loop)](#the-ai_triage-phase-llm-in-the-loop)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Running scans end-to-end](#running-scans-end-to-end)
- [AI configuration](#ai-configuration)
- [Outputs & findings](#outputs--findings)
- [Safety model](#safety-model)
- [Development](#development)
- [Disclaimer](#disclaimer)

---

## Why Vantage-AI

Most recon tooling either runs a fixed pipeline or dumps raw tool output and leaves prioritization to you. Vantage-AI adds a feedback loop:

- **Orchestration, not reinvention** — it drives proven tools and focuses on state, normalization, resumability, and reporting.
- **Resumable by design** — every task lives in SQLite; interrupt and continue without losing findings or artifacts.
- **Evidence-driven** — all results normalize into one `Finding` model, separated into hosts / subdomains / paths / ports / candidate-CVEs.
- **AI analyst in the loop** — an LLM ranks the attack surface by risk and (optionally) *acts*: it autonomously queues deeper safe scans on the riskiest hosts and re-triages as new evidence arrives.
- **Degrades gracefully** — no API key? The AI phase falls back to a deterministic heuristic, so it still works offline / in CI.

---

## Architecture

```
scanner/
├── adapters/       External-tool wrappers (subfinder, assetfinder, crt.sh, securitytrails,
│                   httpx, ffuf, nmap, masscan, naabu, dnsx, gau, subzy, udp, playwright, wappalyzer)
├── normalizers/    Tool output → unified Finding model (subdomain, dirscan, portscan, cve, headers)
├── execution/      Per-phase logic (http_probe, dir_enum, port_scan, banner_probe, cve_match,
│                   access_control, waf_signatures, ai_triage, …)
├── ai/             LLM-in-the-loop triage: client (Anthropic/OpenAI), analyst, planner, schemas
├── ser/            Authenticated-session assessment (authorized use only; redaction + scope guard)
├── storage.py      SQLite persistence (runs, tasks, findings, artifacts)
├── state.py        Run/task state transitions
├── runner.py       Orchestration, CIDR chunking, resume, incremental enqueueing
├── report.py       JSON + HTML reports
├── web.py          Local web UI (run creation, execution control, progress, partial results)
├── installer.py    External-tool installer (go install / brew / winget / choco)
└── watchdog.py     OS-aware stall detection + auto-throttle
```

**Design rules:** adapters / normalization / storage / runner / reporting stay separate; typed Pydantic models everywhere; every phase is independently resumable; deterministic logic preferred over heuristic guesses.

---

## Capabilities (scan phases)

| Phase | Tool(s) | What it does |
|---|---|---|
| `subdomain_enum` | subfinder, assetfinder, crt.sh, securitytrails, dnsx | Subdomain discovery (free-tool-first) + DNS resolution / wildcard handling |
| `http_probe` | httpx | Reachability, titles, tech stack, basic HTTP evidence |
| `domain_discovery` | orchestrator | Derive/confirm in-scope root domains from observed evidence |
| `dir_enum` | ffuf | Directory/content enumeration on live HTTP targets (recursion-aware) |
| `port_scan` | nmap, masscan, naabu | TCP port & service detection; mass pre-scan + targeted NSE |
| `banner_probe` | orchestrator | Service banner collection for triage |
| `cve_match` | offline matcher | **Candidate-only** CVE inference from observed product/version/banner evidence |
| `access_control` | internal | Safe access-control / authorization observation checks |
| `ai_triage` | LLM analyst | **Risk-scores findings and autonomously enqueues deeper scope-locked scans** |

Supporting capabilities: WAF signature detection, GAU URL harvesting, subdomain-takeover checks (subzy), UDP scanning, and JS/SPA rendering (playwright) where enabled.

---

## The `ai_triage` phase (LLM-in-the-loop)

This is what makes Vantage-AI more than a pipeline runner. After recon, the `ai_triage` phase:

1. **Summarizes evidence** — builds a compact, redacted view of subdomains, live hosts, open ports, directory hits, and candidate CVEs.
2. **Risk-scores targets** — an LLM ranks hosts/subdomains/URLs by how much they warrant deeper (still safe) enumeration, with a rationale and signal list per target. Persisted as `candidate`-only findings tagged `ai`, `risk:high|medium|low`.
3. **Acts autonomously** (in `act` mode) — converts the highest-risk targets into follow-up `http_probe` / `dir_enum` / `port_scan` tasks, **only within authorized scope**, then **re-queues itself** to react to the new findings — a bounded agentic loop.

**Safety is enforced by construction:**

- Acts **only on targets already observed** by recon, and **only within the authorized scope** (subdomains of the run target / IPs in range). It never invents new targets.
- Can only trigger **existing safe enumeration phases**. No exploit delivery, no credential attacks, no evasion.
- **Bounded** by `ai_max_followups` (total deeper scans), `ai_max_iterations` (re-triage passes), and gated by `ai_min_risk_to_act`.

**Provider-agnostic & offline-safe:**

- `ai_provider` = `anthropic` (default) or `openai`; the API key is read from the env var named by `ai_api_key_env` (`ANTHROPIC_API_KEY` by default). Calls go over the existing `httpx` dependency — no extra SDK.
- **No key? It still runs**, using a deterministic keyword/port heuristic. Same output shape, so CI and air-gapped runs work.

---

## Requirements

- **Python 3.12+**
- External tools on `PATH` (install what you need for the phases you run): `subfinder`, `assetfinder`, `httpx`, `ffuf`, `nmap`; optionally `masscan`, `naabu`, `dnsx`, `gau`, `subzy`. `crt.sh` is reached over the network.
- A local wordlist for `ffuf` if running `dir_enum` (SecLists is **not** committed — see [Wordlists](#wordlists)).
- *(Optional)* An LLM API key for `ai_triage` to use a model instead of the offline heuristic.

Check what's installed:

```bash
python -m scanner.cli tools-check
# or install missing Go/native tools:
python -m scanner.cli tools-install
```

---

## Installation

```bash
git clone https://github.com/dpfkdlemtp/Vantage-AI.git
cd Vantage-AI
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
```

### Environment variables

The project does not auto-load `.env`. Export values in your shell:

```bash
cp .env.example .env
# edit .env, then:
set -a; source .env; set +a
```

No env vars are required for the default passive flow. For LLM-backed `ai_triage`:

```bash
export ANTHROPIC_API_KEY=sk-ant-...     # default provider
# or, for OpenAI: set OPENAI_API_KEY and ai_api_key_env=OPENAI_API_KEY / ai_provider=openai
```

### Wordlists

SecLists (~2 GB) is intentionally **not** committed (see `.gitignore`). Put your own authorized wordlists under `wordlists/`, or drop SecLists there locally. `dir_enum` needs `ffuf_wordlist_path` configured before it runs.

---

## Quick start

**Web UI (recommended):**

```bash
python -m scanner.cli ui            # then open http://127.0.0.1:8000
```

Create a run, pick the **AI-driven** preset, and watch the AI analyst triage and dig deeper in real time.

**CLI:**

```bash
# Create a run that includes the AI analyst (ordered last, after recon)
python -m scanner.cli scan example.com \
  -m subdomain_enum -m http_probe -m dir_enum -m port_scan -m ai_triage \
  --profile balanced
```

> `scan` creates and enqueues the run; it does **not** execute scanners itself. Execute phases via the Web UI, or the phase runners (below).

---

## CLI reference

| Command | Purpose |
|---|---|
| `scan TARGET [-m MODULE ...] [--profile safe\|balanced\|fast]` | Create a run and enqueue tasks |
| `resume RUN_ID` | Show resumable (incomplete) tasks for a run |
| `extend RUN_ID -m MODULE ...` | Add phases to an existing run, preserving saved results |
| `report RUN_ID [--html PATH]` | Print JSON summary; optionally write HTML |
| `ui [--host H] [--port P] [--workspace DIR]` | Start the local web UI |
| `tools-check` / `tools-install` | Inspect / install external tool dependencies |
| `watchdog-start` / `watchdog-stop` / `watchdog-status` / `watchdog-tail` | OS-aware stall detection & auto-throttle |
| `ser ...` | Authenticated-session assessment tools (authorized use only) |

---

## Running scans end-to-end

`scan` only enqueues. To execute phases from the same workspace where the run was created:

```bash
python - <<'PY'
from scanner.runner import (
    execute_subdomain_enum_tasks, execute_http_probe_tasks, execute_dir_enum_tasks,
    execute_port_scan_tasks, execute_banner_probe_tasks, execute_cve_match_tasks,
    execute_ai_triage_tasks,
)
run_id = "REPLACE_WITH_RUN_ID"
print(execute_subdomain_enum_tasks(run_id))
print(execute_http_probe_tasks(run_id))
print(execute_port_scan_tasks(run_id))
print(execute_dir_enum_tasks(run_id))
print(execute_banner_probe_tasks(run_id))
print(execute_ai_triage_tasks(run_id))   # LLM analyst: scores risk + (act mode) queues deeper scans
PY
```

Run phases in order; each is resumable and reads persisted outputs from earlier phases. In the **Web UI**, the execution loop runs multiple passes so AI-enqueued follow-ups (and re-triage) complete within the same run automatically.

---

## AI configuration

`ai_triage` is controlled by these `ScanConfig` fields (set via the `ai` UI preset or run config):

| Field | Default | Meaning |
|---|---|---|
| `ai_triage_enabled` | `true` | Master switch for the phase |
| `ai_autonomy` | `act` | `act` (autonomous deeper scans) · `advise` (record risk findings only) · `off` |
| `ai_provider` | `anthropic` | `anthropic` or `openai` |
| `ai_model` | `""` | Model id; empty → provider default (`claude-sonnet-4-6` / `gpt-4o-mini`) |
| `ai_api_key_env` | `ANTHROPIC_API_KEY` | Env var name to read the key from |
| `ai_min_risk_to_act` | `0.6` | Risk threshold (0–1) to enqueue a follow-up |
| `ai_max_followups` | `8` | Total autonomous follow-up scans per run (budget) |
| `ai_max_iterations` | `3` | Max re-triage passes (loop bound) |
| `ai_request_timeout_seconds` | `60` | Per-request LLM timeout |

**Autonomy modes at a glance:**

- `act` — the headline mode. LLM scores risk and autonomously queues deeper safe scans within scope.
- `advise` — LLM records risk findings; a human decides whether to `extend` the run.
- `off` — phase is a no-op.

---

## Outputs & findings

```
runs/<run_id>/
├── state.db        # SQLite: run state, tasks, findings, artifact references
└── artifacts/      # raw tool outputs (subfinder/httpx/ffuf/nmap/... XML/JSON/logs)
```

- **Artifacts** are stored on disk; SQLite holds metadata (path, sha256, size, content-type) — not raw blobs.
- **Findings** normalize into one model and group in reports as: subdomains · live hosts · directory hits · open ports/services · candidate CVEs · **AI risk findings** (`candidate`-only, tagged `ai`/`risk:*`).
- `report RUN_ID` prints a JSON summary; `--html` also writes a readable HTML report.

---

## Safety model

- Authorized defensive assessment **only**.
- Safe defaults; **no** exploit delivery, credential attacks, stealth, evasion, persistence, or destructive checks.
- CVE matches are **candidate-only** (matched product/version, confidence, evidence source, `candidate_only=true`).
- The AI analyst **cannot widen scope**: it acts only on already-observed targets inside the authorized scope, triggers only safe enumeration phases, and is bounded by explicit budgets.
- Authenticated-session (`ser`) tooling redacts secrets and enforces a scope allowlist.

---

## Development

```bash
python -m pytest          # full test suite
python -m mypy scanner    # type check
python -m ruff check .     # lint
```

The suite mocks subprocess/tool/network calls by default, so it runs without the external binaries or an LLM key.

---

## Disclaimer

This project is for **authorized** security assessment and educational use only. You are responsible for ensuring you have explicit permission to scan any target. The authors assume no liability for misuse. Candidate CVEs and AI risk scores are **leads for manual verification**, not confirmed findings.
