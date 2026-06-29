# AGENTS.md

## Project Overview

This repository builds a defensive scanning orchestrator for authorized targets only.

Primary capabilities:
- subdomain enumeration
- directory enumeration
- TCP port/service scanning
- optional CVE candidate matching

The project wraps existing tools instead of re-implementing scanners:
- SecurityTrails for subdomain discovery
- httpx for probing/alive/title/tech extraction
- ffuf for directory enumeration
- nmap for TCP port/service scanning

This project is strictly for authorized defensive assessment only.

---

## Product Requirements

- Python 3.12
- CLI-first
- JSON output is mandatory
- resumable execution after interruption
- raw tool outputs must be saved as artifacts
- normalized findings must be persisted
- speed profiles must be configurable
- safe defaults only
- no exploit logic
- no auth brute force
- no stealth/evasion features
- CVE matches must be candidate-only, never confirmed vulnerabilities
- tests must mock subprocess/tool outputs by default

---

## Architecture Rules

- Keep adapters, normalization, storage, runner, and reporting separated
- Use typed models for config, findings, tasks, reports, and persisted state
- All scan results must be normalized into a universal Finding model
- Save both:
  - normalized results
  - raw artifacts from external tools
- Resumability must be implemented with SQLite-backed task state
- Prefer deterministic logic over heuristic guesses
- Every scan phase must be independently resumable

---

## Safety Rules

- Never add exploit delivery
- Never add credential attacks
- Never add stealth, evasion, persistence, or destructive checks
- Never claim a vulnerability is confirmed from banner/title matching alone
- Never skip persistence of intermediate state for long-running tasks

---

## Agent Directives: Mechanical Overrides

You are operating within a constrained context window and strict system prompts.
To produce production-grade code, you MUST adhere to these overrides.

### Pre-Work

1. THE "STEP 0" RULE:
Before ANY structural refactor on a file >300 LOC, first remove dead code, unused imports, unused exports, and debug logs.
Commit this cleanup separately before starting the real work.

2. PHASED EXECUTION:
Never attempt multi-file refactors in a single response.
Break work into explicit phases.
Complete Phase 1, run verification, and wait for approval before Phase 2.
Each phase must touch no more than 5 files.

### Code Quality

3. THE SENIOR DEV OVERRIDE:
If architecture is flawed, state is duplicated, or patterns are inconsistent, propose and implement structural fixes.
Ask: what would a senior, experienced, perfectionist reviewer reject?

4. FORCED VERIFICATION:
Do not report completion until verification has run and all errors are fixed.

Python project equivalent:
- run formatting check if configured
- run lint if configured
- run type-check if configured
- run tests

If a checker is not configured, say that explicitly.

Minimum verification for this repo:
- pytest
- ruff check .  (if configured)
- python -m mypy scanner tests  (if configured)

### Context Management

5. SUB-AGENT SWARMING:
For tasks touching >5 independent files, explicitly propose sub-agent decomposition first.
Do not process large independent file groups as one blob.

6. CONTEXT DECAY AWARENESS:
After long conversations, re-read files before editing.
Do not trust stale memory.

7. FILE READ BUDGET:
For large files, read in chunks.
Do not assume one read captured the entire file.

8. TOOL RESULT BLINDNESS:
If command output looks suspiciously short, re-run with narrower scope and state that truncation may have occurred.

### Edit Safety

9. EDIT INTEGRITY:
Before every edit, re-read the file.
After editing, re-read it to confirm the change applied.
Do not batch more than 3 edits to the same file without a verification read.

10. NO SEMANTIC SEARCH:
When renaming or changing any function/type/variable, search separately for:
- direct references
- type references
- string literals
- dynamic imports
- re-exports
- tests and mocks

Do not assume one grep caught everything.

---

## Execution Strategy

Always work in phases.

Phase order:
1. skeleton + models + storage/state
2. CLI wiring + run lifecycle
3. SecurityTrails + subdomain normalization
4. httpx probing + normalization
5. ffuf dirscan + normalization
6. nmap portscan + normalization
7. optional CVE candidate matching
8. HTML reporting polish

At the end of each phase:
- summarize what changed
- list verification commands run
- state what remains
- stop unless explicitly told to continue

---

## Build / Verify Commands

Preferred commands:
- python -m pytest
- ruff check .
- python -m mypy scanner tests

If a command is unavailable, say so explicitly instead of pretending success.

---

## Reporting Rules

- Findings must be evidence-driven
- Candidate CVEs must include:
  - matched product/version/value
  - confidence score
  - evidence source
  - explicit candidate_only=true
- Reports must clearly separate:
  - hosts
  - subdomains
  - paths
  - ports
  - candidate CVEs