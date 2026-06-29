from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

SECTION_DEFINITIONS: tuple[tuple[str, str, str], ...] = (
    ("subdomains", "Subdomains", "No subdomains observed."),
    ("http_probe_results", "Live Hosts / HTTP Probe Results", "No live HTTP probe results observed."),
    ("directory_findings", "Directory Findings", "No directory findings observed."),
    ("open_ports", "Open Ports / Services", "No open ports or services observed."),
)


def render_html_report(summary: dict[str, Any]) -> str:
    run_summary = summary.get("run_summary", {})
    sections = _sections(summary)
    host_groups = _host_groups(summary)
    candidate_cves = _dict_items(sections.get("candidate_cves"))
    errors = _dict_items(summary.get("errors"))
    key_findings = _collect_key_findings(summary)
    diff_summary = summary.get("diff_summary")
    title = f"Scan Report: {summary.get('target', 'unknown target')}"

    observed_sections = "".join(
        _render_section(section_key, section_title, empty_text, _dict_items(sections.get(section_key)))
        for section_key, section_title, empty_text in SECTION_DEFINITIONS
    )
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f1e8;
      --panel: #fffdf8;
      --ink: #1f2a30;
      --muted: #5d6a70;
      --accent: #114b5f;
      --accent-soft: #dbeef2;
      --warn: #8a4b08;
      --warn-soft: #fceacc;
      --danger: #8c2f39;
      --danger-soft: #f8d8dd;
      --border: #d9d1c3;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top right, rgba(17, 75, 95, 0.12), transparent 28%),
        linear-gradient(180deg, #fcfaf5 0%, var(--bg) 100%);
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }}
    header {{
      margin-bottom: 24px;
      padding: 28px;
      border: 1px solid var(--border);
      border-radius: 20px;
      background: linear-gradient(135deg, rgba(17, 75, 95, 0.08), rgba(255, 255, 255, 0.96));
      box-shadow: 0 14px 28px rgba(31, 42, 48, 0.08);
    }}
    h1, h2, h3, h4, p {{ margin-top: 0; }}
    h1 {{ margin-bottom: 8px; font-size: 2rem; }}
    h2 {{ margin-bottom: 12px; font-size: 1.4rem; }}
    h3 {{ margin-bottom: 10px; font-size: 1.05rem; }}
    .lede {{ margin-bottom: 0; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin: 20px 0 0;
    }}
    .metric {{
      padding: 14px 16px;
      border: 1px solid var(--border);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.8);
    }}
    .metric .label {{
      display: block;
      margin-bottom: 4px;
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .metric .value {{ font-size: 1.2rem; font-weight: 700; }}
    section {{
      margin-top: 24px;
      padding: 24px;
      border: 1px solid var(--border);
      border-radius: 18px;
      background: var(--panel);
      box-shadow: 0 10px 24px rgba(31, 42, 48, 0.06);
    }}
    .section-heading {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }}
    .count {{
      padding: 4px 10px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 0.88rem;
      font-weight: 700;
    }}
    .candidate-note {{
      padding: 12px 14px;
      border-radius: 14px;
      background: var(--warn-soft);
      color: var(--warn);
      border: 1px solid rgba(138, 75, 8, 0.18);
    }}
    .error-note {{
      padding: 12px 14px;
      border-radius: 14px;
      background: var(--danger-soft);
      color: var(--danger);
      border: 1px solid rgba(140, 47, 57, 0.2);
    }}
    .cards {{
      display: grid;
      gap: 14px;
      margin-top: 16px;
    }}
    .host-grid {{
      display: grid;
      gap: 16px;
      margin-top: 16px;
    }}
    .host-shell {{
      border: 1px solid var(--border);
      border-radius: 18px;
      background: #fff;
      overflow: hidden;
    }}
    .host-head {{
      padding: 16px 18px;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(135deg, rgba(17, 75, 95, 0.08), rgba(255, 255, 255, 0.98));
    }}
    .host-head h3 {{ margin-bottom: 8px; }}
    .host-head p {{ margin-bottom: 10px; color: var(--muted); }}
    .host-body {{
      display: grid;
      gap: 14px;
      padding: 16px 18px 18px;
    }}
    .host-row {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }}
    .host-box {{
      padding: 14px;
      border: 1px solid var(--border);
      border-radius: 14px;
      background: #fffdf8;
    }}
    .host-box h4 {{ margin-bottom: 8px; font-size: 0.96rem; }}
    .host-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }}
    .host-table th, .host-table td {{
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    .host-table th {{
      color: var(--muted);
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}
    .host-table tr:last-child td {{ border-bottom: none; }}
    .card {{
      padding: 16px 18px;
      border: 1px solid var(--border);
      border-radius: 16px;
      background: #fff;
    }}
    .card h4 {{
      margin-bottom: 6px;
      font-size: 1rem;
      word-break: break-word;
    }}
    .card p {{
      margin-bottom: 10px;
      color: var(--muted);
    }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }}
    .pill {{
      padding: 3px 8px;
      border-radius: 999px;
      background: #edf2f4;
      color: #33444d;
      font-size: 0.82rem;
    }}
    details {{
      margin-top: 8px;
      border-top: 1px dashed var(--border);
      padding-top: 8px;
    }}
    pre {{
      overflow-x: auto;
      padding: 12px;
      border-radius: 12px;
      background: #f3f0ea;
      color: #22343b;
      font-size: 0.84rem;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .empty {{
      margin: 16px 0 0;
      color: var(--muted);
      font-style: italic;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>{title}</h1>
      <h2>Run Summary</h2>
      <p class="lede">Readable HTML summary generated from persisted scan state. Candidate CVEs are inference-only and are not confirmed vulnerabilities.</p>
      <div class="grid">{summary_metrics}</div>
    </header>
    {scanning_notes_section}
    <section>
      <div class="section-heading">
        <h2>Key Findings</h2>
        <span class="count">{key_findings_count} items</span>
      </div>
      {key_findings_section}
    </section>
    {host_detail_section}
    {diff_section}
    <section>
      <div class="section-heading">
        <h2>Observed Findings</h2>
        <span class="count">{observed_count} items</span>
      </div>
      {observed_sections}
    </section>
    <section>
      <div class="section-heading">
        <h2>Inferred Candidate CVEs</h2>
        <span class="count">{candidate_count} items</span>
      </div>
      <p class="candidate-note">Candidate only. These matches come from previously observed evidence such as titles, products, versions, or service banners. They are not confirmations.</p>
      {candidate_section}
    </section>
    <section>
      <div class="section-heading">
        <h2>Errors</h2>
        <span class="count">{error_count} items</span>
      </div>
      {errors_section}
    </section>
  </main>
</body>
</html>
""".format(
        title=_html(title),
        summary_metrics=_render_summary_metrics(summary, run_summary, sections, errors),
        scanning_notes_section=_render_scanning_notes_section(summary.get("execution_notes", {})),
        key_findings_count=len(key_findings),
        key_findings_section=_render_key_findings_section(key_findings),
        host_detail_section=_render_host_detail_section(host_groups),
        diff_section=_render_diff_summary_section(diff_summary),
        observed_count=sum(len(_dict_items(sections.get(key))) for key, _, _ in SECTION_DEFINITIONS),
        observed_sections=observed_sections,
        candidate_count=len(candidate_cves),
        candidate_section=_render_candidate_section(candidate_cves),
        error_count=len(errors),
        errors_section=_render_error_section(errors),
    )


def write_html_report(summary: dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html_report(summary), encoding="utf-8")
    return output_path


def _render_summary_metrics(
    summary: dict[str, Any],
    run_summary: dict[str, Any],
    sections: dict[str, list[dict[str, Any]]],
    errors: list[dict[str, Any]],
) -> str:
    metrics = [
        ("Run ID", summary.get("run_id", "")),
        ("Target", summary.get("target", "")),
        ("Status", summary.get("status", "")),
        ("Observed", run_summary.get("observed_finding_count", 0)),
        ("Candidates", len(_dict_items(sections.get("candidate_cves")))),
        ("Artifacts", run_summary.get("artifact_count", 0)),
        ("Modules", ", ".join(_string_items(summary.get("modules"))) or "None"),
        ("Started", run_summary.get("started_at") or "Not started"),
        ("Completed", run_summary.get("completed_at") or "In progress"),
        ("Errors", len(errors)),
    ]
    return "".join(_render_metric(label, value) for label, value in metrics)


def _render_metric(label: str, value: object) -> str:
    return (
        '<div class="metric">'
        f'<span class="label">{_html(label)}</span>'
        f'<span class="value">{_html(value)}</span>'
        "</div>"
    )


def _render_key_findings_section(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="empty">No key findings prioritized yet.</p>'
    cards = "".join(
        '<article class="card">'
        f'<h4>{_html(item.get("title", "Key finding"))}</h4>'
        f'<p>{_html(item.get("summary", ""))}</p>'
        f'<div class="meta">{_pill(item.get("kind", "finding"))}{_pill(item.get("target", "unknown target"))}</div>'
        f'{_evidence_details(item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {})}'
        "</article>"
        for item in items
    )
    return f'<div class="cards">{cards}</div>'


def _render_host_detail_section(host_groups: list[dict[str, Any]]) -> str:
    if not host_groups:
        return (
            '<section>'
            '<div class="section-heading"><h2>Host-Centric Detail</h2><span class="count">0 hosts</span></div>'
            '<p class="empty">No host-centric findings are available yet.</p>'
            '</section>'
        )
    cards = "".join(_render_host_group_card(group) for group in host_groups)
    return (
        '<section>'
        f'<div class="section-heading"><h2>Host-Centric Detail</h2><span class="count">{len(host_groups)} hosts</span></div>'
        f'<div class="host-grid">{cards}</div>'
        '</section>'
    )


def _render_diff_summary_section(diff_summary: Any) -> str:
    diff = diff_summary if isinstance(diff_summary, dict) else None
    if not diff:
        return ""
    categories = diff.get("categories")
    if not isinstance(categories, dict):
        return ""
    cards = []
    for key, label, _ in (
        ("subdomains", "Subdomains", ""),
        ("http_probe_results", "Live Hosts / HTTP Probe", ""),
        ("directory_findings", "Directory Findings", ""),
        ("open_ports", "Open Ports / Services", ""),
        ("candidate_cves", "Candidate CVEs", ""),
    ):
        category = categories.get(key)
        if not isinstance(category, dict):
            continue
        cards.append(
            '<article class="card">'
            f'<h4>{_html(label)}</h4>'
            f'<div class="meta">{_pill("added " + str(category.get("added_count", 0)))}'
            f'{_pill("removed " + str(category.get("removed_count", 0)))}'
            f'{_pill("unchanged " + str(category.get("unchanged_count", 0)))}</div>'
            f'{_diff_detail_block("Added", category.get("added"))}'
            f'{_diff_detail_block("Removed", category.get("removed"))}'
            '</article>'
        )
    if not cards:
        return ""
    return (
        '<section>'
        '<div class="section-heading">'
        '<h2>Run Diff Summary</h2>'
        f'<span class="count">{_html(diff.get("baseline_run_id", "baseline"))} -> {_html(diff.get("current_run_id", "current"))}</span>'
        '</div>'
        f'<div class="cards">{ "".join(cards) }</div>'
        '</section>'
    )


def _diff_detail_block(title: str, items: Any) -> str:
    entries = _dict_items(items)
    if not entries:
        return ""
    lines = "".join(f"<li>{_html(item.get('target') or item.get('summary') or 'item')}</li>" for item in entries[:8])
    return f"<details><summary>{_html(title)} ({len(entries)})</summary><ul>{lines}</ul></details>"


def _render_section(
    section_key: str,
    title: str,
    empty_text: str,
    items: list[dict[str, Any]],
) -> str:
    if not items:
        return (
            '<section>'
            f'<div class="section-heading"><h3>{_html(title)}</h3><span class="count">0 items</span></div>'
            f'<p class="empty">{_html(empty_text)}</p>'
            "</section>"
        )
    cards = "".join(_render_finding_card(item, candidate=False) for item in items)
    return (
        '<section>'
        f'<div class="section-heading"><h3>{_html(title)}</h3><span class="count">{len(items)} items</span></div>'
        f'<div class="cards" data-section="{_html(section_key)}">{cards}</div>'
        "</section>"
    )


def _render_candidate_section(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="empty">No inferred candidate CVEs.</p>'
    cards = "".join(_render_finding_card(item, candidate=True) for item in items)
    return f'<div class="cards">{cards}</div>'


def _render_host_group_card(group: dict[str, Any]) -> str:
    overview_pills = [
        _pill("alive" if group.get("alive") else "not confirmed alive"),
        _pill(f"ports {len(_dict_items(group.get('open_ports')))}"),
        _pill(f"paths {len(_dict_items(group.get('directory_findings')))}"),
        _pill(f"candidates {len(_dict_items(group.get('candidate_cves')))}"),
    ]
    auth_required_count = int(group.get("auth_required_path_count") or 0)
    if auth_required_count > 0:
        overview_pills.append(_pill(f"401/403 {auth_required_count}"))
    representative_ports = _dict_items(group.get("representative_ports"))
    representative_paths = _dict_items(group.get("representative_paths"))
    port_rows = "".join(
        "<tr>"
        f"<td>{_html(item.get('protocol') or 'tcp')}/{_html(item.get('port') or '?')}</td>"
        f"<td>{_html(item.get('service') or '-')}</td>"
        f"<td>{_html(item.get('product') or '-')}</td>"
        f"<td>{_html(item.get('version') or '-')}</td>"
        "</tr>"
        for item in representative_ports
    ) or '<tr><td colspan="4" class="empty">No representative ports.</td></tr>'
    path_cards = "".join(
        '<article class="card">'
        f"<h4>{_html(item.get('target') or 'Path')}</h4>"
        f"<p>{_html(item.get('summary') or '')}</p>"
        f"<div class=\"meta\">{_pill('status ' + str(item.get('status_code') or '?'))}</div>"
        "</article>"
        for item in representative_paths
    ) or '<p class="empty">No representative paths.</p>'
    cve_cards = "".join(
        '<article class="card">'
        f"<h4>{_html(item.get('summary') or 'Candidate CVE')}</h4>"
        f"<p class=\"candidate-note\">Candidate only. Review evidence before triage.</p>"
        f"{_evidence_details(_dict_value(item.get('evidence')))}"
        "</article>"
        for item in _dict_items(group.get("candidate_cves"))[:3]
    ) or '<p class="empty">No candidate CVEs for this host.</p>'
    subdomain_cards = "".join(
        '<article class="card">'
        f"<h4>{_html(item.get('target') or 'Subdomain')}</h4>"
        f"<p>{_html(item.get('summary') or '')}</p>"
        "</article>"
        for item in _dict_items(group.get("subdomains"))[:5]
    ) or '<p class="empty">No related subdomains for this host.</p>'
    return (
        '<article class="host-shell">'
        '<div class="host-head">'
        f"<h3>{_html(group.get('host') or 'unknown host')}</h3>"
        f"<p>{_html(', '.join(_string_items(group.get('ip_addresses'))) or 'No IP evidence recorded')}</p>"
        f"<div class=\"meta\">{''.join(overview_pills)}{''.join(_pill(item) for item in _string_items(group.get('technologies'))[:6])}</div>"
        '</div>'
        '<div class="host-body">'
        '<div class="host-row">'
        '<div class="host-box">'
        '<h4>Overview</h4>'
        f"<p><strong>Alive:</strong> {_html('yes' if group.get('alive') else 'no')}</p>"
        f"<p><strong>Technologies:</strong> {_html(', '.join(_string_items(group.get('technologies'))) or 'None recorded')}</p>"
        f"<p><strong>Artifacts:</strong> {_html(len(_dict_items(group.get('artifacts'))))}</p>"
        '</div>'
        '<div class="host-box">'
        '<h4>Representative Ports</h4>'
        '<table class="host-table"><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>'
        f'{port_rows}'
        '</tbody></table>'
        '</div>'
        '</div>'
        '<div class="host-row">'
        f'<div class="host-box"><h4>Representative Paths</h4>{path_cards}</div>'
        f'<div class="host-box"><h4>Candidate CVEs</h4>{cve_cards}</div>'
        '</div>'
        '<div class="host-box">'
        '<h4>Subdomains</h4>'
        f'{subdomain_cards}'
        '</div>'
        '</div>'
        '</article>'
    )


def _render_scanning_notes_section(notes: dict[str, Any]) -> str:
    calibrations = _dict_items(notes.get("calibrations"))
    relevant = [
        c for c in calibrations 
        if c.get("module") == "dir_enum" and (c.get("derived_extensions") or c.get("tech_evidence"))
    ]
    if not relevant:
        return ""
    
    cards = ""
    for item in relevant:
        exts = item.get("derived_extensions") or []
        tech = item.get("tech_evidence") or []
        using_default = item.get("using_default_extensions", False)
        
        info_lines = []
        if exts:
            info_lines.append(f"<strong>Extensions:</strong> {', '.join(exts)}")
        elif using_default:
            info_lines.append("<strong>Extensions:</strong> [Default]")
            
        if tech:
            info_lines.append(f"<strong>Based on tech:</strong> {', '.join(tech)}")
            
        cards += (
            '<article class="card">'
            f'<h4>{_html(item.get("base_url") or item.get("scope") or "Target")}</h4>'
            f'<p>{"<br>".join(info_lines)}</p>'
            f'<div class="meta">{_pill("dir_enum")}{_pill("tech-aware")}</div>'
            "</article>"
        )
        
    return (
        '<section>'
        '<div class="section-heading"><h2>Scanning Intelligence / Tech Notes</h2></div>'
        '<p class="lede">Insights from technology probing influenced the following scan parameters.</p>'
        f'<div class="cards">{cards}</div>'
        '</section>'
    )


def _render_error_section(errors: list[dict[str, Any]]) -> str:
    if not errors:
        return '<p class="empty">No errors recorded.</p>'
    cards = "".join(
        '<article class="card">'
        f'<h4>{_html(error.get("module", "unknown module"))} / {_html(error.get("tool", "unknown tool"))}</h4>'
        f'<p class="error-note">{_html(error.get("last_error", "Unknown error"))}</p>'
        f'<div class="meta">{_pill("Task " + str(error.get("task_id", "unknown")))}{_pill("State " + str(error.get("state", "unknown")))}{_pill("Updated " + str(error.get("updated_at", "unknown")))}</div>'
        "</article>"
        for error in errors
    )
    return f'<div class="cards">{cards}</div>'


def _render_finding_card(item: dict[str, Any], *, candidate: bool) -> str:
    evidence = item.get("evidence")
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    tags = _string_items(item.get("tags"))
    meta_pills = [_pill(f"Module {item.get('module', 'unknown')}"), _pill(f"Status {item.get('status', 'unknown')}")]
    meta_pills.extend(_pill(str(tag)) for tag in tags)
    details = _evidence_details(evidence_dict)
    if candidate:
        title = evidence_dict.get("cve_id", item.get("summary", "Candidate CVE"))
        subtitle = (
            f"Matched {evidence_dict.get('matched_field', 'unknown')} "
            f"'{evidence_dict.get('matched_value', 'unknown')}' with confidence {evidence_dict.get('confidence', 'n/a')}"
        )
    else:
        title = item.get("target", "Unknown target")
        subtitle = item.get("summary", "")
    return (
        '<article class="card">'
        f'<h4>{_html(title)}</h4>'
        f'<p>{_html(subtitle)}</p>'
        f'<div class="meta">{"".join(meta_pills)}</div>'
        f'{_target_line(item.get("target", ""))}'
        f'{details}'
        "</article>"
    )


def _target_line(target: object) -> str:
    if not target:
        return ""
    return f'<p><strong>Target:</strong> {_html(target)}</p>'


def _evidence_details(evidence: dict[str, Any]) -> str:
    if not evidence:
        return ""
    formatted = json.dumps(evidence, indent=2, sort_keys=True)
    return (
        "<details>"
        "<summary>Evidence</summary>"
        f"<pre>{_html(formatted)}</pre>"
        "</details>"
    )


def _pill(value: object) -> str:
    return f'<span class="pill">{_html(value)}</span>'


def _sections(summary: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    sections = summary.get("sections")
    if isinstance(sections, dict):
        return {str(key): _dict_items(value) for key, value in sections.items()}
    return {
        "subdomains": [],
        "http_probe_results": [],
        "directory_findings": [],
        "open_ports": [],
        "candidate_cves": [],
    }


def _host_groups(summary: dict[str, Any]) -> list[dict[str, Any]]:
    groups = summary.get("host_groups")
    return _dict_items(groups)


def _collect_key_findings(summary: dict[str, Any]) -> list[dict[str, Any]]:
    sections = _sections(summary)
    items: list[dict[str, Any]] = []
    for item in _dict_items(sections.get("http_probe_results"))[:3]:
        items.append(
            {
                "kind": "live host",
                "title": item.get("target", "Live host"),
                "target": item.get("target", "unknown"),
                "summary": item.get("summary", ""),
                "evidence": item.get("evidence", {}),
            }
        )
    for item in _dict_items(sections.get("directory_findings")):
        evidence = item.get("evidence", {})
        status_code = evidence.get("status_code") if isinstance(evidence, dict) else None
        if status_code not in {401, 403}:
            continue
        items.append(
            {
                "kind": "auth-required path",
                "title": item.get("target", "Protected path"),
                "target": item.get("target", "unknown"),
                "summary": item.get("summary", ""),
                "evidence": evidence,
            }
        )
        if len([entry for entry in items if entry["kind"] == "auth-required path"]) >= 3:
            break
    unusual_port_count = 0
    for item in _dict_items(sections.get("open_ports")):
        evidence = item.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}
        port = _extract_port_number(item.get("target"), evidence)
        if port is None or not _is_unusual_open_port(port):
            continue
        items.append(
            {
                "kind": "unusual open port",
                "title": item.get("target", "Open port"),
                "target": item.get("target", "unknown"),
                "summary": item.get("summary", ""),
                "evidence": evidence,
            }
        )
        unusual_port_count += 1
        if unusual_port_count >= 3:
            break
    for item in _dict_items(sections.get("candidate_cves"))[:3]:
        items.append(
            {
                "kind": "candidate CVE",
                "title": item.get("summary", "Candidate CVE"),
                "target": item.get("target", "unknown"),
                "summary": item.get("summary", ""),
                "evidence": item.get("evidence", {}),
            }
        )
    return items


def _dict_items(value: object) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _dict_value(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _string_items(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _html(value: object) -> str:
    return escape(str(value), quote=True)


def _extract_port_number(target: object, evidence: dict[str, Any]) -> int | None:
    port_value = evidence.get("port")
    if isinstance(port_value, int):
        return port_value
    target_str = str(target or "")
    if ":tcp/" in target_str:
        suffix = target_str.split(":tcp/", maxsplit=1)[1]
        if suffix.isdigit():
            return int(suffix)
    return None


def _is_unusual_open_port(port: int) -> bool:
    return port not in {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8000, 8080, 8443}
