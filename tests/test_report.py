from scanner.report import render_html_report


def test_render_html_report_includes_scanning_notes():
    summary = {
        "target": "example.com",
        "execution_notes": {
            "calibrations": [
                {
                    "module": "dir_enum",
                    "base_url": "http://php.example.com/",
                    "derived_extensions": [".php"],
                    "tech_evidence": ["PHP"],
                    "using_default_extensions": False
                }
            ]
        }
    }
    html = render_html_report(summary)
    assert "Scanning Intelligence / Tech Notes" in html
    assert "http://php.example.com/" in html
    assert "Extensions:</strong> .php" in html
    assert "Based on tech:</strong> PHP" in html

def test_render_html_report_omits_scanning_notes_if_empty():
    summary = {
        "target": "example.com",
        "execution_notes": {
            "calibrations": []
        }
    }
    html = render_html_report(summary)
    assert "Scanning Intelligence / Tech Notes" not in html


def test_render_html_report_includes_candidate_cves():
    summary = {
        "target": "example.com",
        "sections": {
            "candidate_cves": [
                {
                    "summary": "Candidate CVE-2021-41773 matched",
                    "target": "example.com",
                    "status": "candidate",
                    "module": "cve_match",
                    "evidence": {
                        "cve_id": "CVE-2021-41773",
                        "matched_field": "webserver",
                        "matched_value": "Apache/2.4.49",
                        "confidence": 0.98
                    }
                }
            ]
        }
    }
    html = render_html_report(summary)
    assert "Inferred Candidate CVEs" in html
    assert "CVE-2021-41773" in html
    assert "Apache/2.4.49" in html
    assert "confidence 0.98" in html


def test_render_html_report_includes_host_centric_detail():
    summary = {
        "target": "example.com",
        "host_groups": [
            {
                "host": "app.example.com",
                "alive": True,
                "ip_addresses": ["203.0.113.10"],
                "technologies": ["nginx", "React"],
                "open_ports_count": 1,
                "directory_findings_count": 1,
                "candidate_cve_count": 1,
                "auth_required_path_count": 1,
                "representative_ports": [
                    {"protocol": "tcp", "port": 8443, "service": "https", "product": "nginx", "version": "1.25"}
                ],
                "representative_paths": [
                    {"target": "https://app.example.com/admin", "summary": "Observed path", "status_code": 403}
                ],
                "candidate_cves": [
                    {
                        "summary": "Candidate CVE-2024-9999",
                        "evidence": {"cve_id": "CVE-2024-9999", "candidate_only": True},
                    }
                ],
                "subdomains": [
                    {"target": "api.example.com", "summary": "Discovered subdomain"}
                ],
                "artifacts": [{"path": "/tmp/task.json"}],
            }
        ],
    }
    html = render_html_report(summary)
    assert "Host-Centric Detail" in html
    assert "app.example.com" in html
    assert "Representative Ports" in html
    assert "Representative Paths" in html
    assert "Candidate only. Review evidence before triage." in html
