"""
report_generator.py
--------------------
Part of the PyVscan Web Application Vulnerability Scanner.

Generates a dark-themed, responsive Bootstrap 5 executive HTML dashboard
from a list of discovered vulnerability findings.

Security note: all scanner-controlled and target-controlled strings
(URLs, titles, descriptions, PoC payloads, etc.) are HTML-escaped before
being embedded in the report. Because PyVscan's own test payloads
intentionally contain raw "<script>" tags, failing to escape them here
would make the *report itself* execute those payloads in the reviewer's
browser the moment it's opened. Escaping keeps the report a safe, static
read-only artifact.
"""

import html
import json


TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Application Vulnerability Scan Report</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- FontAwesome for Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --dark-bg: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
        }}

        body {{
            background-color: var(--dark-bg);
            color: var(--text-main);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding-bottom: 50px;
        }}

        .header-section {{
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
            border-bottom: 2px solid var(--border-color);
            padding: 40px 0;
            margin-bottom: 30px;
        }}

        .card-custom {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
        }}

        .severity-badge {{
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-radius: 6px;
            padding: 6px 12px;
        }}

        .bg-critical {{ background-color: var(--critical); color: white; }}
        .bg-high {{ background-color: var(--high); color: white; }}
        .bg-medium {{ background-color: var(--medium); color: #0f172a; }}
        .bg-low {{ background-color: var(--low); color: white; }}

        .border-critical {{ border-left: 5px solid var(--critical) !important; }}
        .border-high {{ border-left: 5px solid var(--high) !important; }}
        .border-medium {{ border-left: 5px solid var(--medium) !important; }}
        .border-low {{ border-left: 5px solid var(--low) !important; }}

        .stat-card {{
            text-align: center;
            padding: 20px;
            border-radius: 10px;
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
        }}

        .accordion-button {{
            background-color: var(--card-bg);
            color: var(--text-main);
            border: none;
        }}

        .accordion-button:not(.collapsed) {{
            background-color: #1e1b4b;
            color: var(--text-main);
            box-shadow: none;
        }}

        .accordion-item {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            margin-bottom: 10px;
            border-radius: 8px !important;
            overflow: hidden;
        }}

        pre {{
            background-color: #0f172a;
            color: #38bdf8;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            overflow-x: auto;
        }}

        .text-muted-custom {{
            color: var(--text-muted);
        }}
    </style>
</head>
<body>

    <!-- Header Section -->
    <div class="header-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <span class="badge bg-primary mb-2"><i class="fa-solid fa-shield-halved"></i> PenTesting Tool Artifact</span>
                    <h1 class="display-5 fw-bold">Vulnerability Scan Report</h1>
                    <p class="lead text-muted-custom">Target Site: <strong class="text-light">{target}</strong></p>
                </div>
                <div class="col-md-4 text-md-end text-muted-custom">
                    <p class="mb-1"><i class="fa-regular fa-calendar"></i> Scan Date: {scan_date}</p>
                    <p class="mb-0"><i class="fa-regular fa-clock"></i> Scanner Engine: PyVscan v1.0.0</p>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Executive Summary Dashboard -->
        <div class="row mb-4">
            <div class="col-12">
                <h3 class="mb-3 fw-bold text-light"><i class="fa-solid fa-chart-pie me-2"></i>Executive Summary</h3>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card-custom stat-card border-critical">
                    <div class="stat-number text-danger">{critical_count}</div>
                    <div class="text-muted-custom fw-semibold">CRITICAL</div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card-custom stat-card border-high">
                    <div class="stat-number text-warning" style="color: var(--high) !important;">{high_count}</div>
                    <div class="text-muted-custom fw-semibold">HIGH</div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card-custom stat-card border-medium">
                    <div class="stat-number text-warning" style="color: var(--medium) !important;">{medium_count}</div>
                    <div class="text-muted-custom fw-semibold">MEDIUM</div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card-custom stat-card border-low">
                    <div class="stat-number text-primary">{low_count}</div>
                    <div class="text-muted-custom fw-semibold">LOW</div>
                </div>
            </div>
        </div>

        <!-- System Information -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card-custom p-4">
                    <h5 class="fw-bold mb-3 text-light"><i class="fa-solid fa-circle-info me-2"></i>Scan Methodology & Info</h5>
                    <p class="text-muted-custom mb-0">
                        This automated security audit crawled the target web application dynamically, mapped its forms and input parameters, and performed non-destructive vulnerability probing against common flaws listed in the OWASP Top 10 (including SQL Injection, Cross-Site Scripting, and CSRF protection analysis).
                    </p>
                </div>
            </div>
        </div>

        <!-- Vulnerabilities List -->
        <div class="row">
            <div class="col-12 mb-3">
                <h3 class="fw-bold text-light"><i class="fa-solid fa-bug me-2"></i>Discovered Vulnerabilities</h3>
            </div>
            <div class="col-12">
                <div class="accordion" id="vulnAccordion">
                    {vulnerability_rows}
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap 5 JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

VULN_ACCORDION_TEMPLATE = """
<div class="accordion-item border-{severity_lower}">
    <h2 class="accordion-header" id="heading_{id}">
        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse_{id}" aria-expanded="false" aria-controls="collapse_{id}">
            <span class="badge bg-{severity_lower} severity-badge me-3">{severity}</span>
            <strong class="text-light">{title}</strong>
        </button>
    </h2>
    <div id="collapse_{id}" class="accordion-collapse collapse" aria-labelledby="heading_{id}" data-bs-parent="#vulnAccordion">
        <div class="accordion-body text-light">
            <div class="row">
                <div class="col-md-4 mb-3">
                    <h6 class="text-primary fw-bold"><i class="fa-solid fa-link me-2"></i>Vulnerable URL / Parameter</h6>
                    <code class="d-block p-2 bg-dark text-info rounded">{url}</code>
                </div>
                <div class="col-md-8 mb-3">
                    <h6 class="text-primary fw-bold"><i class="fa-solid fa-circle-exclamation me-2"></i>Description</h6>
                    <p class="text-muted-custom">{description}</p>
                </div>
            </div>
            <hr class="border-secondary">
            <div class="row">
                <div class="col-md-6 mb-3">
                    <h6 class="text-danger fw-bold"><i class="fa-solid fa-triangle-exclamation me-2"></i>Impact</h6>
                    <p class="text-muted-custom">{impact}</p>
                </div>
                <div class="col-md-6 mb-3">
                    <h6 class="text-success fw-bold"><i class="fa-solid fa-square-check me-2"></i>Remediation</h6>
                    <p class="text-muted-custom">{remediation}</p>
                </div>
            </div>
            {payload_block}
        </div>
    </div>
</div>
"""

# Severities we know how to badge/border. Anything else falls back to "low"
# styling so a malformed severity string never breaks CSS class lookup.
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _esc(value) -> str:
    """HTML-escape any value, coercing non-strings safely first."""
    return html.escape(str(value), quote=True)


def generate_report(target, scan_date, vulnerabilities, output_path="scan_report.html"):
    """
    Generates a beautiful HTML vulnerability report.

    vulnerabilities is a list of dicts:
    [
        {
            "title": "SQL Injection in Login Page",
            "severity": "Critical",
            "url": "http://target-site.com/login",
            "description": "User input is directly concatenated into SQL query.",
            "impact": "Full database access and admin takeover.",
            "remediation": "Use parameterized queries or ORMs.",
            "payload": "admin' OR '1'='1"   # optional
        },
        ...
    ]

    Returns the output_path on success.
    """
    critical_count = sum(1 for v in vulnerabilities if str(v.get('severity', '')).lower() == 'critical')
    high_count = sum(1 for v in vulnerabilities if str(v.get('severity', '')).lower() == 'high')
    medium_count = sum(1 for v in vulnerabilities if str(v.get('severity', '')).lower() == 'medium')
    low_count = sum(1 for v in vulnerabilities if str(v.get('severity', '')).lower() == 'low')

    vuln_rows = []
    for i, v in enumerate(vulnerabilities):
        raw_severity = str(v.get('severity', 'Low'))
        severity_lower = raw_severity.lower()
        if severity_lower not in _VALID_SEVERITIES:
            severity_lower = 'low'

        payload_block = ""
        payload = v.get('payload')
        if payload:
            payload_block = f'''
            <hr class="border-secondary">
            <h6 class="text-warning fw-bold"><i class="fa-solid fa-terminal me-2"></i>Proof of Concept / Payload Used</h6>
            <pre><code>{_esc(payload)}</code></pre>
            '''

        row_html = VULN_ACCORDION_TEMPLATE.format(
            id=i,
            severity=_esc(raw_severity.upper()),
            severity_lower=severity_lower,
            title=_esc(v.get('title', 'Untitled Finding')),
            url=_esc(v.get('url', '')),
            description=_esc(v.get('description', '')),
            impact=_esc(v.get('impact', '')),
            remediation=_esc(v.get('remediation', '')),
            payload_block=payload_block,
        )
        vuln_rows.append(row_html)

    if not vuln_rows:
        vuln_rows.append(
            '<div class="card-custom p-4 text-center text-muted-custom">'
            '<i class="fa-solid fa-circle-check fa-2x mb-2 text-success"></i>'
            '<p class="mb-0">No vulnerabilities were flagged during this scan.</p>'
            '</div>'
        )

    full_html = TEMPLATE.format(
        target=_esc(target),
        scan_date=_esc(scan_date),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        vulnerability_rows="\n".join(vuln_rows),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_html)

    print(f"[+] Report successfully saved to: {output_path}")
    return output_path


def generate_json_summary(target, scan_date, vulnerabilities):
    """
    Returns a compact JSON-serializable summary dict, useful for printing
    a quick terminal summary alongside the HTML report.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulnerabilities:
        sev = str(v.get('severity', '')).lower()
        if sev in counts:
            counts[sev] += 1

    return {
        "target": target,
        "scan_date": scan_date,
        "total_findings": len(vulnerabilities),
        "severity_counts": counts,
        "findings": [
            {
                "title": v.get("title"),
                "severity": v.get("severity"),
                "url": v.get("url"),
            }
            for v in vulnerabilities
        ],
    }


if __name__ == "__main__":
    # Quick self-test / demo when run directly: python report_generator.py
    demo_vulns = [
        {
            "title": "SQL Injection in Login Page",
            "severity": "Critical",
            "url": "http://example-lab.local/login?user=admin",
            "description": "The 'user' parameter is concatenated directly into a SQL query without sanitization.",
            "impact": "Full database access, authentication bypass, and potential admin takeover.",
            "remediation": "Use parameterized queries / prepared statements or an ORM instead of string concatenation.",
            "payload": "admin' OR '1'='1' --",
        },
        {
            "title": "Reflected XSS in Search Field",
            "severity": "High",
            "url": "http://example-lab.local/search?q=",
            "description": "The 'q' parameter is reflected back into the page without HTML-encoding.",
            "impact": "An attacker could hijack sessions or perform actions on behalf of a victim user.",
            "remediation": "HTML-encode all user input before rendering it in the response.",
            "payload": "<script>alert('XSS_TEST')</script>",
        },
        {
            "title": "Form Missing Anti-CSRF Token",
            "severity": "Medium",
            "url": "http://example-lab.local/account/update",
            "description": "The account update form does not include a CSRF token.",
            "impact": "An attacker could trick an authenticated user into submitting unwanted state-changing requests.",
            "remediation": "Add a per-session anti-CSRF token to all state-changing forms and validate it server-side.",
            "payload": "",
        },
    ]
    import datetime
    generate_report(
        target="http://example-lab.local",
        scan_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        vulnerabilities=demo_vulns,
        output_path="demo_report.html",
    )
