def foo():
    if True:
        print("hi")
    return 1
# 🛡️ PyVscan

### An Automated OWASP Top 10 Web Application Security Auditor

PyVscan is a modular, command-line Python scanner that crawls a target web
application, maps its forms and URL parameters, and probes for three of the
most commonly exploited flaws in the OWASP Top 10 - **SQL Injection**,
**Reflected XSS**, and **missing CSRF protection** - then compiles the
findings into a polished, dark-themed Bootstrap 5 executive dashboard.

---

## Why This Project Exists

Most junior cybersecurity portfolios lean on generic exercises - password
strength checkers, keyloggers, port scanners - that don't tell a hiring
manager anything about business impact. A vulnerability scanner is
different: it maps directly to a real cost center.

Manual web application security audits are slow, expensive, and often out
of reach for small and medium-sized businesses, which is exactly why so
many of them get breached through basic, well-known flaws that a
five-minute automated scan would have caught. PyVscan demonstrates how a
lightweight, automated internal scanner can give a business continuous,
low-cost visibility into its own attack surface - catching the SQLi/XSS/CSRF
class of bugs *before* an attacker does, and handing developers a
prioritized, plain-English remediation roadmap instead of a wall of raw
HTTP logs.

---

## Core Features

- **Domain-scoped crawler** - recursively maps a site's pages, forms, and
  input fields up to a configurable depth, while strictly refusing to
  follow links off the target domain (no accidental out-of-scope scanning).
- **SQL Injection detection** - injects classic error-based payloads into
  every form field and URL parameter, and fingerprints the response for
  MySQL, PostgreSQL, SQLite, Microsoft SQL Server, and Oracle error
  signatures.
- **Reflected XSS detection** - injects script-tag payloads and confirms
  whether they come back unescaped in the HTML response.
- **CSRF analysis** - flags any state-changing (POST) form that has no
  recognizable anti-CSRF token field.
- **Authenticated scanning support** - pass an active session via
  `--cookie` (or arbitrary extra headers) to scan pages behind a login wall,
  without building a full login/session-management flow.
- **Executive HTML dashboard** - a single self-contained, dark-themed
  Bootstrap 5 report with severity-coded summary counters and a collapsible
  breakdown per finding (URL, description, business impact, remediation,
  and the exact PoC payload used).
- **Non-destructive by design** - every check *detects and proves* a flaw
  exists; none of them attempt real exploitation, data extraction, or
  destructive requests.

---

## Installation & Usage

```bash
git clone https://github.com/<your-username>/pyvscan.git
cd pyvscan
pip install -r requirements.txt
```

Run a basic scan:

```bash
python pyvscan.py --url http://localhost:8080
```

Limit crawl depth and scan an authenticated area using an active session
cookie:

```bash
python pyvscan.py --url http://localhost:8080 --depth 2 --cookie "PHPSESSID=abc123xyz"
```

Custom output path and a JSON summary printed to the terminal:

```bash
python pyvscan.py --url http://localhost:8080 --output my_report.html --json
```

| Flag | Description | Default |
|---|---|---|
| `--url` | Target base URL to scan (required) | - |
| `--depth` | Max crawl depth | `3` |
| `--cookie` | Raw `Cookie` header value for authenticated scanning | none |
| `--headers` | Extra headers as JSON or `"Key: Value; Key2: Value2"` | none |
| `--output` | HTML report output path | `final_security_report.html` |
| `--json` | Also print a JSON findings summary to stdout | off |
| `--yes` / `-y` | Skip the interactive authorized-use confirmation prompt | off |

Open the generated `final_security_report.html` in any browser to view the
executive dashboard.

---

## Sample Report Preview

> 📸 *Add a screenshot of your generated `final_security_report.html`
> dashboard here* - e.g. `docs/screenshot-dashboard.png` - showing the
> Critical/High/Medium/Low summary tiles and an expanded finding accordion.
> A live demo GIF works well here too.

```
┌─────────────────────────────────────────────────────────┐
│  Vulnerability Scan Report          Target: localhost:8080│
│  ──────────────────────────────────────────────────────  │
│   [ 1 ]        [ 1 ]        [ 1 ]        [ 0 ]            │
│  CRITICAL      HIGH        MEDIUM        LOW               │
│  ──────────────────────────────────────────────────────  │
│  ▸ CRITICAL  SQL Injection in 'username' field             │
│  ▸ HIGH      Reflected XSS via URL parameter 'q'            │
│  ▸ MEDIUM    Missing Anti-CSRF Token                         │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
pyvscan/
├── pyvscan.py            # CLI entry point + crawler + probers
├── report_generator.py   # Bootstrap 5 HTML dashboard builder
├── requirements.txt      # Python dependencies
├── .gitignore
└── README.md
```

---

## ⚠️ Disclaimer - Authorized Use Only

**This tool is strictly for authorized security assessments and
local/lab environments.** Only run PyVscan against systems you own or have
**explicit written permission** to test - for example:

- [DVWA](https://github.com/digininja/DVWA)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) labs
- Your own local development projects

Scanning third-party systems without authorization is illegal in most
jurisdictions and may violate the Computer Fraud and Abuse Act (or your
local equivalent). The author accepts no liability for misuse. PyVscan
prints a legal notice and requires explicit confirmation before every scan
(bypass only with `--yes` once you are certain you're authorized).

---

## Resume Bullet

> Engineered a custom modular Web Application Vulnerability Scanner in
> Python that automated the detection of SQLi, XSS, and CSRF flaws. Built a
> reporting system translating raw technical exposures into prioritized,
> business-focused executive threat briefings with remediation roadmaps for
> stakeholders.
