#!/usr/bin/env python3
"""
PyVscan - Web Application Vulnerability Scanner
=================================================
A modular, non-destructive web application vulnerability scanner built for
authorized penetration-testing portfolio use (lab targets such as DVWA,
OWASP Juice Shop, PortSwigger Web Security Academy, or your own local apps).

Pipeline:
    1. Crawler        -> discover pages, links, forms, and URL parameters
                          (depth-limited, strictly single-domain).
    2. SQLi Prober     -> error-based SQL injection detection.
    3. XSS Prober      -> reflected XSS detection.
    4. CSRF Analyzer   -> flags forms missing anti-CSRF tokens.
    5. Report Bridge   -> hands findings to report_generator.generate_report().

IMPORTANT / LEGAL & ETHICAL USE:
    Only run this tool against systems you own or are explicitly authorized
    to test (e.g. DVWA, Juice Shop, PortSwigger labs, your own local
    projects). Scanning third-party systems without permission is illegal in
    most jurisdictions. This tool performs non-destructive detection only -
    it does not exploit or extract data.

Usage:
    python pyvscan.py --url https://target-lab.local --depth 3
    python pyvscan.py --url https://target-lab.local --cookie "PHPSESSID=abc123"
    python pyvscan.py --url https://target-lab.local --json --output my_report.html
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlunparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependencies. Install them with:")
    print("    pip install requests beautifulsoup4")
    sys.exit(1)

import report_generator


# --------------------------------------------------------------------------
# Constants: payloads & signatures
# --------------------------------------------------------------------------

USER_AGENT = "PyVscan/1.0 (+Authorized-Security-Scanner; portfolio-project)"

REQUEST_TIMEOUT = 10  # seconds

SQLI_PAYLOADS = [
    "'",
    "\"",
    "1' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "1\" OR \"1\"=\"1",
]

XSS_PAYLOADS = [
    "<script>alert('XSS_TEST')</script>",
    "\"><script>alert('XSS_TEST')</script>",
    "'><script>alert('XSS_TEST')</script>",
]

# (Regex pattern, human-readable database engine label)
SQL_ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning:\s*mysql", "MySQL"),
    (r"mysqli?_(?:fetch|query|num_rows|error)", "MySQL"),
    (r"unclosed quotation mark after the character string", "Microsoft SQL Server"),
    (r"microsoft ole db provider for sql server", "Microsoft SQL Server"),
    (r"incorrect syntax near", "Microsoft SQL Server"),
    (r"sqlite3?\.OperationalError", "SQLite"),
    (r"sqlite_(?:error|exception)", "SQLite"),
    (r"unrecognized token", "SQLite"),
    (r"pg_query\(\)|pg_exec\(\)", "PostgreSQL"),
    (r"postgresql.*error", "PostgreSQL"),
    (r"ora-\d{5}", "Oracle"),
    (r"oracle error", "Oracle"),
    (r"sql syntax.*mysql|valid mysql result|check the manual that corresponds to your (mysql|mariadb)", "MySQL"),
]
_COMPILED_SQL_SIGNATURES = [(re.compile(p, re.IGNORECASE), label) for p, label in SQL_ERROR_SIGNATURES]

# Field-name hints that indicate an anti-CSRF token
CSRF_FIELD_HINTS = re.compile(r"csrf|xsrf|authenticity_token|_token|nonce", re.IGNORECASE)

# Input types we consider "testable" text-like fields for injection
TESTABLE_INPUT_TYPES = {"text", "search", "email", "url", "tel", "number", None, ""}


# --------------------------------------------------------------------------
# HTTP session helpers
# --------------------------------------------------------------------------

def build_session(cookie_arg=None, headers_arg=None):
    """Builds a requests.Session with a custom UA and optional cookie/headers."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    if cookie_arg:
        session.headers.update({"Cookie": cookie_arg})

    if headers_arg:
        # Accept either a JSON object string or a "Key: Value; Key2: Value2" string.
        parsed = None
        try:
            parsed = json.loads(headers_arg)
        except (json.JSONDecodeError, TypeError):
            parsed = {}
            for pair in headers_arg.split(";"):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    parsed[k.strip()] = v.strip()
        if isinstance(parsed, dict):
            session.headers.update(parsed)

    return session


def safe_get(session, url, **kwargs):
    try:
        return session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
    except requests.exceptions.RequestException as e:
        print(f"    [!] GET request failed for {url}: {e}")
        return None


def safe_post(session, url, **kwargs):
    try:
        return session.post(url, timeout=REQUEST_TIMEOUT, **kwargs)
    except requests.exceptions.RequestException as e:
        print(f"    [!] POST request failed for {url}: {e}")
        return None


# --------------------------------------------------------------------------
# Crawler
# --------------------------------------------------------------------------

class Crawler:
    """
    Breadth-first crawler restricted to the target's own domain (netloc),
    limited to `max_depth` link-hops from the seed URL.

    Discovers:
        - self.pages       : set of every page URL visited
        - self.forms       : list of form dicts (see extract_forms)
        - self.param_urls  : set of URLs that carry query-string parameters
    """

    def __init__(self, session, base_url, max_depth=3, delay=0.3):
        self.session = session
        self.base_url = base_url
        self.base_netloc = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.delay = delay

        self.visited = set()
        self.pages = set()
        self.forms = []
        self.param_urls = set()

    def _is_same_domain(self, url):
        try:
            return urlparse(url).netloc == self.base_netloc
        except ValueError:
            return False

    def crawl(self):
        queue = [(self.base_url, 0)]
        while queue:
            url, depth = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            resp = safe_get(self.session, url)
            time.sleep(self.delay)
            if resp is None or "text/html" not in resp.headers.get("Content-Type", "text/html"):
                continue

            self.pages.add(url)
            print(f"    [crawl] depth={depth} -> {url}")

            soup = BeautifulSoup(resp.text, "html.parser")

            # --- forms ---
            for form in soup.find_all("form"):
                parsed_form = self._parse_form(form, url)
                # Scope guard: some vulnerable-lab apps (e.g. Metasploitable2's
                # TWiki) ship pages with a form action hardcoded to an absolute,
                # off-target URL (like http://TWiki.org/...). Without this check
                # we'd happily submit SQLi/XSS test payloads to that external
                # host too, which breaks the "stay strictly in-scope" guarantee.
                # Skip any form whose action doesn't resolve to the target domain.
                if self._is_same_domain(parsed_form["action"]):
                    self.forms.append(parsed_form)
                else:
                    print(f"    [scope] skipping out-of-domain form action: {parsed_form['action']}")

            # --- links ---
            if depth < self.max_depth:
                for a in soup.find_all("a", href=True):
                    next_url = urljoin(url, a["href"].split("#")[0])
                    if not next_url.startswith(("http://", "https://")):
                        continue
                    if not self._is_same_domain(next_url):
                        continue
                    if urlparse(next_url).query:
                        self.param_urls.add(next_url)
                    if next_url not in self.visited:
                        queue.append((next_url, depth + 1))

            # a page's own URL may itself carry query parameters
            if urlparse(url).query:
                self.param_urls.add(url)

        return {
            "pages": self.pages,
            "forms": self.forms,
            "param_urls": self.param_urls,
        }

    @staticmethod
    def _parse_form(form_tag, page_url):
        action = form_tag.get("action") or page_url
        action_url = urljoin(page_url, action)
        method = (form_tag.get("method") or "get").lower()

        inputs = []
        for tag in form_tag.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            input_type = (tag.get("type") or ("textarea" if tag.name == "textarea" else "text")).lower()
            value = tag.get("value", "")
            inputs.append({"name": name, "type": input_type, "value": value})

        return {
            "page_url": page_url,
            "action": action_url,
            "method": method,
            "inputs": inputs,
        }


# --------------------------------------------------------------------------
# Form submission helper
# --------------------------------------------------------------------------

def _baseline_data(form):
    """Builds a dict of {field_name: original_or_placeholder_value}."""
    data = {}
    for field in form["inputs"]:
        if field["type"] in ("submit", "button", "image", "reset"):
            continue
        data[field["name"]] = field["value"] or "test"
    return data


def submit_form(session, form, data):
    if form["method"] == "post":
        return safe_post(session, form["action"], data=data)
    else:
        return safe_get(session, form["action"], params=data)


# --------------------------------------------------------------------------
# SQL Injection Prober
# --------------------------------------------------------------------------

def _check_sql_errors(text):
    for pattern, label in _COMPILED_SQL_SIGNATURES:
        if pattern.search(text):
            return label
    return None


def test_sql_injection_forms(session, forms, baseline_cache):
    findings = []
    testable_fields = [f for f in forms]

    for form in forms:
        base_data = _baseline_data(form)
        text_fields = [f for f in form["inputs"] if f["type"] in TESTABLE_INPUT_TYPES]

        for field in text_fields:
            for payload in SQLI_PAYLOADS:
                data = dict(base_data)
                data[field["name"]] = payload

                resp = submit_form(session, form, data)
                if resp is None:
                    continue

                db_label = _check_sql_errors(resp.text)
                if db_label:
                    findings.append({
                        "title": f"SQL Injection in '{field['name']}' field ({form['action']})",
                        "severity": "Critical",
                        "url": form["action"],
                        "description": (
                            f"The '{field['name']}' parameter on this "
                            f"{form['method'].upper()} form appears to be "
                            f"concatenated directly into a SQL query. Injecting "
                            f"the payload triggered a {db_label} error signature "
                            f"in the HTTP response."
                        ),
                        "impact": (
                            "An attacker could bypass authentication, read, "
                            "modify, or delete arbitrary database records, and "
                            "in some configurations achieve full database "
                            "server compromise."
                        ),
                        "remediation": (
                            "Use parameterized queries / prepared statements "
                            "(or a vetted ORM) for all database access. Never "
                            "build SQL strings via direct concatenation of "
                            "user input. Apply least-privilege database "
                            "accounts and enable a WAF as defense-in-depth."
                        ),
                        "payload": payload,
                    })
                    break  # one confirmed finding per field is enough
            else:
                continue
            break  # stop trying more payloads for this field once flagged

    return findings


def test_sql_injection_params(session, param_urls):
    findings = []
    for url in param_urls:
        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        for i, (name, _value) in enumerate(query_pairs):
            for payload in SQLI_PAYLOADS:
                mutated = list(query_pairs)
                mutated[i] = (name, payload)
                new_query = urlencode(mutated)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = safe_get(session, test_url)
                if resp is None:
                    continue

                db_label = _check_sql_errors(resp.text)
                if db_label:
                    findings.append({
                        "title": f"SQL Injection via URL parameter '{name}'",
                        "severity": "Critical",
                        "url": test_url,
                        "description": (
                            f"The URL parameter '{name}' appears to be used "
                            f"directly in a SQL query. Injecting the payload "
                            f"triggered a {db_label} error signature."
                        ),
                        "impact": (
                            "An attacker could bypass authentication, read or "
                            "modify database records, or compromise the "
                            "backend database."
                        ),
                        "remediation": (
                            "Use parameterized queries / prepared statements "
                            "for all database access and validate/allowlist "
                            "URL parameters server-side."
                        ),
                        "payload": payload,
                    })
                    break
            else:
                continue
            break

    return findings


# --------------------------------------------------------------------------
# XSS Prober
# --------------------------------------------------------------------------

def test_xss_forms(session, forms):
    findings = []
    for form in forms:
        base_data = _baseline_data(form)
        text_fields = [f for f in form["inputs"] if f["type"] in TESTABLE_INPUT_TYPES]

        for field in text_fields:
            for payload in XSS_PAYLOADS:
                data = dict(base_data)
                data[field["name"]] = payload

                resp = submit_form(session, form, data)
                if resp is None:
                    continue

                if payload in resp.text:
                    findings.append({
                        "title": f"Reflected XSS in '{field['name']}' field ({form['action']})",
                        "severity": "High",
                        "url": form["action"],
                        "description": (
                            f"The '{field['name']}' parameter on this "
                            f"{form['method'].upper()} form is reflected back "
                            f"into the HTML response without encoding, "
                            f"allowing injected script to execute."
                        ),
                        "impact": (
                            "An attacker could hijack user sessions, steal "
                            "cookies/credentials, deface the page, or perform "
                            "actions on behalf of a victim user (session "
                            "riding)."
                        ),
                        "remediation": (
                            "HTML-encode all user-supplied output before "
                            "rendering it, use context-aware auto-escaping "
                            "template engines, and set a strict "
                            "Content-Security-Policy header."
                        ),
                        "payload": payload,
                    })
                    break
            else:
                continue
            break

    return findings


def test_xss_params(session, param_urls):
    findings = []
    for url in param_urls:
        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        for i, (name, _value) in enumerate(query_pairs):
            for payload in XSS_PAYLOADS:
                mutated = list(query_pairs)
                mutated[i] = (name, payload)
                new_query = urlencode(mutated)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = safe_get(session, test_url)
                if resp is None:
                    continue

                if payload in resp.text:
                    findings.append({
                        "title": f"Reflected XSS via URL parameter '{name}'",
                        "severity": "High",
                        "url": test_url,
                        "description": (
                            f"The URL parameter '{name}' is reflected back "
                            f"into the HTML response without encoding."
                        ),
                        "impact": (
                            "An attacker could craft a malicious link that "
                            "executes arbitrary JavaScript in a victim's "
                            "browser session."
                        ),
                        "remediation": (
                            "HTML-encode all reflected user input and adopt "
                            "a strict Content-Security-Policy."
                        ),
                        "payload": payload,
                    })
                    break
            else:
                continue
            break

    return findings


# --------------------------------------------------------------------------
# CSRF Analyzer
# --------------------------------------------------------------------------

def analyze_csrf(forms):
    findings = []
    for form in forms:
        if form["method"] != "post":
            # CSRF tokens matter for state-changing (POST) requests
            continue

        has_token = any(CSRF_FIELD_HINTS.search(f["name"]) for f in form["inputs"])
        if not has_token:
            findings.append({
                "title": f"Missing Anti-CSRF Token ({form['action']})",
                "severity": "Medium",
                "url": form["action"],
                "description": (
                    "This POST form does not appear to include a "
                    "recognizable anti-CSRF token field (e.g. csrf_token, "
                    "authenticity_token, _token, nonce)."
                ),
                "impact": (
                    "An attacker could craft a malicious page that submits "
                    "this form on behalf of an authenticated victim without "
                    "their consent (e.g. changing account details or "
                    "performing unwanted actions)."
                ),
                "remediation": (
                    "Generate a unique, unpredictable per-session (or "
                    "per-request) CSRF token, embed it as a hidden field in "
                    "the form, and validate it server-side on submission. "
                    "Consider SameSite=Strict/Lax cookies as additional "
                    "defense-in-depth."
                ),
                "payload": "",
            })
    return findings


# --------------------------------------------------------------------------
# CLI / Orchestration
# --------------------------------------------------------------------------

BANNER = r"""
  _____       __     __
 |  __ \      \ \   / /
 | |__) |   _  \ \_/ /__ ___ __ _ _ __
 |  ___/ | | |  \   / __/ __/ _` | '_ \
 | |   | |_| |   | |\__ \ (_| (_| | | | |
 |_|    \__, |   |_||___/\___\__,_|_| |_|
         __/ |
        |___/    PyVscan v1.0.0 - Web App Vulnerability Scanner
"""

CONSENT_NOTICE = """
[!] LEGAL / AUTHORIZED-USE NOTICE
    Only scan systems you own or are explicitly authorized to test
    (e.g. DVWA, OWASP Juice Shop, PortSwigger labs, your own local apps).
    Scanning third-party systems without written permission may be illegal.
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="PyVscan - Web Application Vulnerability Scanner (authorized-use only)."
    )
    parser.add_argument("--url", required=True, help="Target base URL to scan, e.g. http://localhost:8080")
    parser.add_argument("--depth", type=int, default=3, help="Max crawl depth (default: 3)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--cookie", help="Raw Cookie header value for authenticated scanning, e.g. 'PHPSESSID=abc123'")
    parser.add_argument("--headers", help="Extra headers as JSON or 'Key: Value; Key2: Value2'")
    parser.add_argument("--output", default="final_security_report.html", help="HTML report output path")
    parser.add_argument("--json", action="store_true", help="Also print a JSON summary to stdout")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip the interactive authorization confirmation prompt")
    return parser.parse_args()


def confirm_authorization(args):
    if args.yes:
        return True
    print(CONSENT_NOTICE)
    try:
        answer = input(f"Type YES to confirm you are authorized to scan '{args.url}': ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.upper() == "YES"


def main():
    args = parse_args()

    print(BANNER)

    if not confirm_authorization(args):
        print("[!] Authorization not confirmed. Exiting without scanning.")
        sys.exit(1)

    if not args.url.startswith(("http://", "https://")):
        args.url = "http://" + args.url

    session = build_session(cookie_arg=args.cookie, headers_arg=args.headers)

    print(f"\n[1/4] Crawling {args.url} (max depth {args.depth}) ...")
    crawler = Crawler(session, args.url, max_depth=args.depth, delay=args.delay)
    try:
        results = crawler.crawl()
    except KeyboardInterrupt:
        print("\n[!] Crawl interrupted by user. Proceeding with what was discovered so far.")
        results = {"pages": crawler.pages, "forms": crawler.forms, "param_urls": crawler.param_urls}

    print(f"    -> {len(results['pages'])} page(s), {len(results['forms'])} form(s), "
          f"{len(results['param_urls'])} parameterized URL(s) discovered.\n")

    vulnerabilities = []

    print("[2/4] Running SQL Injection probes ...")
    vulnerabilities += test_sql_injection_forms(session, results["forms"], baseline_cache={})
    vulnerabilities += test_sql_injection_params(session, results["param_urls"])

    print("[3/4] Running Reflected XSS probes ...")
    vulnerabilities += test_xss_forms(session, results["forms"])
    vulnerabilities += test_xss_params(session, results["param_urls"])

    print("[4/4] Running CSRF token analysis ...")
    vulnerabilities += analyze_csrf(results["forms"])

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n[+] Scan complete. {len(vulnerabilities)} finding(s) identified.")
    report_generator.generate_report(
        target=args.url,
        scan_date=scan_date,
        vulnerabilities=vulnerabilities,
        output_path=args.output,
    )

    if args.json:
        summary = report_generator.generate_json_summary(args.url, scan_date, vulnerabilities)
        print("\n----- JSON SUMMARY -----")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
