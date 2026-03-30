#!/usr/bin/env python3
"""
HTTP Security Headers Auditor
==============================
Audits a domain's HTTP security response headers over HTTPS:
- HDR-00: Connectivity (can we connect at all?)
- HDR-01: X-Frame-Options (absent = FAIL; ALLOWFROM = WARN)
- HDR-02: X-Content-Type-Options (nosniff required)
- HDR-03: Content-Security-Policy (absent = FAIL; unsafe-inline/eval = WARN)
- HDR-04: Referrer-Policy (unsafe-url/origin = FAIL; absent = FAIL)
- HDR-05: Permissions-Policy (absent = WARN)

Usage:
    python3 http_headers_auditor.py --domain acme.ie
    python3 http_headers_auditor.py --domain acme.ie --port 8443
    python3 http_headers_auditor.py --domain acme.ie --format all --output http_headers_report
"""

import argparse
import csv
import html as html_lib
import http.client
import json
import logging
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


# ── HTTPS wrapper (thin — mock this in tests) ─────────────────────────────────

def get_http_headers(host: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """
    Open HTTPS connection to host:port, send GET /, return response headers.

    Returns dict with key:
        headers  - response headers with names lowercased

    Returns None on ConnectionRefusedError, socket.timeout, socket.gaierror,
    http.client.HTTPException, or OSError.
    """
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"Host": host, "Connection": "close"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return {"headers": headers}
    except (ConnectionRefusedError, socket.timeout, socket.gaierror,
            http.client.HTTPException, OSError):
        return None


# ── Finding helper ─────────────────────────────────────────────────────────────

def _finding(check_id: str, name: str, status: str, risk_level: str,
             severity_score: int, detail: str, remediation: str) -> dict:
    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "risk_level": risk_level,
        "severity_score": severity_score if status == "FAIL" else 0,
        "detail": detail,
        "remediation": remediation,
        "pillar": "headers",
        "cis_control": "CIS 4",
    }


# ── HDR-00: Connectivity ───────────────────────────────────────────────────────

def check_connectivity(conn: Optional[dict], domain: str, port: int) -> dict:
    """HDR-00: Verify we can establish an HTTPS connection to domain:port."""
    if conn is None:
        return _finding(
            "HDR-00", "HTTP Headers Connectivity", "FAIL", "CRITICAL", 10,
            f"Could not establish HTTPS connection to {domain}:{port}. "
            "Host may be unreachable, port closed, or TLS not enabled.",
            "Verify the server is running and accessible on port 443. "
            "Check firewall rules and that TLS is configured.",
        )
    return _finding(
        "HDR-00", "HTTP Headers Connectivity", "PASS", "CRITICAL", 0,
        f"HTTPS connection established to {domain}:{port}", "",
    )


# ── HDR-01: X-Frame-Options ───────────────────────────────────────────────────

_SAFE_XFO = frozenset({"deny", "sameorigin"})


def check_x_frame_options(conn: dict) -> dict:
    """HDR-01: X-Frame-Options header — DENY or SAMEORIGIN required."""
    val = conn.get("headers", {}).get("x-frame-options", "").strip()
    if not val:
        return _finding(
            "HDR-01", "X-Frame-Options", "FAIL", "HIGH", 7,
            "X-Frame-Options header is absent. The site may be embeddable in iframes, "
            "enabling clickjacking attacks.",
            "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all responses. "
            "Prefer Content-Security-Policy frame-ancestors for modern browsers.",
        )
    if val.lower() in _SAFE_XFO:
        return _finding(
            "HDR-01", "X-Frame-Options", "PASS", "HIGH", 0,
            f"X-Frame-Options: {val}", "",
        )
    if val.lower().startswith("allowfrom"):
        return _finding(
            "HDR-01", "X-Frame-Options", "WARN", "HIGH", 0,
            f"X-Frame-Options: {val} — ALLOWFROM is deprecated and ignored by Chrome and Firefox.",
            "Replace with: Content-Security-Policy: frame-ancestors 'self' https://trusted.com",
        )
    return _finding(
        "HDR-01", "X-Frame-Options", "FAIL", "HIGH", 7,
        f"X-Frame-Options value '{val}' is not recognised. Expected DENY or SAMEORIGIN.",
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    )


# ── HDR-02: X-Content-Type-Options ───────────────────────────────────────────

def check_x_content_type_options(conn: dict) -> dict:
    """HDR-02: X-Content-Type-Options must be 'nosniff'."""
    val = conn.get("headers", {}).get("x-content-type-options", "").strip().lower()
    if val == "nosniff":
        return _finding(
            "HDR-02", "X-Content-Type-Options", "PASS", "MEDIUM", 0,
            "X-Content-Type-Options: nosniff", "",
        )
    if not val:
        return _finding(
            "HDR-02", "X-Content-Type-Options", "FAIL", "MEDIUM", 5,
            "X-Content-Type-Options header is absent. Browsers may MIME-sniff responses, "
            "enabling content injection attacks.",
            "Add 'X-Content-Type-Options: nosniff' to all responses.",
        )
    return _finding(
        "HDR-02", "X-Content-Type-Options", "FAIL", "MEDIUM", 5,
        f"X-Content-Type-Options value '{val}' is not 'nosniff'.",
        "Set X-Content-Type-Options to exactly 'nosniff'.",
    )


# ── HDR-03: Content-Security-Policy ──────────────────────────────────────────

_WEAK_CSP = frozenset({"'unsafe-inline'", "'unsafe-eval'"})


def check_content_security_policy(conn: dict) -> dict:
    """HDR-03: CSP must be present and not contain unsafe directives."""
    val = conn.get("headers", {}).get("content-security-policy", "").strip()
    if not val:
        return _finding(
            "HDR-03", "Content-Security-Policy", "FAIL", "HIGH", 8,
            "Content-Security-Policy header is absent. No XSS mitigation policy is enforced.",
            "Define a Content-Security-Policy that restricts script sources. "
            "Start with: Content-Security-Policy: default-src 'self'",
        )
    weak = [kw for kw in _WEAK_CSP if kw in val]
    if weak:
        return _finding(
            "HDR-03", "Content-Security-Policy", "WARN", "HIGH", 0,
            f"Content-Security-Policy present but contains {', '.join(sorted(weak))}, "
            "which weakens XSS protection.",
            "Remove 'unsafe-inline' and 'unsafe-eval'. "
            "Use nonces or hashes for inline scripts instead.",
        )
    return _finding(
        "HDR-03", "Content-Security-Policy", "PASS", "HIGH", 0,
        f"Content-Security-Policy present without unsafe directives: {val[:120]}", "",
    )


# ── HDR-04: Referrer-Policy ───────────────────────────────────────────────────

_SAFE_REFERRER = frozenset({
    "no-referrer",
    "no-referrer-when-downgrade",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
    "origin-when-cross-origin",
})


def check_referrer_policy(conn: dict) -> dict:
    """HDR-04: Referrer-Policy must be present and not leak full URLs cross-site."""
    val = conn.get("headers", {}).get("referrer-policy", "").strip().lower()
    if not val:
        return _finding(
            "HDR-04", "Referrer-Policy", "FAIL", "MEDIUM", 4,
            "Referrer-Policy header is absent. Browsers use their default policy, "
            "which may send full URLs as referrers to third-party sites.",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' to all responses.",
        )
    if val in _SAFE_REFERRER:
        return _finding(
            "HDR-04", "Referrer-Policy", "PASS", "MEDIUM", 0,
            f"Referrer-Policy: {val}", "",
        )
    return _finding(
        "HDR-04", "Referrer-Policy", "FAIL", "MEDIUM", 4,
        f"Referrer-Policy: '{val}' leaks full URLs to third-party origins.",
        "Use 'strict-origin-when-cross-origin' or 'no-referrer'.",
    )


# ── HDR-05: Permissions-Policy ───────────────────────────────────────────────

def check_permissions_policy(conn: dict) -> dict:
    """HDR-05: Permissions-Policy should be present to restrict browser features."""
    val = conn.get("headers", {}).get("permissions-policy", "").strip()
    if val:
        return _finding(
            "HDR-05", "Permissions-Policy", "PASS", "LOW", 0,
            f"Permissions-Policy present: {val[:120]}", "",
        )
    return _finding(
        "HDR-05", "Permissions-Policy", "WARN", "LOW", 0,
        "Permissions-Policy header is absent. Browser features (camera, microphone, "
        "geolocation) are unrestricted.",
        "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to disable "
        "unused browser features.",
    )


# ── Orchestration ─────────────────────────────────────────────────────────────

_SKIP = "Could not connect — skipped."


def run_audit(domain: str, port: int = 443) -> list:
    """Run all HTTP header checks for domain:port. Always returns exactly 6 findings."""
    conn = get_http_headers(domain, port)
    findings = [check_connectivity(conn, domain, port)]
    if conn is None:
        findings.extend([
            _finding("HDR-01", "X-Frame-Options",         "FAIL", "HIGH",   0, _SKIP, ""),
            _finding("HDR-02", "X-Content-Type-Options",  "FAIL", "MEDIUM", 0, _SKIP, ""),
            _finding("HDR-03", "Content-Security-Policy", "FAIL", "HIGH",   0, _SKIP, ""),
            _finding("HDR-04", "Referrer-Policy",         "FAIL", "MEDIUM", 0, _SKIP, ""),
            _finding("HDR-05", "Permissions-Policy",      "FAIL", "LOW",    0, _SKIP, ""),
        ])
        return findings
    findings.extend([
        check_x_frame_options(conn),
        check_x_content_type_options(conn),
        check_content_security_policy(conn),
        check_referrer_policy(conn),
        check_permissions_policy(conn),
    ])
    return findings


def compute_overall_risk(findings: list) -> tuple:
    """Return (overall_risk_level, total_severity_score) from findings list."""
    score = sum(f.get("severity_score", 0) for f in findings)
    has_critical = any(
        f.get("risk_level") == "CRITICAL" and f.get("status") == "FAIL"
        for f in findings
    )
    if has_critical or score >= 10:
        return "CRITICAL", score
    if score >= 6:
        return "HIGH", score
    if score >= 3:
        return "MEDIUM", score
    return "LOW", score


# ── Output ─────────────────────────────────────────────────────────────────────

def write_json(report: dict, prefix: str) -> None:
    path = Path(f"{prefix}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info("JSON report: %s", path)


def write_csv(findings: list, prefix: str) -> None:
    path = Path(f"{prefix}.csv")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not findings:
        return
    fields = ["check_id", "name", "status", "risk_level", "severity_score", "detail", "remediation", "cis_control"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)
    log.info("CSV report: %s", path)


def write_html(report: dict, prefix: str) -> None:
    path = Path(f"{prefix}.html")
    path.parent.mkdir(parents=True, exist_ok=True)
    domain = report.get("domain", "")
    summary = report.get("summary", {})
    overall = summary.get("overall_risk", "UNKNOWN")
    score = summary.get("severity_score", 0)
    generated = report.get("generated_at", "")

    RISK_COLOURS = {
        "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107", "LOW": "#28a745",
    }
    STATUS_COLOURS = {"PASS": "#28a745", "FAIL": "#dc3545", "WARN": "#fd7e14"}
    risk_colour = RISK_COLOURS.get(overall, "#6c757d")

    findings = report.get("findings", [])
    total = len(findings)
    n_fail = sum(1 for f in findings if f.get("status") == "FAIL")
    n_warn = sum(1 for f in findings if f.get("status") == "WARN")
    n_pass = sum(1 for f in findings if f.get("status") == "PASS")

    fail_colour = "#dc3545" if n_fail > 0 else "#6c757d"
    warn_colour = "#fd7e14" if n_warn > 0 else "#6c757d"

    rows = ""
    for f in findings:
        st = f.get("status", "")
        rl = f.get("risk_level", "")
        sc = STATUS_COLOURS.get(st, "#6c757d")
        rc = RISK_COLOURS.get(rl, "#6c757d")
        rows += (
            f"<tr>"
            f"<td>{html_lib.escape(f.get('check_id', ''))}</td>"
            f"<td>{html_lib.escape(f.get('name', ''))}</td>"
            f"<td><span style='background:{sc};color:#fff;padding:2px 10px;"
            f"border-radius:10px;font-weight:700;font-size:0.85em'>"
            f"{html_lib.escape(st)}</span></td>"
            f"<td><span style='background:{rc};color:#fff;padding:2px 10px;"
            f"border-radius:10px;font-weight:700;font-size:0.85em'>"
            f"{html_lib.escape(rl)}</span></td>"
            f"<td>{html_lib.escape(f.get('detail', ''))}</td>"
            f"<td>{html_lib.escape(f.get('remediation', ''))}</td>"
            f"</tr>\n"
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HTTP Security Headers Audit \u2014 {html_lib.escape(domain)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0 0 8px; font-size: 1.8em; }}
  .header p {{ margin: 0; opacity: 0.85; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 20px 30px; flex: 1; min-width: 120px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}
  .card .num {{ font-size: 2.4em; font-weight: bold; }}
  .card .label {{ color: #666; font-size: 0.88em; margin-top: 4px; }}
  .table-wrap {{ padding: 0 40px 40px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  th {{ background: #1a1a2e; color: white; padding: 12px 15px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 10px 15px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8f9ff; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <h1>\U0001f510 HTTP Security Headers Audit</h1>
  <p><strong>Domain:</strong> {html_lib.escape(domain)} &nbsp;|&nbsp;
     <span style="background:{risk_colour};color:#fff;padding:3px 12px;border-radius:12px;font-weight:700">{html_lib.escape(overall)}</span>
     &nbsp;|&nbsp; Score: {score} &nbsp;|&nbsp; Generated: {html_lib.escape(generated)}</p>
</div>
<div class="summary">
  <div class="card"><div class="num" style="color:#3498db">{total}</div><div class="label">Total Checks</div></div>
  <div class="card"><div class="num" style="color:{fail_colour}">{n_fail}</div><div class="label">FAIL</div></div>
  <div class="card"><div class="num" style="color:{warn_colour}">{n_warn}</div><div class="label">WARN</div></div>
  <div class="card"><div class="num" style="color:#28a745">{n_pass}</div><div class="label">PASS</div></div>
</div>
<div class="table-wrap">
<table>
<thead><tr><th>ID</th><th>Check</th><th>Status</th><th>Risk</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
<div class="footer">For internal use only &nbsp;|&nbsp; SecurityAuditScripts</div>
</body>
</html>"""

    path.write_text(html_content)
    log.info("HTML report: %s", path)


# ── Entry point ────────────────────────────────────────────────────────────────

def run(domain: str, port: int, output_prefix: str, fmt: str) -> dict:
    """Run all HTTP header checks for domain and write reports. Returns report dict."""
    findings = run_audit(domain, port)
    overall_risk, score = compute_overall_risk(findings)

    report = {
        "domain": domain,
        "port": port,
        "generated_at": NOW.isoformat(),
        "summary": {
            "overall_risk": overall_risk,
            "severity_score": score,
            "connected": any(
                f["check_id"] == "HDR-00" and f["status"] == "PASS" for f in findings
            ),
        },
        "findings": findings,
        "pillar": "headers",
        "risk_level": overall_risk,
    }

    if fmt in ("json", "all"):
        write_json(report, output_prefix)
    if fmt in ("csv", "all"):
        write_csv(findings, output_prefix)
    if fmt in ("html", "all"):
        write_html(report, output_prefix)
    if fmt == "stdout":
        print(json.dumps(report, indent=2, default=str))

    col = {
        "CRITICAL": "\033[91m", "HIGH": "\033[33m",
        "MEDIUM": "\033[93m", "LOW": "\033[92m",
    }.get(overall_risk, "")
    end = "\033[0m"
    print(f"\n{'='*44}")
    print(f"  HTTP HEADERS AUDIT -- {domain}:{port}")
    print(f"{'-'*44}")
    print(f"  Overall risk:    {col}{overall_risk}{end}")
    print(f"  Score:           {score}")
    print(f"  Connected:       {'Yes' if report['summary']['connected'] else 'No'}")
    print(f"{'='*44}\n")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Security Headers Auditor")
    parser.add_argument("--domain", required=True, help="Domain to audit (e.g. acme.ie)")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("--output", "-o", default="http_headers_report",
                        help="Output filename prefix (default: http_headers_report)")
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "html", "all", "stdout"],
        default="json",
        help="Output format (default: json)",
    )
    args = parser.parse_args()
    run(args.domain, args.port, args.output, args.format)
