#!/usr/bin/env python3
"""
Linux Sysctl Hardening Auditor
===============================
Checks kernel security parameters via sysctl for CIS Benchmark compliance:
- Network hardening (IP forwarding, ICMP redirects, source routing, spoofing)
- TCP hardening (SYN cookies, timestamps)
- Kernel hardening (ASLR, dmesg restriction, ptrace scope, core dumps)
- Filesystem hardening (protected hardlinks/symlinks, SUID coredumps)

Usage:
    sudo python3 linux_sysctl_auditor.py
    python3 linux_sysctl_auditor.py --format html --output sysctl_report
    python3 linux_sysctl_auditor.py --format all
"""

import os
import sys
import json
import csv
import socket
import argparse
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


# ── Thin wrapper functions (for easy mocking in tests) ────────────────────────

def run_command(cmd):
    """Run command, return (stdout, returncode). Returns ('', 1) on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout, r.returncode
    except Exception:
        return '', 1


def read_file(path):
    """Read file content, return empty string if not readable."""
    try:
        return Path(path).read_text(errors='replace')
    except (OSError, PermissionError):
        return ''


# ── Sysctl reader ─────────────────────────────────────────────────────────────

def read_sysctl(param):
    """Return sysctl value as string, or None if unavailable."""
    stdout, rc = run_command(['sysctl', '-n', param])
    if rc == 0:
        return stdout.strip()
    return None


# ── CIS Benchmark parameter table ─────────────────────────────────────────────

SYSCTL_CHECKS = [
    # (param_name, expected_value, severity_if_wrong, description)
    # Network - IP routing
    ("net.ipv4.ip_forward",                      "0", "HIGH",   "IP forwarding disabled (router mode off)"),
    ("net.ipv6.conf.all.forwarding",             "0", "HIGH",   "IPv6 forwarding disabled"),
    # Network - ICMP redirects
    ("net.ipv4.conf.all.send_redirects",         "0", "MEDIUM", "ICMP redirects sending disabled"),
    ("net.ipv4.conf.default.send_redirects",     "0", "MEDIUM", "ICMP redirects sending disabled (default)"),
    ("net.ipv4.conf.all.accept_redirects",       "0", "MEDIUM", "ICMP redirect acceptance disabled"),
    ("net.ipv4.conf.default.accept_redirects",   "0", "MEDIUM", "ICMP redirect acceptance disabled (default)"),
    ("net.ipv6.conf.all.accept_redirects",       "0", "MEDIUM", "IPv6 ICMP redirect acceptance disabled"),
    ("net.ipv6.conf.default.accept_redirects",   "0", "MEDIUM", "IPv6 ICMP redirect acceptance disabled (default)"),
    # Network - Source routing
    ("net.ipv4.conf.all.accept_source_route",    "0", "HIGH",   "Source routing rejected"),
    ("net.ipv4.conf.default.accept_source_route","0", "HIGH",   "Source routing rejected (default)"),
    ("net.ipv6.conf.all.accept_source_route",    "0", "HIGH",   "IPv6 source routing rejected"),
    # Network - Spoofing / Bogon
    ("net.ipv4.conf.all.rp_filter",              "1", "HIGH",   "Reverse path filter enabled (anti-spoofing)"),
    ("net.ipv4.conf.default.rp_filter",          "1", "HIGH",   "Reverse path filter enabled (default)"),
    # Network - Broadcast
    ("net.ipv4.icmp_ignore_bogus_error_responses","1","LOW",    "Bogus ICMP error responses ignored"),
    ("net.ipv4.icmp_echo_ignore_broadcasts",     "1", "MEDIUM", "ICMP echo broadcasts ignored (smurf protection)"),
    # TCP hardening
    ("net.ipv4.tcp_syncookies",                  "1", "HIGH",   "SYN cookies enabled (SYN flood protection)"),
    ("net.ipv4.tcp_timestamps",                  "0", "LOW",    "TCP timestamps disabled (uptime leak)"),
    # Kernel hardening
    ("kernel.randomize_va_space",                "2", "HIGH",   "ASLR fully enabled (=2)"),
    ("kernel.dmesg_restrict",                    "1", "MEDIUM", "dmesg restricted to root"),
    ("kernel.kptr_restrict",                     "2", "MEDIUM", "Kernel pointer restriction enabled"),
    ("kernel.yama.ptrace_scope",                 "1", "MEDIUM", "ptrace restricted to parent processes"),
    # Filesystem hardening
    ("fs.protected_hardlinks",                   "1", "MEDIUM", "Protected hardlinks enabled"),
    ("fs.protected_symlinks",                    "1", "MEDIUM", "Protected symlinks enabled"),
    ("fs.suid_dumpable",                         "0", "MEDIUM", "SUID coredumps disabled"),
]


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse_sysctl():
    """Read all sysctl params and return findings list."""
    results = []
    for param, expected, severity_if_wrong, description in SYSCTL_CHECKS:
        actual = read_sysctl(param)

        if actual is None:
            # Parameter not available on this kernel (e.g., IPv6 not loaded)
            result = {
                "param": param,
                "expected": expected,
                "actual": "N/A",
                "compliant": None,  # Unknown — skip for scoring
                "severity_if_wrong": severity_if_wrong,
                "description": description,
                "flag": f"\u2139\ufe0f {param}: not available (kernel module not loaded?)",
                "remediation": f"Verify kernel supports {param} or load required module",
                "risk_level": "LOW",
            }
        elif actual == expected:
            result = {
                "param": param,
                "expected": expected,
                "actual": actual,
                "compliant": True,
                "severity_if_wrong": severity_if_wrong,
                "description": description,
                "flag": f"\u2705 {param} = {actual}",
                "remediation": None,
                "risk_level": "LOW",
            }
        else:
            result = {
                "param": param,
                "expected": expected,
                "actual": actual,
                "compliant": False,
                "severity_if_wrong": severity_if_wrong,
                "description": description,
                "flag": f"\u26a0\ufe0f {param} = {actual} (expected {expected}): {description}",
                "remediation": (
                    f"Set permanently in /etc/sysctl.d/99-hardening.conf: "
                    f"{param} = {expected}  "
                    f"(apply with: sysctl -p /etc/sysctl.d/99-hardening.conf)"
                ),
                "risk_level": severity_if_wrong,
            }
        results.append(result)
    return results


# ── Scoring ───────────────────────────────────────────────────────────────────

def compute_risk(results):
    """Compute overall risk level from sysctl check results."""
    criticals = sum(1 for r in results if r["compliant"] is False and r["severity_if_wrong"] == "CRITICAL")
    highs     = sum(1 for r in results if r["compliant"] is False and r["severity_if_wrong"] == "HIGH")
    mediums   = sum(1 for r in results if r["compliant"] is False and r["severity_if_wrong"] == "MEDIUM")
    lows      = sum(1 for r in results if r["compliant"] is False and r["severity_if_wrong"] == "LOW")

    score = min(criticals * 3 + highs * 2 + mediums * 1, 10)

    if score >= 8 or criticals > 0:
        risk = "CRITICAL"
    elif score >= 5:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk, criticals, highs, mediums, lows


# ── Output formatters ─────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    os.chmod(path, 0o600)
    log.info(f"JSON report: {path}")


def write_csv(findings, path):
    if not findings:
        return
    fieldnames = [
        'param', 'expected', 'actual', 'compliant', 'severity_if_wrong',
        'description', 'flag', 'remediation',
    ]
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings  = report['findings']
    summary   = report['summary']
    generated = report['generated_at']
    hostname  = report.get('hostname', 'unknown')

    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH':     '#fd7e14',
        'MEDIUM':   '#ffc107',
        'LOW':      '#28a745',
    }

    def _row_color(result):
        if result['compliant'] is None:
            return '#95a5a6'   # grey — unavailable
        if result['compliant']:
            return '#28a745'   # green
        return severity_colors.get(result['severity_if_wrong'], '#fd7e14')

    rows = ''
    for r in findings:
        color = _row_color(r)
        compliant_label = 'SKIP' if r['compliant'] is None else ('PASS' if r['compliant'] else 'FAIL')
        status_icon = '\u2139\ufe0f' if r['compliant'] is None else ('\u2705' if r['compliant'] else '\u274c')
        remediation = r.get('remediation') or ''
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{status_icon} {compliant_label}</span></td>
            <td><span style="background:{severity_colors.get(r['severity_if_wrong'], '#999')};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold">{r['severity_if_wrong']}</span></td>
            <td style="font-family:monospace;font-size:0.85em">{r['param']}</td>
            <td style="font-family:monospace">{r['expected']}</td>
            <td style="font-family:monospace">{r['actual']}</td>
            <td style="font-size:0.85em">{r['description']}</td>
            <td style="font-size:0.8em;color:#28a745">{remediation}</td>
        </tr>"""

    risk_color = severity_colors.get(summary['overall_risk'], '#28a745')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Linux Sysctl Hardening Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #28a745); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 20px 30px; flex: 1; min-width: 140px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}
  .card .num {{ font-size: 2.5em; font-weight: bold; }}
  .card .label {{ color: #666; font-size: 0.9em; margin-top: 4px; }}
  .compliant .num {{ color: #28a745; }}
  .noncompliant .num {{ color: #fd7e14; }}
  .high .num {{ color: #fd7e14; }}
  .medium .num {{ color: #ffc107; }}
  .low .num {{ color: #28a745; }}
  .total .num {{ color: #3498db; }}
  .risk-badge {{ display: inline-block; background: {risk_color}; color: white; border-radius: 6px; padding: 4px 14px; font-weight: bold; font-size: 1.1em; }}
  .table-wrap {{ padding: 0 40px 40px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  th {{ background: #2c3e50; color: white; padding: 12px 15px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 10px 15px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8f9ff; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <h1>&#x2699;&#xFE0F; Linux Sysctl Hardening Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Host: {hostname} &nbsp;|&nbsp; {summary['total_checks']} checks &nbsp;|&nbsp; Risk: <span class="risk-badge">{summary['overall_risk']}</span></p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_checks']}</div><div class="label">Total Checks</div></div>
  <div class="card compliant"><div class="num">{summary['compliant']}</div><div class="label">Compliant</div></div>
  <div class="card noncompliant"><div class="num">{summary['non_compliant']}</div><div class="label">Non-Compliant</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">HIGH Violations</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">MEDIUM Violations</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Status</th><th>Severity</th><th>Parameter</th><th>Expected</th><th>Actual</th><th>Description</th><th>Remediation</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">Linux Sysctl Hardening Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, 'w') as f:
        f.write(html)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Main run function ─────────────────────────────────────────────────────────

def run(output_prefix='sysctl_report', fmt='all'):
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = 'unknown'

    results = analyse_sysctl()

    # Sort: non-compliant first, then N/A, then compliant
    def _sort_key(r):
        if r['compliant'] is False:
            return 0
        if r['compliant'] is None:
            return 1
        return 2

    results.sort(key=_sort_key)

    score, risk, criticals, highs, mediums, lows = compute_risk(results)

    report = {
        "generated_at": NOW.isoformat(),
        "hostname": hostname,
        "pillar": "sysctl",
        "risk_level": risk,
        "summary": {
            "total_checks": len(results),
            "compliant":     sum(1 for r in results if r["compliant"] is True),
            "non_compliant": sum(1 for r in results if r["compliant"] is False),
            "unavailable":   sum(1 for r in results if r["compliant"] is None),
            "critical":      criticals,
            "high":          highs,
            "medium":        mediums,
            "low":           lows,
            "overall_risk":  risk,
            "severity_score": score,
        },
        "findings": results,
    }

    if fmt in ('json', 'all'):
        write_json(report, f"{output_prefix}.json")
    if fmt in ('csv', 'all'):
        write_csv(results, f"{output_prefix}.csv")
    if fmt in ('html', 'all'):
        write_html(report, f"{output_prefix}.html")
    if fmt == 'stdout':
        print(json.dumps(report, indent=2, default=str))

    s = report['summary']
    total       = s['total_checks']
    compliant   = s['compliant']
    noncompliant= s['non_compliant']
    unavailable = s['unavailable']
    high        = s['high']
    medium      = s['medium']
    overall     = s['overall_risk']

    print(f"""
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551      SYSCTL AUDITOR \u2014 SUMMARY            \u2551
\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
\u2551  Total checks:        {total:<20}\u2551
\u2551  Compliant:           {compliant:<20}\u2551
\u2551  Non-compliant:       {noncompliant:<20}\u2551
\u2551  Unavailable:         {unavailable:<20}\u2551
\u2551  HIGH violations:     {high:<20}\u2551
\u2551  MEDIUM violations:   {medium:<20}\u2551
\u2551  Overall risk:        {overall:<20}\u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
""")

    return report


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Linux Sysctl Hardening Auditor')
    parser.add_argument('--output', '-o', default='sysctl_report')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'html', 'all', 'stdout'], default='all')
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format)
