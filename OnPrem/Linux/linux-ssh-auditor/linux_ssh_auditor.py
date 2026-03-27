#!/usr/bin/env python3
"""
Linux SSH Hardening Auditor
============================
Checks SSH daemon configuration via `sshd -T` (effective running config):
- Authentication hardening (root login, password auth, empty passwords)
- Session hardening (X11, forwarding, timeouts, strict modes)
- Logging (log level, PAM)
- Cryptography (weak ciphers, MACs, key exchange algorithms)

Usage:
    sudo python3 linux_ssh_auditor.py
    python3 linux_ssh_auditor.py --format html --output ssh_report
    python3 linux_ssh_auditor.py --format all
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


# ── Thin wrapper (mockable in tests) ─────────────────────────────────────────

def run_command(cmd):
    """Run command, return (stdout, returncode). Returns ('', 1) on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout, r.returncode
    except Exception:
        return '', 1


# ── Config reader ─────────────────────────────────────────────────────────────

def get_effective_config():
    """Call sshd -T and parse output into a lowercase key->value dict.

    Returns {} if sshd is unavailable or returns non-zero.
    sshd -T outputs one 'key value' pair per line (space-separated).
    Multi-word values (e.g. cipher lists) are preserved as-is.
    """
    stdout, rc = run_command(['sshd', '-T'])
    if rc != 0 or not stdout.strip():
        return {}
    config = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(' ', 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1]
    return config


# ── Check helpers ─────────────────────────────────────────────────────────────

def _eq(expected):
    """Returns check_fn: passes if value == expected (case-insensitive)."""
    def check(val):
        ok = val.strip().lower() == expected.lower()
        return ok, expected
    check.expected_label = expected
    return check


def _lte(threshold):
    """Returns check_fn: passes if int(value) <= threshold."""
    def check(val):
        try:
            ok = int(val.strip()) <= threshold
        except ValueError:
            ok = False
        return ok, f"≤{threshold}"
    check.expected_label = f"≤{threshold}"
    return check


def _loglevel_ok():
    """Passes if loglevel is VERBOSE or INFO."""
    def check(val):
        ok = val.strip().upper() in ('VERBOSE', 'INFO')
        return ok, 'VERBOSE or INFO'
    check.expected_label = 'VERBOSE or INFO'
    return check


def _no_weak(weak_patterns):
    """Returns check_fn: passes if none of the weak patterns appear in the value.

    Value must be a comma-separated algorithm list (as output by sshd -T).
    Pattern matching supports three forms:
      'prefix*'  — matches any algo starting with prefix  (e.g. 'arcfour*')
      '*suffix'  — matches any algo ending with suffix    (e.g. '*-cbc')
      'exact'    — literal match                          (e.g. 'ssh-dss')
    """
    label = f'no weak algorithms ({", ".join(weak_patterns)})'

    def check(val):
        algos = [a.strip().lower() for a in val.split(',')]
        for algo in algos:
            for pat in weak_patterns:
                p = pat.lower()
                if p.startswith('*'):
                    if algo.endswith(p[1:]):
                        return False, label
                elif p.endswith('*'):
                    if algo.startswith(p[:-1]):
                        return False, label
                else:
                    if algo == p:
                        return False, label
        return True, label
    check.expected_label = label
    return check


# ── SSH checks table ──────────────────────────────────────────────────────────
# (key, check_fn, severity_if_wrong, description, remediation)

SSH_CHECKS = [
    # ── Authentication ────────────────────────────────────────────────────────
    ("permitrootlogin",       _eq("no"),       "CRITICAL",
     "Root login fully disabled",
     "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("permitemptypasswords",  _eq("no"),       "CRITICAL",
     "Empty password login blocked",
     "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("passwordauthentication", _eq("no"),      "HIGH",
     "Key-based authentication enforced (passwords disabled)",
     "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("pubkeyauthentication",  _eq("yes"),      "HIGH",
     "Public key authentication enabled",
     "Set 'PubkeyAuthentication yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    # ── Session hardening ─────────────────────────────────────────────────────
    ("strictmodes",           _eq("yes"),      "HIGH",
     "Enforce strict .ssh directory permission checks",
     "Set 'StrictModes yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("hostbasedauthentication", _eq("no"),     "MEDIUM",
     "Host-based trust disabled",
     "Set 'HostbasedAuthentication no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("ignorerhosts",          _eq("yes"),      "MEDIUM",
     ".rhosts and .shosts files ignored",
     "Set 'IgnoreRhosts yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("x11forwarding",         _eq("no"),       "MEDIUM",
     "X11 tunnelling disabled",
     "Set 'X11Forwarding no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("loglevel",              _loglevel_ok(),  "MEDIUM",
     "Audit-grade logging active (VERBOSE or INFO)",
     "Set 'LogLevel VERBOSE' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("maxauthtries",          _lte(4),         "MEDIUM",
     "Brute-force throttle: max 4 authentication attempts",
     "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("logingracetime",        _lte(60),        "MEDIUM",
     "Unauthenticated connection timeout ≤60 seconds",
     "Set 'LoginGraceTime 60' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("allowagentforwarding",  _eq("no"),       "LOW",
     "SSH agent forwarding disabled (limits lateral movement)",
     "Set 'AllowAgentForwarding no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("allowtcpforwarding",    _eq("no"),       "LOW",
     "TCP tunnelling disabled",
     "Set 'AllowTcpForwarding no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("usepam",                _eq("yes"),      "LOW",
     "PAM integration active",
     "Set 'UsePAM yes' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("clientaliveinterval",   _lte(300),       "LOW",
     "Idle session keepalive interval ≤300 seconds",
     "Set 'ClientAliveInterval 300' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    ("clientalivecountmax",   _lte(3),         "LOW",
     "Max missed keepalives before disconnect ≤3",
     "Set 'ClientAliveCountMax 3' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

    # ── Crypto ────────────────────────────────────────────────────────────────
    ("ciphers",
     _no_weak(["arcfour*", "*-cbc"]),
     "HIGH",
     "No weak CBC/arcfour ciphers in use",
     "Remove CBC/arcfour ciphers from sshd_config Ciphers line; prefer aes*-ctr and chacha20-poly1305"),

    ("macs",
     _no_weak(["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
               "umac-64*", "hmac-md5-etm*", "hmac-sha1-etm*"]),
     "HIGH",
     "No weak MD5/SHA1 MACs in use",
     "Remove hmac-md5/hmac-sha1/umac-64 from sshd_config MACs line; prefer hmac-sha2-* and umac-128*"),

    ("kexalgorithms",
     _no_weak(["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
               "diffie-hellman-group-exchange-sha1"]),
     "HIGH",
     "No weak Diffie-Hellman key exchange algorithms",
     "Remove group1/group14-sha1 from KexAlgorithms; prefer curve25519-sha256 and ecdh-sha2-nistp*"),

    ("hostkeyalgorithms",
     _no_weak(["ssh-dss"]),
     "HIGH",
     "DSA host key algorithm disabled",
     "Remove ssh-dss from HostKeyAlgorithms; prefer rsa-sha2-256/512 and ecdsa/ed25519"),

    ("pubkeyacceptedalgorithms",
     _no_weak(["ssh-dss"]),
     "MEDIUM",
     "DSA not accepted for public key authentication",
     "Remove ssh-dss from PubkeyAcceptedAlgorithms; prefer rsa-sha2-256/512 and ed25519"),
]


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse_ssh(config):
    """Run all SSH_CHECKS against the parsed config dict. Returns findings list."""
    findings = []
    for key, check_fn, severity, description, remediation in SSH_CHECKS:
        val = config.get(key)

        if val is None:
            # Key absent from sshd -T — compiled-in default; skip scoring
            expected_str = check_fn.expected_label
            finding = {
                'param':             key,
                'expected':          expected_str,
                'actual':            'N/A',
                'compliant':         None,
                'severity_if_wrong': severity,
                'description':       description,
                'flag':              f'ℹ️ {key}: not present in sshd -T output',
                'remediation':       None,
                'risk_level':        'LOW',
            }
        else:
            ok, expected_str = check_fn(val)
            if ok:
                finding = {
                    'param':             key,
                    'expected':          expected_str,
                    'actual':            val,
                    'compliant':         True,
                    'severity_if_wrong': severity,
                    'description':       description,
                    'flag':              f'✅ {key} = {val}',
                    'remediation':       None,
                    'risk_level':        'LOW',
                }
            else:
                finding = {
                    'param':             key,
                    'expected':          expected_str,
                    'actual':            val,
                    'compliant':         False,
                    'severity_if_wrong': severity,
                    'description':       description,
                    'flag':              f'⚠️ {key} = {val} (expected {expected_str}): {description}',
                    'remediation':       remediation,
                    'risk_level':        severity,
                }
        findings.append(finding)
    return findings


# ── Scoring ───────────────────────────────────────────────────────────────────

def compute_risk(findings):
    """Compute overall risk from findings. Returns (score, risk, c, h, m, l)."""
    criticals = sum(1 for f in findings if f['compliant'] is False and f['severity_if_wrong'] == 'CRITICAL')
    highs     = sum(1 for f in findings if f['compliant'] is False and f['severity_if_wrong'] == 'HIGH')
    mediums   = sum(1 for f in findings if f['compliant'] is False and f['severity_if_wrong'] == 'MEDIUM')
    lows      = sum(1 for f in findings if f['compliant'] is False and f['severity_if_wrong'] == 'LOW')

    score = min(criticals * 8 + highs * 4 + mediums * 2 + int(lows * 0.5), 10)

    if score >= 8 or criticals > 0:
        risk = 'CRITICAL'
    elif score >= 5:
        risk = 'HIGH'
    elif score >= 2:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'

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

    def _row_color(f):
        if f['compliant'] is None:
            return '#95a5a6'
        if f['compliant']:
            return '#28a745'
        return severity_colors.get(f['severity_if_wrong'], '#fd7e14')

    rows = ''
    for f in findings:
        color = _row_color(f)
        label = 'SKIP' if f['compliant'] is None else ('PASS' if f['compliant'] else 'FAIL')
        icon  = 'ℹ️' if f['compliant'] is None else ('✅' if f['compliant'] else '❌')
        remediation = f.get('remediation') or ''
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{icon} {label}</span></td>
            <td><span style="background:{severity_colors.get(f['severity_if_wrong'], '#999')};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold">{f['severity_if_wrong']}</span></td>
            <td style="font-family:monospace;font-size:0.85em">{f['param']}</td>
            <td style="font-family:monospace">{f['expected']}</td>
            <td style="font-family:monospace">{f['actual']}</td>
            <td style="font-size:0.85em">{f['description']}</td>
            <td style="font-size:0.8em;color:#28a745">{remediation}</td>
        </tr>"""

    risk_color = severity_colors.get(summary['overall_risk'], '#28a745')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Linux SSH Hardening Audit Report</title>
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
  <h1>🔐 Linux SSH Hardening Audit Report</h1>
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
<div class="footer">Linux SSH Hardening Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, 'w') as f:
        f.write(html)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")
