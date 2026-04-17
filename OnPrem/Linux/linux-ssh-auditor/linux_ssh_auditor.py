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
import html
import shutil
import socket
import argparse
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Shared CSS generator (repo root — 4 levels up from this auditor directory)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))
from report_utils import get_styles

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
                'cis_control':       'CIS 4',
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
                    'cis_control':       'CIS 4',
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
                    'cis_control':       'CIS 4',
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
        'description', 'flag', 'remediation', 'cis_control',
    ]
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings   = report['findings']
    summary    = report['summary']
    generated  = report['generated_at']
    hostname   = html.escape(report.get('hostname', 'unknown'))

    SEV_COLOR = {
        'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#28a745',
    }
    risk_color  = SEV_COLOR.get(summary['overall_risk'], '#28a745')
    na_count    = summary.get('unavailable', 0)
    pass_count  = summary.get('compliant', 0)
    fail_count  = summary.get('non_compliant', 0)

    # P2-2: prominent re-scan callout when N/A rows are present (replaces tiny note)
    rescan_callout = ''
    if na_count:
        rescan_callout = (
            f'<div style="margin:0 40px 16px;padding:14px 18px;background:#fff8e1;'
            f'border-left:4px solid #ffc107;border-radius:0 8px 8px 0;">'
            f'<strong>\u26a0 SSH audit incomplete \u2014 elevated access required</strong><br>'
            f'<span style="font-size:0.9em;color:#555">'
            f'{na_count} of {len(findings)} checks could not be evaluated. '
            f'<code>sshd -T</code> requires root. Re-run with <code>sudo</code> '
            f'to complete this pillar and obtain accurate results.</span></div>'
        )

    # P2-2 + P2-3: build rows — FAILs always visible; PASS and N/A hidden by default
    rows = ''
    for f in findings:
        sev = f.get('severity_if_wrong', 'LOW')
        sev_color = SEV_COLOR.get(sev, '#999')
        if f['compliant'] is None:
            # N/A — greyed, shows severity_if_wrong so client sees potential impact
            rows += (
                f'<tr class="row-na" style="opacity:0.55">'
                f'<td><span style="background:#95a5a6;color:white;padding:2px 8px;'
                f'border-radius:4px;font-weight:bold">\u2014 N/A</span></td>'
                f'<td><span style="background:{sev_color};color:white;padding:2px 8px;'
                f'border-radius:4px;font-size:0.78em;font-weight:bold">{sev} if wrong</span></td>'
                f'<td style="font-family:monospace;font-size:0.85em">{html.escape(f["param"])}</td>'
                f'<td style="font-family:monospace">{html.escape(str(f["expected"]))}</td>'
                f'<td style="font-family:monospace;color:#aaa">N/A</td>'
                f'<td style="font-size:0.85em;color:#888">{html.escape(f["description"])}</td>'
                f'<td style="font-size:0.8em;color:#bbb">Re-run with sudo</td>'
                f'</tr>'
            )
        elif f['compliant']:
            rows += (
                f'<tr class="row-pass">'
                f'<td><span style="background:#28a745;color:white;padding:2px 8px;'
                f'border-radius:4px;font-weight:bold">\u2705 PASS</span></td>'
                f'<td><span style="background:{sev_color};color:white;padding:2px 8px;'
                f'border-radius:4px;font-size:0.78em;font-weight:bold">{sev}</span></td>'
                f'<td style="font-family:monospace;font-size:0.85em">{html.escape(f["param"])}</td>'
                f'<td style="font-family:monospace">{html.escape(str(f["expected"]))}</td>'
                f'<td style="font-family:monospace">{html.escape(str(f["actual"]))}</td>'
                f'<td style="font-size:0.85em">{html.escape(f["description"])}</td>'
                f'<td style="font-size:0.8em;color:#aaa">\u2014</td>'
                f'</tr>'
            )
        else:
            description = f'{html.escape(f["description"])} \u2014 currently: <code>{html.escape(str(f["actual"]))}</code>'
            remediation = html.escape(f.get('remediation') or '')
            rows += (
                f'<tr class="row-fail">'
                f'<td><span style="background:#dc3545;color:white;padding:2px 8px;'
                f'border-radius:4px;font-weight:bold">\u274c FAIL</span></td>'
                f'<td><span style="background:{sev_color};color:white;padding:2px 8px;'
                f'border-radius:4px;font-size:0.78em;font-weight:bold">{sev}</span></td>'
                f'<td style="font-family:monospace;font-size:0.85em">{html.escape(f["param"])}</td>'
                f'<td style="font-family:monospace">{html.escape(str(f["expected"]))}</td>'
                f'<td style="font-family:monospace">{html.escape(str(f["actual"]))}</td>'
                f'<td style="font-size:0.85em">{description}</td>'
                f'<td style="font-size:0.8em;color:#555">{remediation}</td>'
                f'</tr>'
            )

    toggle_label = f'Show all checks ({pass_count} passing, {na_count} unavailable)'

    # P2-5: extra CSS added on top of shared base from get_styles()
    extra_css = (
        f"  .risk-badge {{ display:inline-block; background:{risk_color}; color:white;"
        f" border-radius:8px; padding:4px 14px; font-weight:bold; font-size:1.1em; }}\n"
        "  .row-pass { display: none; }\n"
        "  .row-na   { display: none; }\n"
        "  table.show-all .row-pass { display: table-row; }\n"
        "  table.show-all .row-na   { display: table-row; }\n"
        "  .toggle-btn { display:block; margin:0 40px 12px; padding:8px 18px;"
        " background:#f0f4ff; border:1px solid #c0cfe0; border-radius:6px;"
        " cursor:pointer; font-size:0.88em; text-align:left; }\n"
        "  .toggle-btn:hover { background:#e0e8ff; }\n"
    )

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SSH Security Audit Report</title>
<style>{get_styles(extra_css)}</style>
</head>
<body>
<div class="header">
  <h1>SSH Security Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Host: {hostname} &nbsp;|&nbsp; {summary['total_checks']} checks &nbsp;|&nbsp; Risk: <span class="risk-badge">{summary['overall_risk']}</span></p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_checks']}</div><div class="label">Total Checks</div></div>
  <div class="card noncompliant"><div class="num">{fail_count}</div><div class="label">Issues Found</div></div>
  <div class="card compliant"><div class="num">{pass_count}</div><div class="label">Compliant</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">HIGH Issues</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">MEDIUM Issues</div></div>
</div>
{rescan_callout}<button id="ssh-toggle" class="toggle-btn"
  onclick="var t=document.getElementById('ssh-tbl');var s=t.classList.toggle('show-all');this.textContent=s?'Hide passing \u0026 unavailable checks':'{toggle_label}';"
>{toggle_label}</button>
<div class="table-wrap">
  <table id="ssh-tbl">
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
        f.write(html_out)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Main run function ─────────────────────────────────────────────────────────

def run(output_prefix='ssh_report', fmt='all'):
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = 'unknown'

    # If sshd is not installed, return a clean report with no findings.
    # This avoids triggering the UNKNOWN pillar logic in exec_summary, which
    # is designed for "ran without sudo", not "SSH daemon absent".
    sshd_installed = shutil.which('sshd') is not None or Path('/usr/sbin/sshd').exists()
    if not sshd_installed:
        report = {
            'generated_at': NOW.isoformat(),
            'hostname':     hostname,
            'pillar':       'ssh',
            'risk_level':   'LOW',
            'ssh_daemon_installed': False,
            'summary': {
                'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
                'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0,
                'low': 0, 'overall_risk': 'LOW', 'severity_score': 0,
            },
            'findings': [],
        }
        not_installed_html = (
            '<div style="margin:0 40px 24px;padding:14px 18px;background:#f0f4ff;'
            'border-left:4px solid #28a745;border-radius:0 8px 8px 0;">'
            '<strong>&#10003; SSH daemon not installed</strong><br>'
            '<span style="font-size:0.9em;color:#555">'
            'openssh-server is not present on this host — no inbound SSH connections '
            'are possible and no SSH hardening checks are required.</span></div>'
        )
        if fmt in ('json', 'all'):
            write_json(report, f"{output_prefix}.json")
        if fmt in ('csv', 'all'):
            write_csv([], f"{output_prefix}.csv")
        if fmt in ('html', 'all'):
            html_out = (
                f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
                f'<title>SSH Security Audit Report</title>'
                f'<style>{get_styles()}</style></head><body>'
                f'<div class="header"><h1>SSH Security Audit Report</h1>'
                f'<p>Generated: {NOW.isoformat()} &nbsp;|&nbsp; Host: {hostname}</p></div>'
                f'{not_installed_html}'
                f'<div class="footer">Linux SSH Hardening Auditor &nbsp;|&nbsp; For internal security use only</div>'
                f'</body></html>'
            )
            p = f"{output_prefix}.html"
            with open(p, 'w') as fh:
                fh.write(html_out)
            os.chmod(p, 0o600)
            log.info(f"HTML report: {p}")
        if fmt == 'stdout':
            print(json.dumps(report, indent=2, default=str))
        print('\n╔══════════════════════════════════════════════╗')
        print('║       SSH AUDITOR — SUMMARY                  ║')
        print('╠══════════════════════════════════════════════╣')
        print('║  SSH daemon not installed — checks skipped   ║')
        print('╚══════════════════════════════════════════════╝\n')
        return report

    config   = get_effective_config()
    findings = analyse_ssh(config)

    # Sort: non-compliant first, then N/A (None), then compliant
    def _sort_key(f):
        if f['compliant'] is False:
            return 0
        if f['compliant'] is None:
            return 1
        return 2

    findings.sort(key=_sort_key)

    score, risk, criticals, highs, mediums, lows = compute_risk(findings)

    # When >50% of checks are N/A (compliant=None), the audit ran without sudo
    # and cannot verify most settings. Signal incomplete audit rather than low risk.
    na_count = sum(1 for f in findings if f.get('compliant') is None)
    if findings and na_count / len(findings) > 0.5:
        risk = 'UNKNOWN'

    report = {
        'generated_at': NOW.isoformat(),
        'hostname':     hostname,
        'pillar':       'ssh',
        'risk_level':   risk,
        'summary': {
            'total_checks': len(findings),
            'compliant':     sum(1 for f in findings if f['compliant'] is True),
            'non_compliant': sum(1 for f in findings if f['compliant'] is False),
            'unavailable':   sum(1 for f in findings if f['compliant'] is None),
            'critical':      criticals,
            'high':          highs,
            'medium':        mediums,
            'low':           lows,
            'overall_risk':  risk,
            'severity_score': score,
        },
        'findings': findings,
    }

    if fmt in ('json', 'all'):
        write_json(report, f"{output_prefix}.json")
    if fmt in ('csv', 'all'):
        write_csv(findings, f"{output_prefix}.csv")
    if fmt in ('html', 'all'):
        write_html(report, f"{output_prefix}.html")
    if fmt == 'stdout':
        print(json.dumps(report, indent=2, default=str))

    s = report['summary']
    print(f"""
╔══════════════════════════════════════════════╗
║       SSH AUDITOR — SUMMARY                  ║
╠══════════════════════════════════════════════╣
║  Total checks:        {s['total_checks']:<22}║
║  Compliant:           {s['compliant']:<22}║
║  Non-compliant:       {s['non_compliant']:<22}║
║  Unavailable:         {s['unavailable']:<22}║
║  CRITICAL violations: {s['critical']:<22}║
║  HIGH violations:     {s['high']:<22}║
║  MEDIUM violations:   {s['medium']:<22}║
║  Overall risk:        {s['overall_risk']:<22}║
╚══════════════════════════════════════════════╝
""")

    return report


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Linux SSH Hardening Auditor')
    parser.add_argument('--output', '-o', default='ssh_report')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'html', 'all', 'stdout'], default='all')
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format)
