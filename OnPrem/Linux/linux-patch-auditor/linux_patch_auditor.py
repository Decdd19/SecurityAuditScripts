#!/usr/bin/env python3
"""
Linux Patch & Update Auditor
=============================
Audits Linux system patch status:
- Detects package manager (apt, yum, dnf, zypper)
- Counts available updates (total and security-specific)
- Checks last successful update timestamp
- Verifies automatic update agent (unattended-upgrades, yum-cron, dnf-automatic)
- Reports kernel version vs available kernel updates

Usage:
    sudo python3 linux_patch_auditor.py
    python3 linux_patch_auditor.py --format html --output patch_report
    python3 linux_patch_auditor.py --format all
"""

import os
import sys
import json
import csv
import argparse
import logging
import subprocess
import platform
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


# ── Thin wrapper functions (for easy mocking in tests) ────────────────────────

def run_command(cmd):
    """Run command, return (stdout, returncode). Returns ('', 1) on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout, r.returncode
    except Exception:
        return '', 1


def read_file(path):
    """Read file content, return empty string if not readable."""
    try:
        return Path(path).read_text(errors='replace')
    except (OSError, PermissionError):
        return ''


def path_exists(path):
    """Return True if path exists."""
    return Path(path).exists()


# ── Package manager detection ─────────────────────────────────────────────────

def detect_package_manager():
    """Return 'apt', 'yum', 'dnf', 'zypper', or None."""
    for pm, check_cmd in [
        ('apt', ['apt-get', '--version']),
        ('dnf', ['dnf', '--version']),
        ('yum', ['yum', '--version']),
        ('zypper', ['zypper', '--version']),
    ]:
        _, rc = run_command(check_cmd)
        if rc == 0:
            return pm
    return None


# ── Update counting ───────────────────────────────────────────────────────────

def get_available_updates(pm):
    """
    Return (total_updates: int, security_updates: int, packages: list[str]).
    packages is a list of package name strings (may be truncated to first 20).
    """
    if pm == 'apt':
        stdout, rc = run_command(['apt-get', '-s', '-q', 'upgrade'])
        packages = [line.split()[1] for line in stdout.splitlines()
                    if line.startswith('Inst ')]
        total = len(packages)

        stdout2, rc2 = run_command(['apt-get', '-s', '-q', '-o',
                                    'Dir::Etc::sourcelist=/dev/null',
                                    '-o', 'Dir::Etc::sourceparts=-',
                                    '-o', 'APT::Get::List-Cleanup=0',
                                    '--only-upgrade', 'dist-upgrade'])
        sec_pkgs = [line.split()[1] for line in (stdout2 or '').splitlines()
                    if line.startswith('Inst ')] if rc2 == 0 else []
        security_count = len(sec_pkgs)
        return total, security_count, packages[:20]

    elif pm == 'yum':
        stdout, rc = run_command(['yum', 'check-update', '--quiet'])
        # rc=100 means updates available, rc=0 means up to date, rc=1 means error
        packages = []
        if rc in (0, 100):
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and not line.startswith(' ') and '.' in parts[0]:
                    packages.append(parts[0])
        total = len(packages)
        sec_stdout, sec_rc = run_command(['yum', 'check-update', '--security', '--quiet'])
        sec_pkgs = []
        if sec_rc in (0, 100):
            for line in sec_stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and not line.startswith(' ') and '.' in parts[0]:
                    sec_pkgs.append(parts[0])
        return total, len(sec_pkgs), packages[:20]

    elif pm == 'dnf':
        stdout, rc = run_command(['dnf', 'check-update', '--quiet'])
        packages = []
        if rc in (0, 100):
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and '.' in parts[0] and not line.startswith(' '):
                    packages.append(parts[0])
        total = len(packages)
        sec_stdout, sec_rc = run_command(['dnf', 'check-update', '--security', '--quiet'])
        sec_pkgs = []
        if sec_rc in (0, 100):
            for line in sec_stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and '.' in parts[0] and not line.startswith(' '):
                    sec_pkgs.append(parts[0])
        return total, len(sec_pkgs), packages[:20]

    elif pm == 'zypper':
        stdout, rc = run_command(['zypper', '--non-interactive', 'list-updates'])
        packages = []
        for line in stdout.splitlines():
            if line.startswith('|') and '|' in line[1:]:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) > 2 and parts[1] and not parts[1].startswith('S'):
                    packages.append(parts[2] if len(parts) > 2 else parts[1])
        sec_stdout, _ = run_command(['zypper', '--non-interactive', 'list-patches',
                                     '--category', 'security'])
        sec_count = sum(1 for line in sec_stdout.splitlines()
                        if '|' in line and not line.startswith('+-'))
        return len(packages), max(sec_count - 1, 0), packages[:20]  # -1 for header

    return 0, 0, []


# ── Last update timestamp ─────────────────────────────────────────────────────

def get_last_update_time(pm):
    """Return (datetime_or_None, days_since: int_or_None)."""
    timestamp = None

    if pm == 'apt':
        log_path = '/var/log/dpkg.log'
        content = read_file(log_path)
        if content:
            for line in reversed(content.splitlines()):
                if 'status installed' in line or 'upgrade' in line:
                    try:
                        dt_str = line[:19]
                        timestamp = datetime.strptime(
                            dt_str, '%Y-%m-%d %H:%M:%S'
                        ).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        continue
        if not timestamp:
            try:
                mtime = os.path.getmtime('/var/lib/apt/lists/')
                timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc)
            except OSError:
                pass

    elif pm in ('yum', 'dnf'):
        for log_path in ('/var/log/dnf.log', '/var/log/yum.log'):
            content = read_file(log_path)
            if content:
                for line in reversed(content.splitlines()):
                    try:
                        parts = line.split()
                        if len(parts) >= 2:
                            dt_str = f"{parts[0]} {parts[1]}"
                            timestamp = datetime.strptime(
                                dt_str, '%Y-%m-%d %H:%M:%S'
                            ).replace(tzinfo=timezone.utc)
                            break
                    except ValueError:
                        continue
                if timestamp:
                    break

    elif pm == 'zypper':
        content = read_file('/var/log/zypp/history')
        if content:
            for line in reversed(content.splitlines()):
                if not line.startswith('#'):
                    try:
                        dt_str = line.split('|')[0].strip()
                        timestamp = datetime.strptime(
                            dt_str, '%Y-%m-%d %H:%M:%S'
                        ).replace(tzinfo=timezone.utc)
                        break
                    except (ValueError, IndexError):
                        continue

    if timestamp:
        days_since = (NOW - timestamp).days
        return timestamp, days_since
    return None, None


# ── Auto-update check ─────────────────────────────────────────────────────────

def check_auto_updates(pm):
    """Return (enabled: bool, agent_name: str, details: str)."""
    if pm == 'apt':
        _, rc = run_command(['dpkg', '-l', 'unattended-upgrades'])
        installed = rc == 0
        if installed:
            stdout, _ = run_command(['systemctl', 'is-active', 'apt-daily-upgrade.timer'])
            active = stdout.strip() == 'active'
            return active, 'unattended-upgrades', 'apt-daily-upgrade.timer'
        return False, 'unattended-upgrades', 'not installed'

    elif pm == 'yum':
        stdout, rc = run_command(['systemctl', 'is-active', 'yum-cron'])
        if rc == 0 and stdout.strip() == 'active':
            return True, 'yum-cron', 'active'
        stdout2, rc2 = run_command(['systemctl', 'is-active', 'yum-updatesd'])
        return (rc2 == 0 and stdout2.strip() == 'active'), 'yum-cron/yum-updatesd', 'not active'

    elif pm == 'dnf':
        stdout, _ = run_command(['systemctl', 'is-active', 'dnf-automatic.timer'])
        active = stdout.strip() == 'active'
        if not active:
            stdout2, _ = run_command(['systemctl', 'is-active', 'dnf-automatic-install.timer'])
            active = stdout2.strip() == 'active'
        return active, 'dnf-automatic', 'dnf-automatic.timer'

    elif pm == 'zypper':
        stdout, _ = run_command(['systemctl', 'is-active',
                                  'yast2-online-update-finish.service'])
        return stdout.strip() == 'active', 'zypper auto-refresh', 'yast2-online-update-finish'

    return False, 'unknown', 'could not determine'


# ── Main analyse function ─────────────────────────────────────────────────────

def analyse_patch_status():
    """Run all patch checks and return a structured result."""
    import socket
    hostname = socket.gethostname()
    kernel = platform.release()

    pm = detect_package_manager()

    if pm is None:
        return {
            "hostname": hostname,
            "kernel": kernel,
            "package_manager": None,
            "total_updates": None,
            "security_updates": None,
            "pending_packages": [],
            "last_update": None,
            "days_since_update": None,
            "auto_updates_enabled": None,
            "auto_update_agent": None,
            "risk_level": "MEDIUM",
            "severity_score": 3,
            "flags": ["⚠️ Could not detect package manager — manual verification required"],
            "remediations": ["Verify system has apt, yum, dnf, or zypper installed"],
            "cis_control": "CIS 7",
        }

    total_updates, security_updates, pending_pkgs = get_available_updates(pm)
    last_update_dt, days_since = get_last_update_time(pm)
    auto_enabled, agent_name, auto_details = check_auto_updates(pm)

    flags = []
    remediations = []
    score = 0

    # Security updates pending
    if security_updates > 0:
        flags.append(f"❌ {security_updates} security update(s) pending")
        remediations.append(
            f"Apply security updates immediately: sudo {pm} "
            f"{'upgrade' if pm == 'apt' else 'update'} "
            f"(with --security flag for yum/dnf)"
        )
        score += min(security_updates, 4) + 1  # 1-5 points depending on count

    # Total updates pending
    if total_updates > 0 and security_updates == 0:
        flags.append(
            f"ℹ️ {total_updates} package update(s) available (no security updates detected)"
        )
        remediations.append(
            f"Apply updates: sudo {'apt-get upgrade' if pm == 'apt' else pm + ' update'}"
        )
        score += 1
    elif total_updates > 0:
        flags.append(
            f"ℹ️ {total_updates} total update(s) available ({security_updates} security)"
        )

    # Stale last update
    if days_since is not None:
        if days_since > 90:
            flags.append(f"❌ Last update was {days_since} days ago (>90 days)")
            remediations.append(
                "Update system immediately and establish a regular patching schedule "
                "(weekly minimum)"
            )
            score += 3
        elif days_since > 30:
            flags.append(f"⚠️ Last update was {days_since} days ago (>30 days)")
            remediations.append(
                f"Apply pending updates: sudo "
                f"{'apt-get upgrade' if pm == 'apt' else pm + ' update'}"
            )
            score += 1
        else:
            flags.append(f"✅ Last update {days_since} days ago")
    else:
        flags.append("⚠️ Could not determine last update time")
        remediations.append("Check system logs for last update timestamp")
        score += 1

    # Auto-updates
    if not auto_enabled:
        flags.append(f"⚠️ Automatic updates ({agent_name}) not enabled")
        remediations.append(
            f"Enable automatic security updates: install and configure {agent_name}"
        )
        score += 1
    else:
        flags.append(f"✅ Automatic updates enabled ({agent_name})")

    score = min(score, 10)
    if score >= 8:
        risk = "CRITICAL"
    elif score >= 5:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "hostname": hostname,
        "kernel": kernel,
        "package_manager": pm,
        "total_updates": total_updates,
        "security_updates": security_updates,
        "pending_packages": pending_pkgs,
        "last_update": last_update_dt.isoformat() if last_update_dt else None,
        "days_since_update": days_since,
        "auto_updates_enabled": auto_enabled,
        "auto_update_agent": agent_name,
        "risk_level": risk,
        "severity_score": score,
        "flags": flags,
        "remediations": [r for r in remediations if r],
        "cis_control": "CIS 7",
    }


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
        'hostname', 'kernel', 'package_manager', 'total_updates', 'security_updates',
        'days_since_update', 'auto_updates_enabled', 'auto_update_agent',
        'risk_level', 'severity_score',
    ]
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    result = report['findings'][0] if report['findings'] else {}
    summary = report['summary']
    generated = report['generated_at']
    hostname = report.get('hostname', 'unknown')
    kernel = report.get('kernel', 'unknown')

    risk_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745',
    }
    risk = summary.get('overall_risk', 'UNKNOWN')
    risk_color = risk_colors.get(risk, '#999')

    flags_html = ''
    for flag in result.get('flags', []):
        flags_html += f'<li style="margin:4px 0">{flag}</li>\n'

    remediations_html = ''
    for rem in result.get('remediations', []):
        remediations_html += f'<li style="margin:4px 0">{rem}</li>\n'

    pending_pkgs = result.get('pending_packages', [])
    pkgs_html = ', '.join(pending_pkgs) if pending_pkgs else 'None'

    pm = result.get('package_manager') or 'N/A'
    total_updates = result.get('total_updates')
    security_updates = result.get('security_updates')
    days_since = result.get('days_since_update')
    auto_enabled = result.get('auto_updates_enabled')
    auto_agent = result.get('auto_update_agent', 'N/A')

    total_str = str(total_updates) if total_updates is not None else 'N/A'
    security_str = str(security_updates) if security_updates is not None else 'N/A'
    days_str = str(days_since) if days_since is not None else 'N/A'
    auto_str = 'Yes' if auto_enabled else ('No' if auto_enabled is False else 'N/A')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Linux Patch Auditor Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #e74c3c); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 20px 30px; flex: 1; min-width: 140px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}
  .card .num {{ font-size: 2.5em; font-weight: bold; }}
  .card .label {{ color: #666; font-size: 0.9em; margin-top: 4px; }}
  .risk .num {{ color: {risk_color}; }}
  .detail-wrap {{ padding: 0 40px 20px; }}
  .detail-card {{ background: white; border-radius: 8px; padding: 20px 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; }}
  .detail-card h2 {{ margin-top: 0; font-size: 1.1em; color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 8px; }}
  table.info {{ width: 100%; border-collapse: collapse; }}
  table.info td {{ padding: 8px 12px; border-bottom: 1px solid #ecf0f1; }}
  table.info td:first-child {{ font-weight: bold; color: #555; width: 200px; }}
  table.info tr:last-child td {{ border-bottom: none; }}
  ul.flags {{ margin: 0; padding-left: 20px; }}
  .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <h1>🩹 Linux Patch Auditor Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Host: {hostname} &nbsp;|&nbsp; Kernel: {kernel}</p>
</div>
<div class="summary">
  <div class="card"><div class="num">{total_str}</div><div class="label">Total Updates</div></div>
  <div class="card"><div class="num" style="color:#e74c3c">{security_str}</div><div class="label">Security Updates</div></div>
  <div class="card"><div class="num">{days_str}</div><div class="label">Days Since Update</div></div>
  <div class="card"><div class="num" style="color:{'#28a745' if auto_enabled else '#e74c3c'}">{auto_str}</div><div class="label">Auto-Updates</div></div>
  <div class="card risk"><div class="num">{risk}</div><div class="label">Overall Risk</div></div>
</div>
<div class="detail-wrap">
  <div class="detail-card">
    <h2>System Information</h2>
    <table class="info">
      <tr><td>Hostname</td><td>{hostname}</td></tr>
      <tr><td>Kernel</td><td>{kernel}</td></tr>
      <tr><td>Package Manager</td><td>{pm}</td></tr>
      <tr><td>Auto-update Agent</td><td>{auto_agent}</td></tr>
      <tr><td>Pending Packages</td><td style="font-size:0.85em">{pkgs_html}</td></tr>
    </table>
  </div>
  <div class="detail-card">
    <h2>Findings</h2>
    <ul class="flags">{flags_html}</ul>
  </div>
  <div class="detail-card">
    <h2>Remediations</h2>
    <ul class="flags">{remediations_html if remediations_html else '<li>No remediations required.</li>'}</ul>
  </div>
</div>
<div class="footer">Linux Patch Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, 'w') as f:
        f.write(html)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Main run function ─────────────────────────────────────────────────────────

def run(output_prefix='patch_report', fmt='all'):
    result = analyse_patch_status()

    report = {
        "generated_at": NOW.isoformat(),
        "hostname": result["hostname"],
        "kernel": result["kernel"],
        "package_manager": result["package_manager"],
        "summary": {
            "total_updates": result["total_updates"],
            "security_updates": result["security_updates"],
            "days_since_update": result["days_since_update"],
            "auto_updates_enabled": result["auto_updates_enabled"],
            "overall_risk": result["risk_level"],
            "severity_score": result["severity_score"],
        },
        "findings": [result],
        "pillar": "patch",
        "risk_level": result["risk_level"],
    }

    if fmt in ('json', 'all'):
        write_json(report, f"{output_prefix}.json")
    if fmt in ('csv', 'all'):
        write_csv(report['findings'], f"{output_prefix}.csv")
    if fmt in ('html', 'all'):
        write_html(report, f"{output_prefix}.html")
    if fmt == 'stdout':
        print(json.dumps(report, indent=2, default=str))

    pm = result['package_manager'] or 'N/A'
    total = result['total_updates']
    security = result['security_updates']
    days = result['days_since_update']
    auto_yn = 'Yes' if result['auto_updates_enabled'] else (
        'No' if result['auto_updates_enabled'] is False else 'N/A'
    )
    risk = result['risk_level']

    total_str = str(total) if total is not None else 'N/A'
    security_str = str(security) if security is not None else 'N/A'
    days_str = str(days) if days is not None else 'N/A'

    print(f"""
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551      PATCH AUDITOR \u2014 SUMMARY            \u2551
\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
\u2551  Package manager:     {pm:<20}\u2551
\u2551  Total updates:       {total_str:<20}\u2551
\u2551  Security updates:    {security_str:<20}\u2551
\u2551  Days since update:   {days_str:<20}\u2551
\u2551  Auto-updates:        {auto_yn:<20}\u2551
\u2551  Overall risk:        {risk:<20}\u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
""")

    return report


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Linux Patch & Update Auditor')
    parser.add_argument('--output', '-o', default='patch_report')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'html', 'all', 'stdout'],
                        default='all')
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format)
