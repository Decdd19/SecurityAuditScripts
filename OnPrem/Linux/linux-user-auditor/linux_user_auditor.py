#!/usr/bin/env python3
"""
Linux User & Sudo Auditor
=========================
Audits local user accounts, sudo configuration, SSH settings, and password policy on Linux.
Reads: /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers, /etc/sudoers.d/*, /etc/ssh/sshd_config, /etc/login.defs

Usage:
    sudo python3 linux_user_auditor.py
    python3 linux_user_auditor.py --format html --output user_report
    python3 linux_user_auditor.py --format all
"""

import os
import sys
import re
import json
import csv
import argparse
import logging
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


# ── Thin wrapper functions (for easy mocking in tests) ────────────────────────

def read_file(path):
    """Read file content, return empty string if not readable."""
    try:
        return Path(path).read_text(errors='replace')
    except (OSError, PermissionError):
        return ''


def run_command(cmd):
    """Run command, return (stdout, returncode). Returns ('', 1) on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout, r.returncode
    except Exception:
        return '', 1


def get_file_stat(path):
    """Return os.stat result or None."""
    try:
        return os.stat(path)
    except OSError:
        return None


# ── Severity helper ───────────────────────────────────────────────────────────

def severity_label(score):
    if score >= 8:
        return 'CRITICAL'
    if score >= 6:
        return 'HIGH'
    if score >= 3:
        return 'MEDIUM'
    return 'LOW'


# ── Core data parsers ─────────────────────────────────────────────────────────

def parse_passwd(content):
    """Parse /etc/passwd. Returns list of dicts with: username, uid, gid, home, shell."""
    users = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) < 7:
            continue
        try:
            users.append({
                'username': parts[0],
                'uid': int(parts[2]),
                'gid': int(parts[3]),
                'home': parts[5],
                'shell': parts[6],
            })
        except (ValueError, IndexError):
            continue
    return users


def parse_shadow(content):
    """Parse /etc/shadow. Returns dict of {username: {'hash': ..., 'max_days': int_or_none, 'last_change': int_or_none}}."""
    shadow = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) < 2:
            continue
        username = parts[0]
        password_hash = parts[1] if len(parts) > 1 else ''

        max_days = None
        if len(parts) > 4 and parts[4] != '':
            try:
                max_days = int(parts[4])
            except ValueError:
                pass

        last_change = None
        if len(parts) > 2 and parts[2] != '':
            try:
                last_change = int(parts[2])
            except ValueError:
                pass

        shadow[username] = {
            'hash': password_hash,
            'max_days': max_days,
            'last_change': last_change,
        }
    return shadow


def parse_sudoers(content):
    """Parse sudoers content. Returns list of dicts: {user_or_group, spec, nopasswd: bool, all_commands: bool}."""
    entries = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments, blank lines, and directives
        if not line or line.startswith('#') or line.startswith('@') or line.startswith('Defaults'):
            continue
        # Skip alias definitions
        if re.match(r'^(User|Runas|Host|Cmnd)_Alias\s', line):
            continue
        # Match user/group privilege lines: <user> <host>=(<runas>) [NOPASSWD:] <cmds>
        # Basic pattern: token followed by whitespace and an = somewhere
        m = re.match(r'^(%?\S+)\s+.+=\s*.*', line)
        if not m:
            continue
        user_or_group = m.group(1)
        nopasswd = bool(re.search(r'NOPASSWD\s*:', line, re.IGNORECASE))
        # ALL commands: check if the commands part contains ALL (not just part of a path)
        # Strip the user and host=(runas) portion then check commands
        # Rough heuristic: after the last ')' or after the '=', check for standalone ALL
        after_eq = re.sub(r'^%?\S+\s+\S+=\s*(\([^)]*\)\s*)?', '', line)
        # Remove NOPASSWD: tag if present
        cmds_part = re.sub(r'NOPASSWD\s*:\s*', '', after_eq, flags=re.IGNORECASE).strip()
        # ALL commands if the commands section is exactly ALL or starts with ALL,
        # or contains a standalone ALL token
        all_commands = bool(re.search(r'(?<![/\w])ALL(?![/\w])', cmds_part))
        entries.append({
            'user_or_group': user_or_group,
            'spec': line,
            'nopasswd': nopasswd,
            'all_commands': all_commands,
        })
    return entries


def parse_sshd_config(content):
    """Parse sshd_config. Returns dict of lowercase key -> value."""
    cfg = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            cfg[parts[0].lower()] = parts[1].strip()
    return cfg


def parse_login_defs(content):
    """Parse /etc/login.defs. Returns dict of key -> value (uppercase keys)."""
    defs = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            defs[parts[0].upper()] = parts[1].strip()
    return defs


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
        'finding_type', 'username', 'detail', 'score', 'severity', 'recommendation',
    ]
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)
    os.chmod(path, 0o600)
    log.info(f"CSV report: {path}")


def write_html(report, path):
    findings = report['findings']
    summary = report['summary']
    generated = report['generated_at']
    hostname = report.get('hostname', 'unknown')

    risk_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745',
    }

    rows = ''
    for f in findings:
        color = risk_colors.get(f['severity'], '#999')
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['severity']}</span></td>
            <td style="font-weight:bold">{f['score']}/10</td>
            <td>{f['finding_type']}</td>
            <td>{f.get('username', '')}</td>
            <td style="font-size:0.85em">{f.get('detail', '')}</td>
            <td style="font-size:0.85em;color:#28a745">{f.get('recommendation', '')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Linux User Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; }}
  .header {{ background: linear-gradient(135deg, #2c3e50, #dc3545); color: white; padding: 30px 40px; }}
  .header h1 {{ margin: 0; font-size: 1.8em; }}
  .header p {{ margin: 5px 0 0; opacity: 0.8; }}
  .summary {{ display: flex; gap: 20px; padding: 20px 40px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 20px 30px; flex: 1; min-width: 140px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }}
  .card .num {{ font-size: 2.5em; font-weight: bold; }}
  .card .label {{ color: #666; font-size: 0.9em; margin-top: 4px; }}
  .critical .num {{ color: #dc3545; }} .high .num {{ color: #fd7e14; }}
  .medium .num {{ color: #ffc107; }} .low .num {{ color: #28a745; }}
  .total .num {{ color: #3498db; }}
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
  <h1>Linux User Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Host: {hostname} &nbsp;|&nbsp; {summary['total_findings']} findings</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total_findings']}</div><div class="label">Total Findings</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Severity</th><th>Score</th><th>Finding</th><th>Username</th><th>Detail</th><th>Recommendation</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">Linux User Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, 'w') as f:
        f.write(html)
    os.chmod(path, 0o600)
    log.info(f"HTML report: {path}")


# ── Stale user helper ─────────────────────────────────────────────────────────

def _parse_lastlog_date(username):
    """
    Run lastlog for a single user and return a datetime or None.
    Returns None if the user has never logged in or if parsing fails.
    """
    stdout, rc = run_command(['lastlog', '-u', username])
    if rc != 0 or not stdout:
        return None
    lines = stdout.strip().splitlines()
    # lastlog output: header line + data line
    if len(lines) < 2:
        return None
    data_line = lines[-1]
    if 'Never logged in' in data_line:
        return None
    # Typical format: "username  pts/0  1.2.3.4  Mon Jan  1 12:00:00 +0000 2024"
    # Try to extract date using regex for the trailing date portion
    # Format: "DDD MMM DD HH:MM:SS [+ZZZZ] YYYY"
    m = re.search(
        r'(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?:[+-]\d{4}\s+)?(\d{4})$',
        data_line
    )
    if not m:
        return None
    try:
        date_str = f"{m.group(1)} {m.group(2)}"
        return datetime.strptime(date_str, '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ── Main audit function ───────────────────────────────────────────────────────

def audit(output_prefix='user_report', fmt='all'):
    hostname = run_command(['hostname'])[0].strip() or 'unknown'
    findings = []

    passwd_content = read_file('/etc/passwd')
    shadow_content = read_file('/etc/shadow')
    sudoers_content = read_file('/etc/sudoers')
    sshd_content = read_file('/etc/ssh/sshd_config')
    login_defs_content = read_file('/etc/login.defs')

    users = parse_passwd(passwd_content)
    shadow = parse_shadow(shadow_content)
    sudoers_entries = parse_sudoers(sudoers_content)

    # Also parse sudoers.d files
    sudoers_d = Path('/etc/sudoers.d')
    sudoers_d_files = []
    if sudoers_d.exists():
        try:
            sudoers_d_files = list(sudoers_d.glob('*'))
        except OSError:
            pass
    for p in sudoers_d_files:
        try:
            sudoers_entries += parse_sudoers(read_file(str(p)))
        except Exception:
            pass

    ssh_cfg = parse_sshd_config(sshd_content)
    login_defs = parse_login_defs(login_defs_content)

    # ── Check: EmptyPasswordHash (score 10) ───────────────────────────────────
    for username, sdata in shadow.items():
        h = sdata.get('hash', '')
        # Truly empty — not locked ('!' / '!!' / '!*' / '*')
        if h == '':
            findings.append({
                'finding_type': 'EmptyPasswordHash',
                'username': username,
                'detail': f"User '{username}' has an empty password hash in /etc/shadow",
                'score': 10,
                'severity': severity_label(10),
                'recommendation': (
                    'Lock the account immediately with `passwd -l {username}` or set a strong password.'
                ),
            })

    # ── Check: UidZeroNonRoot (score 9) ──────────────────────────────────────
    for u in users:
        if u['uid'] == 0 and u['username'] != 'root':
            findings.append({
                'finding_type': 'UidZeroNonRoot',
                'username': u['username'],
                'detail': (
                    f"User '{u['username']}' has UID 0 (root-equivalent) but is not named 'root'"
                ),
                'score': 9,
                'severity': severity_label(9),
                'recommendation': (
                    'Remove or reassign this account. Only the canonical root account should have UID 0.'
                ),
            })

    # ── Check: DirectRootSSH (score 8) ───────────────────────────────────────
    permit_root = ssh_cfg.get('permitrootlogin', '').lower()
    if permit_root == 'yes':
        findings.append({
            'finding_type': 'DirectRootSSH',
            'username': 'root',
            'detail': "sshd_config PermitRootLogin is set to 'yes'",
            'score': 8,
            'severity': severity_label(8),
            'recommendation': (
                "Set 'PermitRootLogin no' (or 'prohibit-password') in /etc/ssh/sshd_config "
                "and restart sshd."
            ),
        })

    # ── Check: SSHPasswordAuthEnabled (score 6) ──────────────────────────────
    # Default when not set is 'yes', so flag if 'yes' OR if not present
    password_auth = ssh_cfg.get('passwordauthentication', 'yes').lower()
    if password_auth == 'yes':
        findings.append({
            'finding_type': 'SSHPasswordAuthEnabled',
            'username': '',
            'detail': (
                "sshd_config PasswordAuthentication is 'yes' (or not set — default is yes). "
                "Password-based SSH login is enabled."
            ),
            'score': 6,
            'severity': severity_label(6),
            'recommendation': (
                "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and use key-based "
                "authentication only. Restart sshd after the change."
            ),
        })

    # ── Check: PasswordlessRootEquivalent / SudoAllNopasswd / SudoAllCommandsGranted ──
    for entry in sudoers_entries:
        uog = entry.get('user_or_group', '')
        nopasswd = entry.get('nopasswd', False)
        all_cmds = entry.get('all_commands', False)

        if nopasswd and all_cmds:
            # NOPASSWD + ALL = most dangerous
            findings.append({
                'finding_type': 'PasswordlessRootEquivalent',
                'username': uog,
                'detail': (
                    f"Sudoers entry for '{uog}' grants NOPASSWD ALL — full root-equivalent "
                    f"access without a password. Rule: {entry['spec']}"
                ),
                'score': 10,
                'severity': severity_label(10),
                'recommendation': (
                    'Remove NOPASSWD or restrict to specific commands. Apply the principle of '
                    'least privilege; no user should have unrestricted passwordless sudo.'
                ),
            })
        elif nopasswd and not all_cmds:
            # NOPASSWD for specific commands
            findings.append({
                'finding_type': 'SudoAllNopasswd',
                'username': uog,
                'detail': (
                    f"Sudoers entry for '{uog}' grants NOPASSWD for specific commands. "
                    f"Rule: {entry['spec']}"
                ),
                'score': 9,
                'severity': severity_label(9),
                'recommendation': (
                    'Review whether NOPASSWD is necessary. Prefer requiring password confirmation '
                    'for all sudo usage.'
                ),
            })
        elif all_cmds and not nopasswd:
            # ALL commands with password
            findings.append({
                'finding_type': 'SudoAllCommandsGranted',
                'username': uog,
                'detail': (
                    f"Sudoers entry for '{uog}' grants ALL commands (with password). "
                    f"Rule: {entry['spec']}"
                ),
                'score': 7,
                'severity': severity_label(7),
                'recommendation': (
                    'Restrict sudo rules to only the specific commands required. '
                    'Avoid granting blanket ALL access.'
                ),
            })

    # ── Check: NoPasswordExpiry (score 5) ────────────────────────────────────
    # From login.defs
    try:
        defs_max = int(login_defs.get('PASS_MAX_DAYS', '99999'))
    except ValueError:
        defs_max = 99999
    if defs_max >= 99999:
        findings.append({
            'finding_type': 'NoPasswordExpiry',
            'username': '',
            'detail': (
                f"login.defs PASS_MAX_DAYS is {defs_max} — passwords never expire by default"
            ),
            'score': 5,
            'severity': severity_label(5),
            'recommendation': (
                'Set PASS_MAX_DAYS to 90 or fewer days in /etc/login.defs and apply per-account '
                'expiry with `chage -M 90 <username>`.'
            ),
        })

    # Per-user shadow max_days == 99999
    normal_users = {u['username'] for u in users if u['uid'] >= 1000 and u['username'] != 'nobody'}
    for username, sdata in shadow.items():
        if username not in normal_users:
            continue
        md = sdata.get('max_days')
        if md is not None and md >= 99999:
            findings.append({
                'finding_type': 'NoPasswordExpiry',
                'username': username,
                'detail': (
                    f"User '{username}' has PASS_MAX_DAYS={md} in /etc/shadow — password never expires"
                ),
                'score': 5,
                'severity': severity_label(5),
                'recommendation': (
                    f"Run `chage -M 90 {username}` to enforce a 90-day maximum password age."
                ),
            })

    # ── Check: WeakPasswordPolicy (score 6) ──────────────────────────────────
    try:
        pass_min_len = int(login_defs.get('PASS_MIN_LEN', '12'))
    except ValueError:
        pass_min_len = 12
    if pass_min_len < 12:
        findings.append({
            'finding_type': 'WeakPasswordPolicy',
            'username': '',
            'detail': (
                f"login.defs PASS_MIN_LEN is {pass_min_len} — minimum password length is below 12"
            ),
            'score': 6,
            'severity': severity_label(6),
            'recommendation': (
                'Set PASS_MIN_LEN to at least 12 in /etc/login.defs. Consider also enabling '
                'pam_pwquality for complexity requirements.'
            ),
        })

    # ── Check: StaleUser (score 4) ────────────────────────────────────────────
    inactive_shells = {'/sbin/nologin', '/bin/false', '/usr/sbin/nologin', '/usr/bin/nologin'}
    stale_threshold = NOW - timedelta(days=90)
    for u in users:
        if u['uid'] < 1000 or u['username'] == 'nobody':
            continue
        if u['shell'] in inactive_shells:
            continue
        last_login = _parse_lastlog_date(u['username'])
        if last_login is None:
            continue
        if last_login < stale_threshold:
            days_ago = (NOW - last_login).days
            findings.append({
                'finding_type': 'StaleUser',
                'username': u['username'],
                'detail': (
                    f"User '{u['username']}' last logged in {days_ago} days ago "
                    f"(threshold: 90 days)"
                ),
                'score': 4,
                'severity': severity_label(4),
                'recommendation': (
                    f"Disable or remove the account: `usermod -L {u['username']}` or "
                    f"`userdel -r {u['username']}`."
                ),
            })

    # ── Check: HomeDirectoryWorldReadable (score 4) ───────────────────────────
    for u in users:
        home = u.get('home', '')
        if not home or home in ('/', '/nonexistent', '/dev/null'):
            continue
        st = get_file_stat(home)
        if st is None:
            continue
        if st.st_mode & 0o004:
            findings.append({
                'finding_type': 'HomeDirectoryWorldReadable',
                'username': u['username'],
                'detail': (
                    f"Home directory '{home}' for user '{u['username']}' is world-readable "
                    f"(mode: {oct(st.st_mode & 0o777)})"
                ),
                'score': 4,
                'severity': severity_label(4),
                'recommendation': (
                    f"Run `chmod o-rx {home}` to remove world read/execute permissions."
                ),
            })

    # ── Check: WorldWritableSudoers (score 8) ────────────────────────────────
    sudoers_paths = ['/etc/sudoers']
    if sudoers_d.exists():
        try:
            sudoers_paths += [str(p) for p in sudoers_d.glob('*')]
        except OSError:
            pass
    for sp in sudoers_paths:
        st = get_file_stat(sp)
        if st is None:
            continue
        if st.st_mode & 0o002:
            findings.append({
                'finding_type': 'WorldWritableSudoers',
                'username': '',
                'detail': (
                    f"Sudoers file '{sp}' is world-writable (mode: {oct(st.st_mode & 0o777)}). "
                    "Any local user can escalate to root."
                ),
                'score': 8,
                'severity': severity_label(8),
                'recommendation': (
                    f"Run `chmod 440 {sp}` immediately. Sudoers files must not be world-writable."
                ),
            })

    # ── Sort and summarise ────────────────────────────────────────────────────
    findings.sort(key=lambda x: x['score'], reverse=True)

    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        risk_counts[f['severity']] = risk_counts.get(f['severity'], 0) + 1

    report = {
        'generated_at': NOW.isoformat(),
        'hostname': hostname,
        'summary': {
            'total_findings': len(findings),
            'users_scanned': len(users),
            'critical': risk_counts.get('CRITICAL', 0),
            'high': risk_counts.get('HIGH', 0),
            'medium': risk_counts.get('MEDIUM', 0),
            'low': risk_counts.get('LOW', 0),
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
    total = s['total_findings']
    critical = s['critical']
    high = s['high']
    medium = s['medium']
    low = s['low']
    users_count = s['users_scanned']

    print(f"""
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551      LINUX USER AUDITOR \u2014 SUMMARY        \u2551
\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563
\u2551  Hostname:            {hostname:<20}\u2551
\u2551  Users scanned:       {users_count:<20}\u2551
\u2551  Total findings:      {total:<20}\u2551
\u2551  CRITICAL:            {critical:<20}\u2551
\u2551  HIGH:                {high:<20}\u2551
\u2551  MEDIUM:              {medium:<20}\u2551
\u2551  LOW:                 {low:<20}\u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
""")

    return report


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Linux User & Sudo Auditor')
    parser.add_argument('--output', '-o', default='user_report')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'html', 'all', 'stdout'], default='all')
    args = parser.parse_args()
    audit(output_prefix=args.output, fmt=args.format)
