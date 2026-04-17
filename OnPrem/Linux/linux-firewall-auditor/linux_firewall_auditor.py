#!/usr/bin/env python3
"""
Linux Firewall & Logging Auditor
==================================
Auto-detects and audits the active firewall backend (iptables, nftables, ufw, firewalld)
and checks auditd and syslog configuration.

Usage:
    sudo python3 linux_firewall_auditor.py
    python3 linux_firewall_auditor.py --format html --output fw_report
    python3 linux_firewall_auditor.py --format all
"""

import os, sys, re, json, csv, html, argparse, logging, subprocess
from datetime import datetime, timezone
from pathlib import Path

# Shared CSS generator (repo root — 4 levels up from this auditor directory)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))
from report_utils import get_styles

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ── Thin wrappers (for mockability) ───────────────────────────────────────────

def run_command(cmd):
    """Run command list. Returns (stdout, returncode). ('', 1) on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout, r.returncode
    except Exception:
        return '', 1


def read_file(path):
    try:
        return Path(path).read_text(errors='replace')
    except (OSError, PermissionError):
        return ''


# ── Severity helper ───────────────────────────────────────────────────────────

def severity_label(score):
    if score >= 8: return 'CRITICAL'
    if score >= 6: return 'HIGH'
    if score >= 3: return 'MEDIUM'
    return 'LOW'


# ── Dangerous ports ───────────────────────────────────────────────────────────

DANGEROUS_PORTS = {
    22:    ('SSH', 7),
    23:    ('Telnet', 9),
    25:    ('SMTP', 6),
    445:   ('SMB', 9),
    3389:  ('RDP', 10),
    1433:  ('MSSQL', 8),
    3306:  ('MySQL', 8),
    5432:  ('PostgreSQL', 8),
    6379:  ('Redis', 8),
    27017: ('MongoDB', 8),
    2375:  ('Docker unencrypted', 9),
    9200:  ('Elasticsearch', 8),
    2379:  ('etcd', 9),
}


# ── Backend detection ─────────────────────────────────────────────────────────

def detect_backend():
    """Returns one of: 'ufw', 'firewalld', 'nftables', 'iptables', 'none'"""
    # Check ufw
    ufw_out, ufw_rc = run_command(['ufw', 'status'])
    if ufw_rc == 0 and 'Status: active' in ufw_out:
        return 'ufw'
    # Check firewalld
    fw_out, fw_rc = run_command(['firewall-cmd', '--state'])
    if fw_rc == 0 and 'running' in fw_out:
        return 'firewalld'
    # Check nftables
    nft_out, nft_rc = run_command(['nft', 'list', 'ruleset'])
    if nft_rc == 0 and nft_out.strip():
        return 'nftables'
    # Check iptables
    ipt_out, ipt_rc = run_command(['iptables', '-L', '-n'])
    if ipt_rc == 0:
        return 'iptables'
    return 'none'


# ── Firewall checks per backend ───────────────────────────────────────────────

def check_iptables(findings):
    # -v gives structured columns: pkts bytes target prot opt in out source destination [extensions]
    out, rc = run_command(['iptables', '-L', '-n', '-v'])

    # Check default INPUT policy
    if 'Chain INPUT (policy ACCEPT)' in out:
        findings.append({
            'finding_type': 'DefaultPolicyAccept',
            'detail': 'iptables INPUT chain default policy is ACCEPT — all unmatched traffic is allowed in.',
            'score': 8,
            'severity': severity_label(8),
            'recommendation': 'Set the default INPUT policy to DROP: iptables -P INPUT DROP',
            'cis_control': 'CIS 12',
        })

    # Parse rule lines by field position (cols: pkts bytes target prot opt in out src dst [ext...])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue
        target, prot, src, dst = parts[2], parts[3], parts[7], parts[8]
        ext = ' '.join(parts[9:]) if len(parts) > 9 else ''

        # Check for allow-all rule: ACCEPT with 0.0.0.0/0 as both source and destination
        if target == 'ACCEPT' and src == '0.0.0.0/0' and dst.startswith('0.0.0.0/0') and not ext:
            findings.append({
                'finding_type': 'AllowAllInputRule',
                'detail': 'An iptables ACCEPT rule allows all traffic from 0.0.0.0/0 to 0.0.0.0/0.',
                'score': 9,
                'severity': severity_label(9),
                'recommendation': 'Remove broad ACCEPT rules and replace with specific port/source allowances.',
                'cis_control': 'CIS 12',
            })

        # Check for dangerous ports open to all
        if target == 'ACCEPT' and prot == 'tcp' and src == '0.0.0.0/0':
            for port, (svc, score) in DANGEROUS_PORTS.items():
                if f'dpt:{port}' in ext or ext.rstrip().endswith(f':{port}'):
                    findings.append({
                        'finding_type': 'DangerousPortOpenToAll',
                        'detail': f'iptables allows unrestricted inbound access to port {port} ({svc}).',
                        'score': score,
                        'severity': severity_label(score),
                        'recommendation': f'Restrict port {port} ({svc}) to known source IPs or remove the rule.',
                        'port': port,
                        'service': svc,
                        'cis_control': 'CIS 12',
                    })

    # Check ip6tables
    out6, _ = run_command(['ip6tables', '-L', '-n'])
    if out6 and 'Chain INPUT (policy ACCEPT)' in out6:
        findings.append({
            'finding_type': 'IPv6FirewallMissing',
            'detail': 'ip6tables INPUT chain default policy is ACCEPT — IPv6 traffic is unrestricted.',
            'score': 7,
            'severity': severity_label(7),
            'recommendation': 'Apply equivalent ip6tables rules to your IPv4 iptables policy.',
            'cis_control': 'CIS 12',
        })


def check_ufw(findings):
    out, rc = run_command(['ufw', 'status', 'verbose'])
    if rc != 0:
        findings.append({
            'finding_type': 'UFWInactive',
            'detail': 'ufw is installed but returned a non-zero exit code — firewall may be inactive or broken.',
            'score': 8,
            'severity': severity_label(8),
            'recommendation': 'Enable ufw: ufw enable',
            'cis_control': 'CIS 12',
        })
        return

    if 'Default: allow (incoming)' in out:
        findings.append({
            'finding_type': 'DefaultPolicyAccept',
            'detail': 'ufw default incoming policy is allow — all unmatched inbound traffic is permitted.',
            'score': 8,
            'severity': severity_label(8),
            'recommendation': 'Set default incoming policy to deny: ufw default deny incoming',
            'cis_control': 'CIS 12',
        })

    for port, (svc, score) in DANGEROUS_PORTS.items():
        if re.search(rf'\b{port}\b.*ALLOW\s+(?:IN\s+)?Anywhere', out):
            findings.append({
                'finding_type': 'DangerousPortOpenToAll',
                'detail': f'ufw allows unrestricted inbound access to port {port} ({svc}) from anywhere.',
                'score': score,
                'severity': severity_label(score),
                'recommendation': f'Restrict port {port} ({svc}) to specific source IPs: ufw allow from <IP> to any port {port}',
                'port': port,
                'service': svc,
                'cis_control': 'CIS 12',
            })


def check_nftables(findings):
    out, rc = run_command(['nft', 'list', 'ruleset'])
    if rc != 0 or not out.strip():
        findings.append({
            'finding_type': 'NoFirewallActive',
            'detail': 'nftables returned no ruleset — no filtering rules are active.',
            'score': 9,
            'severity': severity_label(9),
            'recommendation': 'Define an nftables ruleset with default drop policies for input and forward chains.',
            'cis_control': 'CIS 12',
        })
        return

    if 'policy accept' in out.lower():
        findings.append({
            'finding_type': 'DefaultPolicyAccept',
            'detail': 'An nftables chain uses "policy accept" — unmatched packets are allowed through.',
            'score': 8,
            'severity': severity_label(8),
            'recommendation': 'Change chain policy to "drop": e.g., chain input { type filter hook input priority 0; policy drop; }',
            'cis_control': 'CIS 12',
        })


def check_auditd(findings):
    _, rc = run_command(['systemctl', 'is-active', 'auditd'])
    if rc != 0:
        findings.append({
            'finding_type': 'AuditdNotRunning',
            'detail': 'auditd service is not active — system call auditing is disabled.',
            'score': 7,
            'severity': severity_label(7),
            'recommendation': 'Install and enable auditd: apt install auditd && systemctl enable --now auditd',
            'cis_control': 'CIS 12',
        })
        return

    rules_out, _ = run_command(['auditctl', '-l'])
    if not rules_out.strip() or rules_out.strip() == '-a never,task':
        findings.append({
            'finding_type': 'AuditdNoExecRules',
            'detail': 'auditd is running but no meaningful audit rules are loaded (no execve or file-watch rules).',
            'score': 6,
            'severity': severity_label(6),
            'recommendation': 'Load a comprehensive ruleset, e.g. from /usr/share/doc/auditd/examples/rules/ or the CIS benchmark rules.',
            'cis_control': 'CIS 12',
        })

    # Check privileged command rules
    if not re.search(r'-a\s+always,exit.*-F\s+perm=x.*-F\s+auid>=', rules_out):
        findings.append({
            'finding_type': 'AuditdNoPrivilegedCommandRules',
            'detail': 'No auditd rules found that audit privileged command execution (perm=x auid>=).',
            'score': 5,
            'severity': severity_label(5),
            'recommendation': 'Add rules to audit privileged commands: -a always,exit -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged',
            'cis_control': 'CIS 12',
        })


def check_syslog(findings):
    syslog_active = False
    for svc in ['rsyslog', 'syslog', 'syslog-ng']:
        _, rc = run_command(['systemctl', 'is-active', svc])
        if rc == 0:
            syslog_active = True
            break
    if not syslog_active:
        findings.append({
            'finding_type': 'SyslogNotConfigured',
            'detail': 'No syslog daemon (rsyslog, syslog, syslog-ng) is active — system events are not being logged.',
            'score': 6,
            'severity': severity_label(6),
            'recommendation': 'Install and enable rsyslog: apt install rsyslog && systemctl enable --now rsyslog',
            'cis_control': 'CIS 12',
        })


def check_docker_iptables(findings):
    """Check if Docker is bypassing iptables."""
    docker_cfg = read_file('/etc/docker/daemon.json')
    if '"iptables": false' in docker_cfg or "'iptables': false" in docker_cfg:
        findings.append({
            'finding_type': 'DockerBypassesIptables',
            'detail': 'Docker daemon.json sets "iptables": false — Docker containers bypass host iptables rules.',
            'score': 8,
            'severity': severity_label(8),
            'recommendation': 'Remove "iptables": false from /etc/docker/daemon.json and restart Docker, or implement an alternative container network policy.',
            'cis_control': 'CIS 12',
        })

    # Also check if DOCKER chain exists in iptables
    out, rc = run_command(['iptables', '-L', 'DOCKER', '-n'])
    if rc == 0 and out.strip():
        # Docker is using iptables normally — not a finding
        pass


def check_firewall_persistence(findings, backend='iptables'):
    """Check if firewall rules will survive reboot (backend-aware)."""
    if backend == 'nftables':
        _, rc = run_command(['systemctl', 'is-enabled', 'nftables'])
        if rc != 0:
            findings.append({
                'finding_type': 'FirewallRulesFlushable',
                'detail': 'nftables service is not enabled — ruleset will be lost on reboot.',
                'score': 3,
                'severity': severity_label(3),
                'recommendation': 'Enable nftables persistence: systemctl enable nftables && nft list ruleset > /etc/nftables.conf',
                'cis_control': 'CIS 12',
            })
    elif backend == 'ufw':
        _, rc = run_command(['systemctl', 'is-enabled', 'ufw'])
        if rc != 0:
            findings.append({
                'finding_type': 'FirewallRulesFlushable',
                'detail': 'ufw service is not enabled — firewall will not start on reboot.',
                'score': 3,
                'severity': severity_label(3),
                'recommendation': 'Enable ufw on boot: systemctl enable ufw',
                'cis_control': 'CIS 12',
            })
    elif backend == 'firewalld':
        _, rc = run_command(['systemctl', 'is-enabled', 'firewalld'])
        if rc != 0:
            findings.append({
                'finding_type': 'FirewallRulesFlushable',
                'detail': 'firewalld service is not enabled — firewall will not start on reboot.',
                'score': 3,
                'severity': severity_label(3),
                'recommendation': 'Enable firewalld on boot: systemctl enable firewalld',
                'cis_control': 'CIS 12',
            })
    else:
        # iptables / unknown — check netfilter-persistent or iptables service
        _, rc = run_command(['systemctl', 'is-enabled', 'netfilter-persistent'])
        if rc != 0:
            _, rc2 = run_command(['systemctl', 'is-enabled', 'iptables'])
            if rc2 != 0:
                findings.append({
                    'finding_type': 'FirewallRulesFlushable',
                    'detail': 'Neither netfilter-persistent nor iptables service is enabled — firewall rules may be lost on reboot.',
                    'score': 3,
                    'severity': severity_label(3),
                    'recommendation': 'Install iptables-persistent and save rules: apt install iptables-persistent && netfilter-persistent save',
                    'cis_control': 'CIS 12',
                })


# ── Output formatters ─────────────────────────────────────────────────────────

def write_json(report, path):
    with open(path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    os.chmod(path, 0o600)
    log.info(f'JSON report: {path}')


def write_csv(findings, path):
    if not findings:
        return
    fieldnames = ['finding_type', 'detail', 'port', 'service', 'score', 'severity', 'recommendation', 'cis_control']
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)
    os.chmod(path, 0o600)
    log.info(f'CSV report: {path}')


def write_html(report, path):
    findings = report['findings']
    summary = report['summary']
    generated = report['generated_at']
    hostname = html.escape(report['hostname'])
    backend = html.escape(report['firewall_backend'])

    risk_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745',
    }

    rows = ''
    for f in findings:
        color = risk_colors.get(f.get('severity', 'LOW'), '#999')
        port_svc = html.escape(f'{f["port"]}/{f["service"]}') if f.get('port') else '—'
        rec = html.escape(f.get('recommendation', '') or '—')
        detail = html.escape(f.get('detail', '') or '—')
        finding_type = html.escape(f.get('finding_type', ''))
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:8px;font-weight:bold">{f.get('severity', '')}</span></td>
            <td style="font-weight:bold">{f.get('score', 0)}/10</td>
            <td>{finding_type}</td>
            <td style="font-size:0.85em">{detail}</td>
            <td><code>{port_svc}</code></td>
            <td style="font-size:0.85em;color:#555">{rec}</td>
        </tr>"""

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Firewall Security Audit Report</title>
<style>
{get_styles()}
</style>
</head>
<body>
<div class="header">
  <h1>Firewall Security Audit Report</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Host: {hostname} &nbsp;|&nbsp; Backend: {backend}</p>
</div>
<div class="summary">
  <div class="card total"><div class="num">{summary['total']}</div><div class="label">Total Findings</div></div>
  <div class="card critical"><div class="num">{summary['critical']}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{summary['medium']}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="label">Low</div></div>
</div>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Score</th>
        <th>Finding</th>
        <th>Detail</th>
        <th>Port/Service</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">Linux Firewall &amp; Logging Auditor &nbsp;|&nbsp; For internal security use only</div>
</body>
</html>"""

    with open(path, 'w') as f:
        f.write(html_out)
    os.chmod(path, 0o600)
    log.info(f'HTML report: {path}')


# ── Main audit function ───────────────────────────────────────────────────────

def run(output_prefix='fw_report', fmt='all'):
    hostname = run_command(['hostname'])[0].strip() or 'unknown'
    findings = []

    backend = detect_backend()

    if backend == 'none':
        findings.append({
            'finding_type': 'NoFirewallActive',
            'detail': 'No active firewall detected',
            'score': 9,
            'severity': 'CRITICAL',
            'recommendation': 'Install and enable a firewall (ufw, firewalld, or iptables).',
            'cis_control': 'CIS 12',
        })
    elif backend == 'ufw':
        check_ufw(findings)
    elif backend == 'firewalld':
        out, _ = run_command(['firewall-cmd', '--list-all'])
        if 'target: ACCEPT' in out:
            findings.append({
                'finding_type': 'DefaultPolicyAccept',
                'detail': 'firewalld zone target ACCEPT',
                'score': 8,
                'severity': severity_label(8),
                'recommendation': 'Set zone target to default or DROP.',
                'cis_control': 'CIS 12',
            })
    elif backend == 'nftables':
        check_nftables(findings)
    elif backend == 'iptables':
        check_iptables(findings)

    check_auditd(findings)
    check_syslog(findings)
    check_docker_iptables(findings)
    check_firewall_persistence(findings, backend=backend)

    # Ensure all findings have required fields
    for f in findings:
        f.setdefault('detail', f.get('finding_type', ''))
        f.setdefault('severity', severity_label(f.get('score', 0)))
        f.setdefault('recommendation', '')
        f.setdefault('port', None)
        f.setdefault('service', None)
        # Canonical schema fields (P1-3): exec_summary aggregates on these
        f.setdefault('risk_level', f.get('severity', 'LOW'))
        f.setdefault('remediation', f.get('recommendation', ''))

    findings.sort(key=lambda x: x['score'], reverse=True)

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    report = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'hostname': hostname,
        'firewall_backend': backend,
        'summary': {
            'total': len(findings),
            'critical': counts.get('CRITICAL', 0),
            'high': counts.get('HIGH', 0),
            'medium': counts.get('MEDIUM', 0),
            'low': counts.get('LOW', 0),
        },
        'findings': findings,
    }

    if fmt in ('json', 'all'):
        write_json(report, f'{output_prefix}.json')
    if fmt in ('csv', 'all'):
        write_csv(findings, f'{output_prefix}.csv')
    if fmt in ('html', 'all'):
        write_html(report, f'{output_prefix}.html')
    if fmt == 'stdout':
        print(json.dumps(report, indent=2))

    s = report['summary']
    print(f"""
╔══════════════════════════════════════════╗
║   LINUX FIREWALL AUDITOR — SUMMARY       ║
╠══════════════════════════════════════════╣
║  Hostname:            {hostname:<20}║
║  Backend:             {backend:<20}║
║  Total findings:      {s['total']:<20}║
║  CRITICAL:            {s['critical']:<20}║
║  HIGH:                {s['high']:<20}║
║  MEDIUM:              {s['medium']:<20}║
║  LOW:                 {s['low']:<20}║
╚══════════════════════════════════════════╝
""")
    return report


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Linux Firewall & Logging Auditor')
    parser.add_argument('--output', '-o', default='fw_report', help='Output file prefix (default: fw_report)')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'html', 'all', 'stdout'], default='all', help='Output format (default: all)')
    args = parser.parse_args()
    run(output_prefix=args.output, fmt=args.format)
