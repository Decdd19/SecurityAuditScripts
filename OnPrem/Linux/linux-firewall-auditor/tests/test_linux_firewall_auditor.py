import sys, os, json, csv
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import linux_firewall_auditor as lfa


# ── detect_backend ────────────────────────────────────────────────────────────

def test_detect_backend_ufw():
    with patch.object(lfa, 'run_command') as mock_cmd:
        mock_cmd.return_value = ('Status: active\n', 0)
        assert lfa.detect_backend() == 'ufw'


def test_detect_backend_ufw_inactive_falls_through():
    """ufw present but inactive should not match ufw."""
    def side_effect(cmd):
        if cmd[0] == 'ufw': return ('Status: inactive\n', 0)
        if cmd[0] == 'firewall-cmd': return ('running\n', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        assert lfa.detect_backend() == 'firewalld'


def test_detect_backend_firewalld():
    def side_effect(cmd):
        if cmd[0] == 'ufw': return ('', 1)
        if cmd[0] == 'firewall-cmd': return ('running\n', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        assert lfa.detect_backend() == 'firewalld'


def test_detect_backend_nftables():
    def side_effect(cmd):
        if cmd[0] == 'ufw': return ('', 1)
        if cmd[0] == 'firewall-cmd': return ('not running', 1)
        if cmd[0] == 'nft': return ('table inet filter {\n  chain input {}\n}\n', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        assert lfa.detect_backend() == 'nftables'


def test_detect_backend_nftables_empty_output_falls_through():
    """nft exits 0 but empty ruleset — should not match nftables."""
    def side_effect(cmd):
        if cmd[0] == 'ufw': return ('Status: inactive', 0)
        if cmd[0] == 'firewall-cmd': return ('not running', 1)
        if cmd[0] == 'nft': return ('', 0)           # empty ruleset
        if cmd[0] == 'iptables': return ('Chain INPUT (policy DROP)\n', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        assert lfa.detect_backend() == 'iptables'


def test_detect_backend_iptables():
    def side_effect(cmd):
        if cmd[0] == 'ufw': return ('Status: inactive', 0)
        if cmd[0] == 'firewall-cmd': return ('not running', 1)
        if cmd[0] == 'nft': return ('', 0)
        if cmd[0] == 'iptables': return ('Chain INPUT (policy DROP)\n', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        assert lfa.detect_backend() == 'iptables'


def test_detect_backend_none():
    with patch.object(lfa, 'run_command', return_value=('', 1)):
        assert lfa.detect_backend() == 'none'


# ── check_iptables ────────────────────────────────────────────────────────────

def test_check_iptables_default_accept():
    findings = []
    iptables_output = (
        'Chain INPUT (policy ACCEPT)\n'
        'Chain FORWARD (policy DROP)\n'
        'Chain OUTPUT (policy ACCEPT)\n'
    )
    with patch.object(lfa, 'run_command', return_value=(iptables_output, 0)):
        lfa.check_iptables(findings)
    assert any(f['finding_type'] == 'DefaultPolicyAccept' for f in findings)


def test_check_iptables_default_accept_score():
    findings = []
    with patch.object(lfa, 'run_command',
                      return_value=('Chain INPUT (policy ACCEPT)\n', 0)):
        lfa.check_iptables(findings)
    match = next(f for f in findings if f['finding_type'] == 'DefaultPolicyAccept')
    assert match['score'] == 8
    assert match['severity'] == 'CRITICAL'


def test_check_iptables_allow_all():
    findings = []
    # -v format: pkts bytes target prot opt in out source destination [ext]
    iptables_output = (
        'Chain INPUT (policy DROP)\n'
        '    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0\n'
    )
    with patch.object(lfa, 'run_command', return_value=(iptables_output, 0)):
        lfa.check_iptables(findings)
    assert any(f['finding_type'] == 'AllowAllInputRule' for f in findings)


def test_check_iptables_allow_all_score():
    findings = []
    output = 'Chain INPUT (policy DROP)\n    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0\n'
    with patch.object(lfa, 'run_command', return_value=(output, 0)):
        lfa.check_iptables(findings)
    match = next(f for f in findings if f['finding_type'] == 'AllowAllInputRule')
    assert match['score'] == 9


def test_check_iptables_dangerous_port():
    findings = []
    output = (
        'Chain INPUT (policy DROP)\n'
        '    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3306\n'
    )
    with patch.object(lfa, 'run_command', return_value=(output, 0)):
        lfa.check_iptables(findings)
    assert any(
        f['finding_type'] == 'DangerousPortOpenToAll' and f['port'] == 3306
        for f in findings
    )


def test_check_iptables_ipv6_accept():
    findings = []
    def side_effect(cmd):
        if cmd[0] == 'iptables': return ('Chain INPUT (policy DROP)\n', 0)
        if cmd[0] == 'ip6tables': return ('Chain INPUT (policy ACCEPT)\n', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_iptables(findings)
    assert any(f['finding_type'] == 'IPv6FirewallMissing' for f in findings)


def test_check_iptables_clean():
    findings = []
    clean_output = 'Chain INPUT (policy DROP)\nChain FORWARD (policy DROP)\nChain OUTPUT (policy ACCEPT)\n'
    with patch.object(lfa, 'run_command', return_value=(clean_output, 0)):
        lfa.check_iptables(findings)
    assert not any(f['finding_type'] == 'DefaultPolicyAccept' for f in findings)
    assert not any(f['finding_type'] == 'AllowAllInputRule' for f in findings)


# ── check_ufw ─────────────────────────────────────────────────────────────────

def test_check_ufw_inactive_rc_nonzero():
    """rc != 0 triggers UFWInactive."""
    findings = []
    with patch.object(lfa, 'run_command', return_value=('', 1)):
        lfa.check_ufw(findings)
    assert any(f['finding_type'] == 'UFWInactive' for f in findings)


def test_check_ufw_inactive_returns_early():
    """UFWInactive finding causes early return; no DefaultPolicyAccept."""
    findings = []
    with patch.object(lfa, 'run_command', return_value=('', 1)):
        lfa.check_ufw(findings)
    assert not any(f['finding_type'] == 'DefaultPolicyAccept' for f in findings)


def test_check_ufw_default_allow():
    findings = []
    ufw_verbose = 'Status: active\nDefault: allow (incoming), deny (outgoing)\n'
    with patch.object(lfa, 'run_command', return_value=(ufw_verbose, 0)):
        lfa.check_ufw(findings)
    assert any(f['finding_type'] == 'DefaultPolicyAccept' for f in findings)


def test_check_ufw_default_allow_score():
    findings = []
    ufw_verbose = 'Status: active\nDefault: allow (incoming), deny (outgoing)\n'
    with patch.object(lfa, 'run_command', return_value=(ufw_verbose, 0)):
        lfa.check_ufw(findings)
    match = next(f for f in findings if f['finding_type'] == 'DefaultPolicyAccept')
    assert match['score'] == 8


def test_check_ufw_dangerous_port_rdp():
    findings = []
    ufw_verbose = (
        'Status: active\n'
        'Default: deny (incoming), allow (outgoing)\n'
        '3389                       ALLOW IN    Anywhere\n'
    )
    with patch.object(lfa, 'run_command', return_value=(ufw_verbose, 0)):
        lfa.check_ufw(findings)
    assert any(
        f['finding_type'] == 'DangerousPortOpenToAll' and f['port'] == 3389
        for f in findings
    )


def test_check_ufw_clean():
    findings = []
    ufw_verbose = 'Status: active\nDefault: deny (incoming), allow (outgoing)\n'
    with patch.object(lfa, 'run_command', return_value=(ufw_verbose, 0)):
        lfa.check_ufw(findings)
    assert findings == []


# ── check_nftables ────────────────────────────────────────────────────────────

def test_check_nftables_no_ruleset():
    findings = []
    with patch.object(lfa, 'run_command', return_value=('', 1)):
        lfa.check_nftables(findings)
    assert any(f['finding_type'] == 'NoFirewallActive' for f in findings)


def test_check_nftables_empty_output():
    findings = []
    with patch.object(lfa, 'run_command', return_value=('   \n', 0)):
        lfa.check_nftables(findings)
    assert any(f['finding_type'] == 'NoFirewallActive' for f in findings)


def test_check_nftables_policy_accept():
    findings = []
    ruleset = 'table inet filter {\n  chain input {\n    type filter hook input priority 0; policy accept;\n  }\n}\n'
    with patch.object(lfa, 'run_command', return_value=(ruleset, 0)):
        lfa.check_nftables(findings)
    assert any(f['finding_type'] == 'DefaultPolicyAccept' for f in findings)


def test_check_nftables_policy_drop_clean():
    findings = []
    ruleset = 'table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n  }\n}\n'
    with patch.object(lfa, 'run_command', return_value=(ruleset, 0)):
        lfa.check_nftables(findings)
    assert not any(f['finding_type'] == 'DefaultPolicyAccept' for f in findings)
    assert not any(f['finding_type'] == 'NoFirewallActive' for f in findings)


# ── check_auditd ──────────────────────────────────────────────────────────────

def test_check_auditd_not_running():
    findings = []
    with patch.object(lfa, 'run_command', return_value=('inactive', 1)):
        lfa.check_auditd(findings)
    assert any(f['finding_type'] == 'AuditdNotRunning' for f in findings)


def test_check_auditd_not_running_score():
    findings = []
    with patch.object(lfa, 'run_command', return_value=('inactive', 1)):
        lfa.check_auditd(findings)
    match = next(f for f in findings if f['finding_type'] == 'AuditdNotRunning')
    assert match['score'] == 7
    assert match['severity'] == 'HIGH'


def test_check_auditd_not_running_returns_early():
    """If auditd is not running, no AuditdNoExecRules finding should be added."""
    findings = []
    with patch.object(lfa, 'run_command', return_value=('inactive', 1)):
        lfa.check_auditd(findings)
    assert not any(f['finding_type'] == 'AuditdNoExecRules' for f in findings)


def test_check_auditd_no_exec_rules_never_task():
    findings = []
    def side_effect(cmd):
        if 'is-active' in cmd: return ('active', 0)
        if 'auditctl' in cmd: return ('-a never,task\n', 0)
        return ('', 0)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_auditd(findings)
    assert any(f['finding_type'] == 'AuditdNoExecRules' for f in findings)


def test_check_auditd_no_exec_rules_empty():
    findings = []
    def side_effect(cmd):
        if 'is-active' in cmd: return ('active', 0)
        if 'auditctl' in cmd: return ('', 0)
        return ('', 0)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_auditd(findings)
    assert any(f['finding_type'] == 'AuditdNoExecRules' for f in findings)


def test_check_auditd_no_privileged_command_rules():
    findings = []
    # Has some rules but not privileged command rules
    rules = '-a always,exit -F arch=b64 -S open -k file_open\n'
    def side_effect(cmd):
        if 'is-active' in cmd: return ('active', 0)
        if 'auditctl' in cmd: return (rules, 0)
        return ('', 0)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_auditd(findings)
    assert any(f['finding_type'] == 'AuditdNoPrivilegedCommandRules' for f in findings)


def test_check_auditd_with_privileged_command_rules():
    findings = []
    # Has privileged command rules matching the pattern
    rules = '-a always,exit -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged\n'
    def side_effect(cmd):
        if 'is-active' in cmd: return ('active', 0)
        if 'auditctl' in cmd: return (rules, 0)
        return ('', 0)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_auditd(findings)
    assert not any(f['finding_type'] == 'AuditdNoPrivilegedCommandRules' for f in findings)


# ── check_syslog ──────────────────────────────────────────────────────────────

def test_check_syslog_not_running():
    findings = []
    with patch.object(lfa, 'run_command', return_value=('inactive', 1)):
        lfa.check_syslog(findings)
    assert any(f['finding_type'] == 'SyslogNotConfigured' for f in findings)


def test_check_syslog_not_running_score():
    findings = []
    with patch.object(lfa, 'run_command', return_value=('inactive', 1)):
        lfa.check_syslog(findings)
    match = next(f for f in findings if f['finding_type'] == 'SyslogNotConfigured')
    assert match['score'] == 6
    assert match['severity'] == 'HIGH'


def test_check_syslog_rsyslog_active():
    findings = []
    def side_effect(cmd):
        if 'rsyslog' in cmd: return ('active', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_syslog(findings)
    assert not any(f['finding_type'] == 'SyslogNotConfigured' for f in findings)


def test_check_syslog_syslog_ng_active():
    findings = []
    def side_effect(cmd):
        if 'rsyslog' in cmd: return ('inactive', 1)
        if 'syslog-ng' in cmd: return ('active', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_syslog(findings)
    assert not any(f['finding_type'] == 'SyslogNotConfigured' for f in findings)


def test_check_syslog_fallback_syslog_active():
    findings = []
    def side_effect(cmd):
        if 'rsyslog' in cmd: return ('inactive', 1)
        if cmd[-1] == 'syslog': return ('active', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_syslog(findings)
    assert not any(f['finding_type'] == 'SyslogNotConfigured' for f in findings)


# ── check_docker_iptables ─────────────────────────────────────────────────────

def test_check_docker_bypasses_iptables():
    findings = []
    daemon_json = '{"iptables": false, "log-driver": "json-file"}'
    with patch.object(lfa, 'read_file', return_value=daemon_json), \
         patch.object(lfa, 'run_command', return_value=('', 1)):
        lfa.check_docker_iptables(findings)
    assert any(f['finding_type'] == 'DockerBypassesIptables' for f in findings)


def test_check_docker_bypasses_iptables_score():
    findings = []
    daemon_json = '{"iptables": false}'
    with patch.object(lfa, 'read_file', return_value=daemon_json), \
         patch.object(lfa, 'run_command', return_value=('', 1)):
        lfa.check_docker_iptables(findings)
    match = next(f for f in findings if f['finding_type'] == 'DockerBypassesIptables')
    assert match['score'] == 8
    assert match['severity'] == 'CRITICAL'


def test_check_docker_no_daemon_json():
    findings = []
    with patch.object(lfa, 'read_file', return_value=''), \
         patch.object(lfa, 'run_command', return_value=('', 1)):
        lfa.check_docker_iptables(findings)
    assert not any(f['finding_type'] == 'DockerBypassesIptables' for f in findings)


def test_check_docker_normal_iptables():
    """DOCKER chain present in iptables — not a finding."""
    findings = []
    with patch.object(lfa, 'read_file', return_value='{}'), \
         patch.object(lfa, 'run_command', return_value=('Chain DOCKER (1 references)\n', 0)):
        lfa.check_docker_iptables(findings)
    assert findings == []


# ── check_firewall_persistence ────────────────────────────────────────────────

def test_check_firewall_persistence_not_enabled():
    findings = []
    with patch.object(lfa, 'run_command', return_value=('disabled', 1)):
        lfa.check_firewall_persistence(findings)
    assert any(f['finding_type'] == 'FirewallRulesFlushable' for f in findings)


def test_check_firewall_persistence_not_enabled_score():
    findings = []
    with patch.object(lfa, 'run_command', return_value=('disabled', 1)):
        lfa.check_firewall_persistence(findings)
    match = next(f for f in findings if f['finding_type'] == 'FirewallRulesFlushable')
    assert match['score'] == 3
    assert match['severity'] == 'MEDIUM'


def test_check_firewall_persistence_netfilter_enabled():
    findings = []
    def side_effect(cmd):
        if 'netfilter-persistent' in cmd: return ('enabled', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_firewall_persistence(findings)
    assert not any(f['finding_type'] == 'FirewallRulesFlushable' for f in findings)


def test_check_firewall_persistence_iptables_service_enabled():
    findings = []
    def side_effect(cmd):
        if 'netfilter-persistent' in cmd: return ('disabled', 1)
        if 'iptables' in cmd: return ('enabled', 0)
        return ('', 1)
    with patch.object(lfa, 'run_command', side_effect=side_effect):
        lfa.check_firewall_persistence(findings)
    assert not any(f['finding_type'] == 'FirewallRulesFlushable' for f in findings)


# ── DANGEROUS_PORTS ───────────────────────────────────────────────────────────

def test_dangerous_ports_contains_rdp():
    assert 3389 in lfa.DANGEROUS_PORTS


def test_dangerous_ports_contains_smb():
    assert 445 in lfa.DANGEROUS_PORTS


def test_dangerous_ports_contains_ssh():
    assert 22 in lfa.DANGEROUS_PORTS


def test_dangerous_ports_contains_telnet():
    assert 23 in lfa.DANGEROUS_PORTS


def test_dangerous_ports_contains_docker():
    assert 2375 in lfa.DANGEROUS_PORTS


def test_dangerous_ports_rdp_max_score():
    _, score = lfa.DANGEROUS_PORTS[3389]
    assert score == 10


def test_dangerous_ports_telnet_score():
    _, score = lfa.DANGEROUS_PORTS[23]
    assert score == 9


def test_dangerous_ports_structure():
    for port, (svc, score) in lfa.DANGEROUS_PORTS.items():
        assert isinstance(port, int)
        assert isinstance(svc, str)
        assert 1 <= score <= 10


# ── severity_label ────────────────────────────────────────────────────────────

def test_severity_label_critical_8():
    assert lfa.severity_label(8) == 'CRITICAL'


def test_severity_label_critical():
    assert lfa.severity_label(9) == 'CRITICAL'


def test_severity_label_critical_10():
    assert lfa.severity_label(10) == 'CRITICAL'


def test_severity_label_high():
    assert lfa.severity_label(7) == 'HIGH'


def test_severity_label_high_6():
    assert lfa.severity_label(6) == 'HIGH'


def test_severity_label_medium():
    assert lfa.severity_label(4) == 'MEDIUM'


def test_severity_label_medium_3():
    assert lfa.severity_label(3) == 'MEDIUM'


def test_severity_label_low():
    assert lfa.severity_label(1) == 'LOW'


def test_severity_label_low_0():
    assert lfa.severity_label(0) == 'LOW'


def test_severity_label_boundary_below_critical():
    assert lfa.severity_label(7) == 'HIGH'


def test_severity_label_boundary_below_high():
    assert lfa.severity_label(5) == 'MEDIUM'


def test_severity_label_boundary_below_medium():
    assert lfa.severity_label(2) == 'LOW'


# ── read_file ─────────────────────────────────────────────────────────────────

def test_read_file_returns_empty_on_missing(tmp_path):
    result = lfa.read_file(str(tmp_path / 'nonexistent.txt'))
    assert result == ''


def test_read_file_returns_content(tmp_path):
    p = tmp_path / 'test.txt'
    p.write_text('hello world')
    assert lfa.read_file(str(p)) == 'hello world'


# ── run_command ───────────────────────────────────────────────────────────────

def test_run_command_returns_empty_on_exception():
    with patch('subprocess.run', side_effect=FileNotFoundError):
        out, rc = lfa.run_command(['nonexistent_binary'])
    assert out == ''
    assert rc == 1


def test_run_command_success():
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='hello\n', returncode=0)
        out, rc = lfa.run_command(['echo', 'hello'])
    assert out == 'hello\n'
    assert rc == 0


# ── audit integration ─────────────────────────────────────────────────────────

def test_audit_no_firewall():
    with patch.object(lfa, 'detect_backend', return_value='none'), \
         patch.object(lfa, 'check_auditd'), \
         patch.object(lfa, 'check_syslog'), \
         patch.object(lfa, 'check_docker_iptables'), \
         patch.object(lfa, 'check_firewall_persistence'), \
         patch.object(lfa, 'run_command', return_value=('testhost', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lfa.run(fmt='stdout')
    assert any(f['finding_type'] == 'NoFirewallActive' for f in report['findings'])


def test_audit_returns_report_structure():
    with patch.object(lfa, 'detect_backend', return_value='none'), \
         patch.object(lfa, 'check_auditd'), \
         patch.object(lfa, 'check_syslog'), \
         patch.object(lfa, 'check_docker_iptables'), \
         patch.object(lfa, 'check_firewall_persistence'), \
         patch.object(lfa, 'run_command', return_value=('myhost', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lfa.run(fmt='stdout')
    assert 'generated_at' in report
    assert 'hostname' in report
    assert 'firewall_backend' in report
    assert 'summary' in report
    assert 'findings' in report


def test_audit_summary_counts():
    with patch.object(lfa, 'detect_backend', return_value='none'), \
         patch.object(lfa, 'check_auditd'), \
         patch.object(lfa, 'check_syslog'), \
         patch.object(lfa, 'check_docker_iptables'), \
         patch.object(lfa, 'check_firewall_persistence'), \
         patch.object(lfa, 'run_command', return_value=('host1', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lfa.run(fmt='stdout')
    s = report['summary']
    assert s['total'] == len(report['findings'])
    assert s['critical'] + s['high'] + s['medium'] + s['low'] == s['total']


def test_audit_findings_sorted_by_score_descending():
    with patch.object(lfa, 'detect_backend', return_value='none'), \
         patch.object(lfa, 'check_auditd'), \
         patch.object(lfa, 'check_syslog'), \
         patch.object(lfa, 'check_docker_iptables'), \
         patch.object(lfa, 'check_firewall_persistence'), \
         patch.object(lfa, 'run_command', return_value=('host', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lfa.run(fmt='stdout')
    scores = [f['score'] for f in report['findings']]
    assert scores == sorted(scores, reverse=True)


def test_audit_firewall_backend_recorded():
    with patch.object(lfa, 'detect_backend', return_value='ufw'), \
         patch.object(lfa, 'check_ufw'), \
         patch.object(lfa, 'check_auditd'), \
         patch.object(lfa, 'check_syslog'), \
         patch.object(lfa, 'check_docker_iptables'), \
         patch.object(lfa, 'check_firewall_persistence'), \
         patch.object(lfa, 'run_command', return_value=('myhost', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lfa.run(fmt='stdout')
    assert report['firewall_backend'] == 'ufw'


def test_audit_calls_check_ufw_when_backend_ufw():
    with patch.object(lfa, 'detect_backend', return_value='ufw'), \
         patch.object(lfa, 'check_ufw') as mock_ufw, \
         patch.object(lfa, 'check_auditd'), \
         patch.object(lfa, 'check_syslog'), \
         patch.object(lfa, 'check_docker_iptables'), \
         patch.object(lfa, 'check_firewall_persistence'), \
         patch.object(lfa, 'run_command', return_value=('host', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        lfa.run(fmt='stdout')
    mock_ufw.assert_called_once()


def test_audit_calls_check_iptables_when_backend_iptables():
    with patch.object(lfa, 'detect_backend', return_value='iptables'), \
         patch.object(lfa, 'check_iptables') as mock_ipt, \
         patch.object(lfa, 'check_auditd'), \
         patch.object(lfa, 'check_syslog'), \
         patch.object(lfa, 'check_docker_iptables'), \
         patch.object(lfa, 'check_firewall_persistence'), \
         patch.object(lfa, 'run_command', return_value=('host', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        lfa.run(fmt='stdout')
    mock_ipt.assert_called_once()


def test_audit_calls_check_nftables_when_backend_nftables():
    with patch.object(lfa, 'detect_backend', return_value='nftables'), \
         patch.object(lfa, 'check_nftables') as mock_nft, \
         patch.object(lfa, 'check_auditd'), \
         patch.object(lfa, 'check_syslog'), \
         patch.object(lfa, 'check_docker_iptables'), \
         patch.object(lfa, 'check_firewall_persistence'), \
         patch.object(lfa, 'run_command', return_value=('host', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        lfa.run(fmt='stdout')
    mock_nft.assert_called_once()


def test_audit_always_calls_ancillary_checks():
    """check_auditd, check_syslog, check_docker_iptables, check_firewall_persistence
    are called regardless of the detected backend."""
    with patch.object(lfa, 'detect_backend', return_value='none'), \
         patch.object(lfa, 'check_auditd') as mock_auditd, \
         patch.object(lfa, 'check_syslog') as mock_syslog, \
         patch.object(lfa, 'check_docker_iptables') as mock_docker, \
         patch.object(lfa, 'check_firewall_persistence') as mock_persist, \
         patch.object(lfa, 'run_command', return_value=('host', 0)), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        lfa.run(fmt='stdout')
    mock_auditd.assert_called_once()
    mock_syslog.assert_called_once()
    mock_docker.assert_called_once()
    mock_persist.assert_called_once()


# ── write_json / write_csv / write_html ───────────────────────────────────────

def test_write_json_creates_file(tmp_path):
    report = {'generated_at': 'now', 'findings': [], 'summary': {}}
    path = str(tmp_path / 'out.json')
    lfa.write_json(report, path)
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert data['generated_at'] == 'now'


def test_write_json_sets_permissions(tmp_path):
    path = str(tmp_path / 'out.json')
    lfa.write_json({}, path)
    assert oct(os.stat(path).st_mode)[-3:] == '600'


def test_write_csv_creates_file(tmp_path):
    findings = [{'finding_type': 'Test', 'detail': 'x', 'port': None, 'service': None, 'score': 5, 'severity': 'MEDIUM', 'recommendation': 'fix'}]
    path = str(tmp_path / 'out.csv')
    lfa.write_csv(findings, path)
    assert os.path.exists(path)


def test_write_csv_sets_permissions(tmp_path):
    findings = [{'finding_type': 'T', 'detail': '', 'port': None, 'service': None, 'score': 1, 'severity': 'LOW', 'recommendation': ''}]
    path = str(tmp_path / 'out.csv')
    lfa.write_csv(findings, path)
    assert oct(os.stat(path).st_mode)[-3:] == '600'


def test_write_csv_empty_no_file(tmp_path):
    path = str(tmp_path / 'out.csv')
    lfa.write_csv([], path)
    assert not os.path.exists(path)


def test_write_csv_correct_headers(tmp_path):
    findings = [{'finding_type': 'T', 'detail': 'd', 'port': 22, 'service': 'SSH', 'score': 7, 'severity': 'HIGH', 'recommendation': 'fix'}]
    path = str(tmp_path / 'out.csv')
    lfa.write_csv(findings, path)
    with open(path) as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
    assert 'finding_type' in headers
    assert 'severity' in headers
    assert 'recommendation' in headers


def test_write_html_creates_file(tmp_path):
    report = {
        'generated_at': 'now',
        'hostname': 'testhost',
        'firewall_backend': 'ufw',
        'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'findings': [],
    }
    path = str(tmp_path / 'out.html')
    lfa.write_html(report, path)
    assert os.path.exists(path)


def test_write_html_sets_permissions(tmp_path):
    report = {
        'generated_at': 'now',
        'hostname': 'h',
        'firewall_backend': 'none',
        'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'findings': [],
    }
    path = str(tmp_path / 'out.html')
    lfa.write_html(report, path)
    assert oct(os.stat(path).st_mode)[-3:] == '600'


def test_write_html_contains_title(tmp_path):
    report = {
        'generated_at': 'now',
        'hostname': 'h',
        'firewall_backend': 'iptables',
        'summary': {'total': 1, 'critical': 1, 'high': 0, 'medium': 0, 'low': 0},
        'findings': [{'finding_type': 'DefaultPolicyAccept', 'detail': 'd', 'port': None, 'service': None, 'score': 8, 'severity': 'CRITICAL', 'recommendation': 'fix'}],
    }
    path = str(tmp_path / 'out.html')
    lfa.write_html(report, path)
    content = Path(path).read_text()
    assert 'Linux Firewall' in content
    assert 'Audit Report' in content
