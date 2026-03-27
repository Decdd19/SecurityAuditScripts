"""Tests for linux_ssh_auditor.py"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch
import linux_ssh_auditor as lsa


# ── run_command ────────────────────────────────────────────────────────────────

def test_run_command_returns_tuple_on_bad_command():
    stdout, rc = lsa.run_command(['__nonexistent_cmd_xyz__'])
    assert isinstance(stdout, str)
    assert isinstance(rc, int)


# ── get_effective_config ───────────────────────────────────────────────────────

def test_get_effective_config_parses_output():
    sshd_output = "permitrootlogin no\npasswordauthentication yes\nport 22\n"
    with patch.object(lsa, 'run_command', return_value=(sshd_output, 0)):
        config = lsa.get_effective_config()
    assert config['permitrootlogin'] == 'no'
    assert config['passwordauthentication'] == 'yes'
    assert config['port'] == '22'


def test_get_effective_config_returns_empty_on_failure():
    with patch.object(lsa, 'run_command', return_value=('', 1)):
        config = lsa.get_effective_config()
    assert config == {}


def test_get_effective_config_lowercases_keys():
    with patch.object(lsa, 'run_command', return_value=('PermitRootLogin no\n', 0)):
        config = lsa.get_effective_config()
    assert 'permitrootlogin' in config


def test_get_effective_config_handles_multi_word_values():
    with patch.object(lsa, 'run_command', return_value=('ciphers aes128-ctr,aes256-ctr\n', 0)):
        config = lsa.get_effective_config()
    assert config['ciphers'] == 'aes128-ctr,aes256-ctr'


# ── analyse_ssh ────────────────────────────────────────────────────────────────

def test_analyse_ssh_compliant_exact_match():
    """permitrootlogin=no → compliant=True."""
    config = {'permitrootlogin': 'no'}
    findings = lsa.analyse_ssh(config)
    root_finding = next(f for f in findings if f['param'] == 'permitrootlogin')
    assert root_finding['compliant'] is True


def test_analyse_ssh_non_compliant_exact_match():
    """permitrootlogin=yes → compliant=False, severity=CRITICAL."""
    config = {'permitrootlogin': 'yes'}
    findings = lsa.analyse_ssh(config)
    root_finding = next(f for f in findings if f['param'] == 'permitrootlogin')
    assert root_finding['compliant'] is False
    assert root_finding['severity_if_wrong'] == 'CRITICAL'


def test_analyse_ssh_missing_key_returns_none():
    """Key absent from sshd -T → compliant=None (SKIP)."""
    config = {}
    findings = lsa.analyse_ssh(config)
    root_finding = next(f for f in findings if f['param'] == 'permitrootlogin')
    assert root_finding['compliant'] is None


def test_analyse_ssh_maxauthtries_pass_at_boundary():
    """maxauthtries=4 → compliant=True (<=4 passes)."""
    config = {'maxauthtries': '4'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'maxauthtries')
    assert f['compliant'] is True


def test_analyse_ssh_maxauthtries_fail_above_boundary():
    """maxauthtries=5 → compliant=False."""
    config = {'maxauthtries': '5'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'maxauthtries')
    assert f['compliant'] is False


def test_analyse_ssh_logingracetime_pass():
    """logingracetime=60 → compliant=True (<=60)."""
    config = {'logingracetime': '60'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'logingracetime')
    assert f['compliant'] is True


def test_analyse_ssh_logingracetime_fail():
    """logingracetime=120 → compliant=False."""
    config = {'logingracetime': '120'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'logingracetime')
    assert f['compliant'] is False


def test_analyse_ssh_loglevel_verbose_passes():
    """loglevel=VERBOSE → compliant=True."""
    config = {'loglevel': 'VERBOSE'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'loglevel')
    assert f['compliant'] is True


def test_analyse_ssh_loglevel_info_passes():
    """loglevel=INFO → compliant=True."""
    config = {'loglevel': 'INFO'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'loglevel')
    assert f['compliant'] is True


def test_analyse_ssh_loglevel_case_insensitive():
    """loglevel=verbose (lowercase) → compliant=True."""
    config = {'loglevel': 'verbose'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'loglevel')
    assert f['compliant'] is True


def test_analyse_ssh_loglevel_quiet_fails():
    """loglevel=QUIET → compliant=False."""
    config = {'loglevel': 'QUIET'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'loglevel')
    assert f['compliant'] is False


def test_analyse_ssh_finding_has_required_fields():
    """Every finding has all required fields."""
    findings = lsa.analyse_ssh({'permitrootlogin': 'no'})
    for f in findings:
        for field in ('param', 'expected', 'actual', 'compliant',
                      'severity_if_wrong', 'description', 'flag',
                      'remediation', 'risk_level'):
            assert field in f, f"Missing field '{field}' in finding for {f.get('param')}"


def test_analyse_ssh_clientaliveinterval_pass():
    """clientaliveinterval=300 → compliant=True (<=300)."""
    config = {'clientaliveinterval': '300'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'clientaliveinterval')
    assert f['compliant'] is True


def test_analyse_ssh_clientalivecountmax_fail():
    """clientalivecountmax=5 → compliant=False (>3)."""
    config = {'clientalivecountmax': '5'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'clientalivecountmax')
    assert f['compliant'] is False


# ── Crypto checks ──────────────────────────────────────────────────────────────

def test_analyse_ssh_ciphers_clean_passes():
    """Only strong ciphers → compliant=True."""
    config = {'ciphers': 'aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'ciphers')
    assert f['compliant'] is True


def test_analyse_ssh_ciphers_cbc_fails():
    """CBC cipher present → compliant=False, severity=HIGH."""
    config = {'ciphers': 'aes128-ctr,aes256-cbc'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'ciphers')
    assert f['compliant'] is False
    assert f['severity_if_wrong'] == 'HIGH'


def test_analyse_ssh_ciphers_arcfour_fails():
    """arcfour cipher → compliant=False."""
    config = {'ciphers': 'arcfour,aes128-ctr'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'ciphers')
    assert f['compliant'] is False


def test_analyse_ssh_macs_clean_passes():
    """Strong MACs only → compliant=True."""
    config = {'macs': 'hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'macs')
    assert f['compliant'] is True


def test_analyse_ssh_macs_hmac_md5_fails():
    """hmac-md5 present → compliant=False."""
    config = {'macs': 'hmac-sha2-256,hmac-md5'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'macs')
    assert f['compliant'] is False


def test_analyse_ssh_macs_hmac_sha1_fails():
    """hmac-sha1 present → compliant=False."""
    config = {'macs': 'hmac-sha1,hmac-sha2-256'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'macs')
    assert f['compliant'] is False


def test_analyse_ssh_kex_clean_passes():
    """Modern KEX only → compliant=True."""
    config = {'kexalgorithms': 'curve25519-sha256,ecdh-sha2-nistp256'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'kexalgorithms')
    assert f['compliant'] is True


def test_analyse_ssh_kex_weak_fails():
    """diffie-hellman-group1-sha1 present → compliant=False."""
    config = {'kexalgorithms': 'curve25519-sha256,diffie-hellman-group1-sha1'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'kexalgorithms')
    assert f['compliant'] is False


def test_analyse_ssh_hostkeyalgorithms_dss_fails():
    """ssh-dss in hostkeyalgorithms → compliant=False."""
    config = {'hostkeyalgorithms': 'rsa-sha2-256,ssh-dss'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'hostkeyalgorithms')
    assert f['compliant'] is False


def test_analyse_ssh_crypto_absent_is_skip():
    """Crypto key absent from sshd -T → compliant=None (compiled-in default)."""
    config = {}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'ciphers')
    assert f['compliant'] is None


# ── Additional coverage ────────────────────────────────────────────────────────

def test_lte_nonnumeric_input_returns_false():
    """_lte(4) with a non-integer string → compliant=False (ValueError path)."""
    check = lsa._lte(4)
    ok, _ = check('not-a-number')
    assert ok is False


def test_analyse_ssh_compliant_remediation_is_none():
    """Compliant finding must have remediation=None."""
    config = {'permitrootlogin': 'no'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'permitrootlogin')
    assert f['compliant'] is True
    assert f['remediation'] is None


def test_analyse_ssh_noncompliant_remediation_is_set():
    """Non-compliant finding must have a non-empty remediation string."""
    config = {'permitrootlogin': 'yes'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'permitrootlogin')
    assert f['compliant'] is False
    assert f['remediation'] is not None
    assert len(f['remediation']) > 0


def test_analyse_ssh_pubkeyaccepted_dss_fails():
    """ssh-dss in pubkeyacceptedalgorithms → compliant=False."""
    config = {'pubkeyacceptedalgorithms': 'rsa-sha2-256,ssh-dss'}
    findings = lsa.analyse_ssh(config)
    f = next(x for x in findings if x['param'] == 'pubkeyacceptedalgorithms')
    assert f['compliant'] is False


def test_no_weak_suffix_wildcard():
    """*-cbc suffix pattern rejects any algo ending in -cbc."""
    fn = lsa._no_weak(['*-cbc'])
    assert fn('aes128-cbc')[0] is False
    assert fn('rijndael-cbc')[0] is False
    assert fn('aes128-ctr')[0] is True
    assert fn('cbc')[0] is True  # no hyphen, should pass


# ── compute_risk ───────────────────────────────────────────────────────────────

def test_compute_risk_no_findings():
    score, risk, c, h, m, l = lsa.compute_risk([])
    assert score == 0
    assert risk == 'LOW'


def test_compute_risk_critical_raises_to_critical():
    findings = [{'compliant': False, 'severity_if_wrong': 'CRITICAL'}]
    score, risk, c, h, m, l = lsa.compute_risk(findings)
    assert risk == 'CRITICAL'
    assert c == 1


def test_compute_risk_score_capped_at_10():
    findings = [{'compliant': False, 'severity_if_wrong': 'HIGH'}] * 10
    score, risk, c, h, m, l = lsa.compute_risk(findings)
    assert score == 10


def test_compute_risk_skips_none_compliant():
    findings = [{'compliant': None, 'severity_if_wrong': 'CRITICAL'}]
    score, risk, c, h, m, l = lsa.compute_risk(findings)
    assert score == 0
    assert risk == 'LOW'


def test_compute_risk_mixed_severity():
    findings = [
        {'compliant': False, 'severity_if_wrong': 'HIGH'},
        {'compliant': False, 'severity_if_wrong': 'MEDIUM'},
        {'compliant': True,  'severity_if_wrong': 'CRITICAL'},
    ]
    score, risk, c, h, m, l = lsa.compute_risk(findings)
    assert h == 1
    assert m == 1
    assert c == 0


# ── write_json ─────────────────────────────────────────────────────────────────

def test_write_json_creates_file(tmp_path):
    report = {'generated_at': '2026-01-01', 'findings': []}
    path = str(tmp_path / 'out.json')
    with patch('os.chmod'):
        lsa.write_json(report, path)
    assert os.path.exists(path)


def test_write_json_valid_json(tmp_path):
    report = {'generated_at': '2026-01-01', 'findings': []}
    path = str(tmp_path / 'out.json')
    with patch('os.chmod'):
        lsa.write_json(report, path)
    with open(path) as f:
        data = json.load(f)
    assert data['generated_at'] == '2026-01-01'


# ── write_html ─────────────────────────────────────────────────────────────────

def test_write_html_creates_file(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost',
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'out.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    assert os.path.exists(path)


def test_write_html_contains_green_gradient(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost',
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'out.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    with open(path) as f:
        content = f.read()
    assert '#28a745' in content


def test_write_html_contains_hostname(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'my-special-host',
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'out.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    with open(path) as f:
        content = f.read()
    assert 'my-special-host' in content
