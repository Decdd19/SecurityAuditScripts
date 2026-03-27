"""Tests for linux_ssh_auditor.py"""
import sys
import os

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
