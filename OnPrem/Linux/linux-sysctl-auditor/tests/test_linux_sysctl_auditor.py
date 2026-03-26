"""Tests for linux_sysctl_auditor.py"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch, MagicMock, call
import linux_sysctl_auditor as lsa


# ── read_sysctl wrapper ────────────────────────────────────────────────────────

def test_read_sysctl_success():
    with patch.object(lsa, 'run_command', return_value=('1\n', 0)):
        result = lsa.read_sysctl('net.ipv4.ip_forward')
    assert result == '1'


def test_read_sysctl_strips_whitespace():
    with patch.object(lsa, 'run_command', return_value=('  2  \n', 0)):
        result = lsa.read_sysctl('kernel.randomize_va_space')
    assert result == '2'


def test_read_sysctl_returns_none_on_nonzero_rc():
    with patch.object(lsa, 'run_command', return_value=('', 1)):
        result = lsa.read_sysctl('kernel.nonexistent.param')
    assert result is None


def test_read_sysctl_returns_none_when_run_command_returns_error():
    """run_command itself swallows exceptions and returns ('', 1); read_sysctl should return None."""
    with patch.object(lsa, 'run_command', return_value=('', 1)):
        result = lsa.read_sysctl('net.ipv4.ip_forward')
    assert result is None


# ── run_command / read_file thin wrappers ─────────────────────────────────────

def test_run_command_returns_tuple_on_bad_command():
    stdout, rc = lsa.run_command(['__nonexistent_cmd_xyz__'])
    assert isinstance(stdout, str)
    assert isinstance(rc, int)


def test_read_file_returns_empty_on_missing():
    result = lsa.read_file('/nonexistent/path/that/does/not/exist')
    assert result == ''


# ── analyse_sysctl ─────────────────────────────────────────────────────────────

def test_analyse_sysctl_compliant_param():
    """When sysctl returns the expected value, compliant=True."""
    def mock_read_sysctl(param):
        # ip_forward expected=0 → return '0'
        return '0'

    with patch.object(lsa, 'read_sysctl', side_effect=mock_read_sysctl):
        results = lsa.analyse_sysctl()

    compliant_results = [r for r in results if r['compliant'] is True]
    assert len(compliant_results) > 0
    for r in compliant_results:
        assert r['actual'] == r['expected']
    # compliant flags start with ✅
    assert results[0]['flag'].startswith('\u2705') or any(
        r['flag'].startswith('\u2705') for r in compliant_results
    )


def test_analyse_sysctl_non_compliant_param():
    """When sysctl returns wrong value, compliant=False with ⚠️ flag."""
    def mock_read_sysctl(param):
        # ip_forward expected=0 → return '1' (wrong)
        return '1'

    with patch.object(lsa, 'read_sysctl', side_effect=mock_read_sysctl):
        results = lsa.analyse_sysctl()

    non_compliant = [r for r in results if r['compliant'] is False]
    assert len(non_compliant) > 0
    # Every non-compliant result has the warning icon in flag
    for r in non_compliant:
        assert '\u26a0\ufe0f' in r['flag']
    # Every non-compliant has a remediation
    for r in non_compliant:
        assert r['remediation'] is not None
        assert '/etc/sysctl.d/99-hardening.conf' in r['remediation']


def test_analyse_sysctl_unavailable_param():
    """When sysctl is unavailable (None), compliant=None."""
    with patch.object(lsa, 'read_sysctl', return_value=None):
        results = lsa.analyse_sysctl()

    unavailable = [r for r in results if r['compliant'] is None]
    assert len(unavailable) == len(lsa.SYSCTL_CHECKS)
    for r in unavailable:
        assert r['actual'] == 'N/A'
        assert r['remediation'] is not None
        assert '\u2139\ufe0f' in r['flag']


def test_analyse_sysctl_returns_all_checks():
    with patch.object(lsa, 'read_sysctl', return_value='0'):
        results = lsa.analyse_sysctl()
    assert len(results) == len(lsa.SYSCTL_CHECKS)


def test_analyse_sysctl_ip_forward_non_compliant():
    """net.ipv4.ip_forward = 1 should be non-compliant with HIGH severity."""
    def mock_read_sysctl(param):
        if param == 'net.ipv4.ip_forward':
            return '1'
        return '0'  # everything else compliant

    with patch.object(lsa, 'read_sysctl', side_effect=mock_read_sysctl):
        results = lsa.analyse_sysctl()

    r = next(x for x in results if x['param'] == 'net.ipv4.ip_forward')
    assert r['compliant'] is False
    assert r['severity_if_wrong'] == 'HIGH'
    assert r['actual'] == '1'
    assert r['expected'] == '0'


def test_analyse_sysctl_aslr_partial_non_compliant():
    """kernel.randomize_va_space = 1 (partial ASLR) should be non-compliant."""
    def mock_read_sysctl(param):
        if param == 'kernel.randomize_va_space':
            return '1'
        # Return expected for all others
        for p, exp, _, _ in lsa.SYSCTL_CHECKS:
            if p == param:
                return exp
        return '0'

    with patch.object(lsa, 'read_sysctl', side_effect=mock_read_sysctl):
        results = lsa.analyse_sysctl()

    r = next(x for x in results if x['param'] == 'kernel.randomize_va_space')
    assert r['compliant'] is False
    assert r['severity_if_wrong'] == 'HIGH'
    assert '1' in r['flag']
    assert '2' in r['flag']  # expected=2 referenced in flag


def test_analyse_sysctl_fs_protected_hardlinks_non_compliant():
    """fs.protected_hardlinks = 0 should be non-compliant MEDIUM."""
    def mock_read_sysctl(param):
        if param == 'fs.protected_hardlinks':
            return '0'
        for p, exp, _, _ in lsa.SYSCTL_CHECKS:
            if p == param:
                return exp
        return '1'

    with patch.object(lsa, 'read_sysctl', side_effect=mock_read_sysctl):
        results = lsa.analyse_sysctl()

    r = next(x for x in results if x['param'] == 'fs.protected_hardlinks')
    assert r['compliant'] is False
    assert r['severity_if_wrong'] == 'MEDIUM'


# ── compute_risk ───────────────────────────────────────────────────────────────

def _make_results(n_high=0, n_medium=0, n_low=0, n_critical=0):
    """Build a minimal results list with the requested violation counts."""
    results = []
    for _ in range(n_critical):
        results.append({'compliant': False, 'severity_if_wrong': 'CRITICAL'})
    for _ in range(n_high):
        results.append({'compliant': False, 'severity_if_wrong': 'HIGH'})
    for _ in range(n_medium):
        results.append({'compliant': False, 'severity_if_wrong': 'MEDIUM'})
    for _ in range(n_low):
        results.append({'compliant': False, 'severity_if_wrong': 'LOW'})
    return results


def test_compute_risk_all_compliant():
    results = [{'compliant': True, 'severity_if_wrong': 'HIGH'} for _ in range(10)]
    score, risk, criticals, highs, mediums, lows = lsa.compute_risk(results)
    assert risk == 'LOW'
    assert score == 0
    assert highs == 0


def test_compute_risk_many_high_violations():
    results = _make_results(n_high=5)
    score, risk, criticals, highs, mediums, lows = lsa.compute_risk(results)
    assert risk in ('HIGH', 'CRITICAL')
    assert highs == 5
    assert score >= 5


def test_compute_risk_critical_overrides():
    results = _make_results(n_critical=1)
    score, risk, criticals, highs, mediums, lows = lsa.compute_risk(results)
    assert risk == 'CRITICAL'
    assert criticals == 1


def test_compute_risk_medium_only():
    results = _make_results(n_medium=2)
    score, risk, criticals, highs, mediums, lows = lsa.compute_risk(results)
    assert risk == 'MEDIUM'
    assert mediums == 2
    assert score == 2


def test_compute_risk_low_only():
    results = _make_results(n_low=1)
    score, risk, criticals, highs, mediums, lows = lsa.compute_risk(results)
    assert risk == 'LOW'
    assert lows == 1


def test_compute_risk_score_capped_at_10():
    # 10 HIGH violations → 20 raw score, should be capped at 10
    results = _make_results(n_high=10)
    score, risk, criticals, highs, mediums, lows = lsa.compute_risk(results)
    assert score == 10


def test_compute_risk_unavailable_not_counted():
    results = [{'compliant': None, 'severity_if_wrong': 'HIGH'} for _ in range(5)]
    score, risk, criticals, highs, mediums, lows = lsa.compute_risk(results)
    assert score == 0
    assert risk == 'LOW'
    assert highs == 0


# ── write_json ─────────────────────────────────────────────────────────────────

def test_write_json_calls_chmod(tmp_path):
    report = {'generated_at': '2026-01-01', 'findings': [], 'summary': {}}
    path = str(tmp_path / 'test.json')
    with patch('os.chmod') as mock_chmod:
        lsa.write_json(report, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_json_produces_valid_json(tmp_path):
    report = {
        'generated_at': '2026-01-01',
        'findings': [{'param': 'net.ipv4.ip_forward', 'actual': '0'}],
        'summary': {'total_checks': 1},
    }
    path = str(tmp_path / 'out.json')
    with patch('os.chmod'):
        lsa.write_json(report, path)
    with open(path) as f:
        data = json.load(f)
    assert data['findings'][0]['param'] == 'net.ipv4.ip_forward'


def test_write_json_report_structure(tmp_path):
    report = {
        'generated_at': '2026-01-01',
        'hostname': 'myhost',
        'pillar': 'sysctl',
        'risk_level': 'LOW',
        'summary': {'total_checks': 0, 'compliant': 0, 'non_compliant': 0},
        'findings': [],
    }
    path = str(tmp_path / 'structured.json')
    with patch('os.chmod'):
        lsa.write_json(report, path)
    with open(path) as f:
        data = json.load(f)
    assert data['pillar'] == 'sysctl'
    assert 'risk_level' in data


# ── write_csv ──────────────────────────────────────────────────────────────────

def test_write_csv_calls_chmod(tmp_path):
    findings = [{
        'param': 'net.ipv4.ip_forward', 'expected': '0', 'actual': '1',
        'compliant': False, 'severity_if_wrong': 'HIGH',
        'description': 'IP forwarding', 'flag': '⚠️ ...', 'remediation': 'fix it',
    }]
    path = str(tmp_path / 'test.csv')
    with patch('os.chmod') as mock_chmod:
        lsa.write_csv(findings, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_csv_creates_file_with_header(tmp_path):
    findings = [{
        'param': 'kernel.randomize_va_space', 'expected': '2', 'actual': '1',
        'compliant': False, 'severity_if_wrong': 'HIGH',
        'description': 'ASLR', 'flag': '⚠️ aslr', 'remediation': 'set it to 2',
    }]
    path = str(tmp_path / 'out.csv')
    with patch('os.chmod'):
        lsa.write_csv(findings, path)
    with open(path) as f:
        content = f.read()
    assert 'param' in content
    assert 'kernel.randomize_va_space' in content


def test_write_csv_empty_findings_no_file(tmp_path):
    path = str(tmp_path / 'empty.csv')
    lsa.write_csv([], path)
    assert not os.path.exists(path)


# ── write_html ─────────────────────────────────────────────────────────────────

def test_write_html_calls_chmod(tmp_path):
    report = {
        'generated_at': '2026-01-01',
        'hostname': 'host',
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'test.html')
    with patch('os.chmod') as mock_chmod:
        lsa.write_html(report, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_html_contains_title(tmp_path):
    report = {
        'generated_at': '2026-01-01',
        'hostname': 'myhost',
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
    assert 'Linux Sysctl Hardening Audit Report' in content


def test_write_html_contains_green_gradient(tmp_path):
    """HTML header should use the Linux green gradient theme."""
    report = {
        'generated_at': '2026-01-01',
        'hostname': 'myhost',
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'gradient.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    with open(path) as f:
        content = f.read()
    assert '#28a745' in content


# ── run() end-to-end ───────────────────────────────────────────────────────────

def _all_expected_sysctl(param):
    """Return the expected value for every known param."""
    for p, exp, _, _ in lsa.SYSCTL_CHECKS:
        if p == param:
            return exp
    return '0'


def test_run_returns_report_dict():
    with patch.object(lsa, 'read_sysctl', side_effect=_all_expected_sysctl), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lsa.run(fmt='stdout')
    assert isinstance(report, dict)


def test_run_summary_keys_present():
    with patch.object(lsa, 'read_sysctl', side_effect=_all_expected_sysctl), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lsa.run(fmt='stdout')
    s = report['summary']
    for key in ('total_checks', 'compliant', 'non_compliant', 'unavailable',
                'critical', 'high', 'medium', 'low', 'overall_risk', 'severity_score'):
        assert key in s, f"Missing summary key: {key}"


def test_run_all_compliant_gives_low_risk():
    with patch.object(lsa, 'read_sysctl', side_effect=_all_expected_sysctl), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lsa.run(fmt='stdout')
    assert report['summary']['overall_risk'] == 'LOW'
    assert report['summary']['non_compliant'] == 0


def test_run_non_compliant_params_sorted_first():
    def mixed_sysctl(param):
        if param == 'net.ipv4.ip_forward':
            return '1'  # wrong
        return _all_expected_sysctl(param)

    with patch.object(lsa, 'read_sysctl', side_effect=mixed_sysctl), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lsa.run(fmt='stdout')

    findings = report['findings']
    # First finding in list should be non-compliant
    assert findings[0]['compliant'] is False


def test_run_pillar_and_risk_level_in_report():
    with patch.object(lsa, 'read_sysctl', side_effect=_all_expected_sysctl), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lsa.run(fmt='stdout')
    assert report['pillar'] == 'sysctl'
    assert 'risk_level' in report


def test_run_hostname_in_report():
    with patch.object(lsa, 'read_sysctl', side_effect=_all_expected_sysctl), \
         patch('socket.gethostname', return_value='testserver'), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lsa.run(fmt='stdout')
    assert report['hostname'] == 'testserver'


def test_run_with_multiple_violations():
    def bad_sysctl(param):
        # Make all HIGH params non-compliant
        for p, exp, sev, _ in lsa.SYSCTL_CHECKS:
            if p == param and sev == 'HIGH':
                return '99'  # always wrong
            if p == param:
                return exp
        return '0'

    with patch.object(lsa, 'read_sysctl', side_effect=bad_sysctl), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.chmod'):
        report = lsa.run(fmt='stdout')

    s = report['summary']
    assert s['high'] > 0
    assert s['overall_risk'] in ('HIGH', 'CRITICAL')


def test_run_write_json_called_on_json_format(tmp_path):
    prefix = str(tmp_path / 'report')
    with patch.object(lsa, 'read_sysctl', side_effect=_all_expected_sysctl), \
         patch.object(lsa, 'write_json') as mock_json, \
         patch.object(lsa, 'write_csv') as mock_csv, \
         patch.object(lsa, 'write_html') as mock_html:
        lsa.run(output_prefix=prefix, fmt='json')
    mock_json.assert_called_once()
    mock_csv.assert_not_called()
    mock_html.assert_not_called()


def test_run_all_format_calls_all_writers(tmp_path):
    prefix = str(tmp_path / 'report')
    with patch.object(lsa, 'read_sysctl', side_effect=_all_expected_sysctl), \
         patch.object(lsa, 'write_json') as mock_json, \
         patch.object(lsa, 'write_csv') as mock_csv, \
         patch.object(lsa, 'write_html') as mock_html:
        lsa.run(output_prefix=prefix, fmt='all')
    mock_json.assert_called_once()
    mock_csv.assert_called_once()
    mock_html.assert_called_once()
