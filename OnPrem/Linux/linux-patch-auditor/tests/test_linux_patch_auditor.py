"""Tests for linux_patch_auditor.py"""
import sys
import os
import json
from unittest.mock import patch, MagicMock, call
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import linux_patch_auditor as lpa


# ── detect_package_manager tests ──────────────────────────────────────────────

def test_detect_pm_apt():
    def fake_run(cmd):
        if cmd == ['apt-get', '--version']:
            return 'apt 2.0', 0
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        assert lpa.detect_package_manager() == 'apt'


def test_detect_pm_dnf():
    def fake_run(cmd):
        if cmd == ['apt-get', '--version']:
            return '', 1
        if cmd == ['dnf', '--version']:
            return 'dnf 4.0', 0
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        assert lpa.detect_package_manager() == 'dnf'


def test_detect_pm_yum():
    def fake_run(cmd):
        if cmd[0] in ('apt-get', 'dnf'):
            return '', 1
        if cmd == ['yum', '--version']:
            return 'yum 4.0', 0
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        assert lpa.detect_package_manager() == 'yum'


def test_detect_pm_zypper():
    def fake_run(cmd):
        if cmd[0] in ('apt-get', 'dnf', 'yum'):
            return '', 1
        if cmd == ['zypper', '--version']:
            return 'zypper 1.14', 0
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        assert lpa.detect_package_manager() == 'zypper'


def test_detect_pm_none():
    with patch.object(lpa, 'run_command', return_value=('', 1)):
        assert lpa.detect_package_manager() is None


# ── get_available_updates — apt ────────────────────────────────────────────────

def test_get_available_updates_apt_parses_inst_lines():
    apt_output = (
        "Inst libssl1.1 [1.1.1f] (1.1.1n security)\n"
        "Inst curl [7.68.0] (7.68.1 security)\n"
        "Inst vim [8.1] (8.2 main)\n"
    )

    def fake_run(cmd):
        if '-s' in cmd and '--only-upgrade' not in cmd:
            return apt_output, 0
        return '', 1  # security sim fails -> 0 sec updates

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        total, security, pkgs = lpa.get_available_updates('apt')

    assert total == 3
    assert security == 0
    assert 'libssl1.1' in pkgs
    assert 'curl' in pkgs


def test_get_available_updates_apt_empty_output():
    with patch.object(lpa, 'run_command', return_value=('', 0)):
        total, security, pkgs = lpa.get_available_updates('apt')
    assert total == 0
    assert security == 0
    assert pkgs == []


def test_get_available_updates_apt_security_count():
    main_output = (
        "Inst libssl1.1 [1.1.1f] (1.1.1n security)\n"
        "Inst curl [7.68.0] (7.68.1 security)\n"
    )
    sec_output = "Inst libssl1.1 [1.1.1f] (1.1.1n security)\n"

    call_count = [0]

    def fake_run(cmd):
        call_count[0] += 1
        if '--only-upgrade' in cmd:
            return sec_output, 0
        return main_output, 0

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        total, security, pkgs = lpa.get_available_updates('apt')

    assert total == 2
    assert security == 1


# ── get_available_updates — yum ────────────────────────────────────────────────

def test_get_available_updates_yum_rc100_parses_packages():
    yum_output = (
        "\n"
        "kernel.x86_64              5.14.0-162  baseos\n"
        "openssl.x86_64             1.1.1k-7    baseos\n"
    )

    def fake_run(cmd):
        if '--security' in cmd:
            return '', 0
        return yum_output, 100

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        total, security, pkgs = lpa.get_available_updates('yum')

    assert total == 2
    assert 'kernel.x86_64' in pkgs


def test_get_available_updates_yum_rc0_no_updates():
    with patch.object(lpa, 'run_command', return_value=('', 0)):
        total, security, pkgs = lpa.get_available_updates('yum')
    assert total == 0
    assert security == 0
    assert pkgs == []


def test_get_available_updates_yum_security_updates():
    yum_output = "openssl.x86_64  1.1.1k-7  baseos\n"
    sec_output = "openssl.x86_64  1.1.1k-7  baseos\n"

    def fake_run(cmd):
        if '--security' in cmd:
            return sec_output, 100
        return yum_output, 100

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        total, security, pkgs = lpa.get_available_updates('yum')

    assert total == 1
    assert security == 1


# ── get_available_updates — dnf ────────────────────────────────────────────────

def test_get_available_updates_dnf_rc100():
    dnf_output = (
        "bash.x86_64             5.1.8-6.el9  baseos\n"
        "glibc.x86_64            2.34-60.el9  baseos\n"
    )

    def fake_run(cmd):
        if '--security' in cmd:
            return '', 0
        return dnf_output, 100

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        total, security, pkgs = lpa.get_available_updates('dnf')

    assert total == 2
    assert 'bash.x86_64' in pkgs


def test_get_available_updates_dnf_rc0_empty():
    with patch.object(lpa, 'run_command', return_value=('', 0)):
        total, security, pkgs = lpa.get_available_updates('dnf')
    assert total == 0


# ── get_available_updates — unknown/None ──────────────────────────────────────

def test_get_available_updates_unknown_pm():
    total, security, pkgs = lpa.get_available_updates('unknown')
    assert total == 0
    assert security == 0
    assert pkgs == []


def test_get_available_updates_none_pm():
    total, security, pkgs = lpa.get_available_updates(None)
    assert total == 0
    assert security == 0
    assert pkgs == []


# ── get_last_update_time — apt ────────────────────────────────────────────────

def test_get_last_update_time_apt_valid_dpkg_log():
    dpkg_log = (
        "2024-01-10 08:00:00 startup archives unpack\n"
        "2024-01-10 08:01:00 status installed curl:amd64 7.68.1\n"
    )

    with patch.object(lpa, 'read_file', return_value=dpkg_log):
        dt, days = lpa.get_last_update_time('apt')

    assert dt is not None
    assert isinstance(days, int)
    assert days >= 0


def test_get_last_update_time_apt_no_log():
    with patch.object(lpa, 'read_file', return_value=''):
        with patch('os.path.getmtime', side_effect=OSError):
            dt, days = lpa.get_last_update_time('apt')
    assert dt is None
    assert days is None


# ── get_last_update_time — yum/dnf ────────────────────────────────────────────

def test_get_last_update_time_dnf_valid_log():
    dnf_log = (
        "2024-03-15 10:30:00 DEBUG dnf something\n"
        "2024-03-15 10:30:05 DEBUG dnf something else\n"
    )

    def fake_read(path):
        if 'dnf' in path:
            return dnf_log
        return ''

    with patch.object(lpa, 'read_file', side_effect=fake_read):
        dt, days = lpa.get_last_update_time('dnf')

    assert dt is not None
    assert dt.year == 2024


def test_get_last_update_time_yum_no_log():
    with patch.object(lpa, 'read_file', return_value=''):
        dt, days = lpa.get_last_update_time('yum')
    assert dt is None
    assert days is None


# ── check_auto_updates — apt ──────────────────────────────────────────────────

def test_check_auto_updates_apt_installed_and_active():
    def fake_run(cmd):
        if cmd == ['dpkg', '-l', 'unattended-upgrades']:
            return 'ii  unattended-upgrades', 0
        if cmd == ['systemctl', 'is-active', 'apt-daily-upgrade.timer']:
            return 'active\n', 0
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        enabled, agent, details = lpa.check_auto_updates('apt')

    assert enabled is True
    assert agent == 'unattended-upgrades'


def test_check_auto_updates_apt_not_installed():
    def fake_run(cmd):
        if cmd == ['dpkg', '-l', 'unattended-upgrades']:
            return '', 1
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        enabled, agent, details = lpa.check_auto_updates('apt')

    assert enabled is False
    assert agent == 'unattended-upgrades'
    assert details == 'not installed'


def test_check_auto_updates_apt_installed_timer_inactive():
    def fake_run(cmd):
        if cmd == ['dpkg', '-l', 'unattended-upgrades']:
            return 'ii  unattended-upgrades', 0
        if cmd == ['systemctl', 'is-active', 'apt-daily-upgrade.timer']:
            return 'inactive\n', 0
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        enabled, agent, details = lpa.check_auto_updates('apt')

    assert enabled is False


# ── check_auto_updates — dnf ──────────────────────────────────────────────────

def test_check_auto_updates_dnf_timer_active():
    def fake_run(cmd):
        if cmd == ['systemctl', 'is-active', 'dnf-automatic.timer']:
            return 'active\n', 0
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        enabled, agent, details = lpa.check_auto_updates('dnf')

    assert enabled is True
    assert agent == 'dnf-automatic'


def test_check_auto_updates_dnf_timer_not_active():
    def fake_run(cmd):
        if 'dnf-automatic' in ' '.join(cmd):
            return 'inactive\n', 1
        return '', 1

    with patch.object(lpa, 'run_command', side_effect=fake_run):
        enabled, agent, details = lpa.check_auto_updates('dnf')

    assert enabled is False
    assert agent == 'dnf-automatic'


# ── analyse_patch_status tests ────────────────────────────────────────────────

def test_analyse_patch_status_no_pm_returns_medium():
    with patch.object(lpa, 'detect_package_manager', return_value=None):
        with patch('socket.gethostname', return_value='testhost'):
            result = lpa.analyse_patch_status()

    assert result['risk_level'] == 'MEDIUM'
    assert result['package_manager'] is None
    assert any('Could not detect' in f for f in result['flags'])


def test_analyse_patch_status_security_updates_raises_risk():
    # 10 security updates: min(10,4)+1 = 5 points → HIGH; last update recent → no extra;
    # auto-updates off → +1 → score=6 → HIGH
    with patch.object(lpa, 'detect_package_manager', return_value='apt'):
        with patch.object(lpa, 'get_available_updates', return_value=(12, 10, ['a', 'b', 'c'])):
            with patch.object(lpa, 'get_last_update_time', return_value=(
                datetime.now(timezone.utc) - timedelta(days=10), 10
            )):
                with patch.object(lpa, 'check_auto_updates', return_value=(False, 'unattended-upgrades', 'not installed')):
                    with patch('socket.gethostname', return_value='testhost'):
                        result = lpa.analyse_patch_status()

    assert result['security_updates'] == 10
    assert result['risk_level'] in ('HIGH', 'CRITICAL')
    assert any('security' in f.lower() for f in result['flags'])


def test_analyse_patch_status_old_update_over_90_days():
    old_dt = datetime.now(timezone.utc) - timedelta(days=100)

    with patch.object(lpa, 'detect_package_manager', return_value='apt'):
        with patch.object(lpa, 'get_available_updates', return_value=(0, 0, [])):
            with patch.object(lpa, 'get_last_update_time', return_value=(old_dt, 100)):
                with patch.object(lpa, 'check_auto_updates', return_value=(True, 'unattended-upgrades', 'active')):
                    with patch('socket.gethostname', return_value='testhost'):
                        result = lpa.analyse_patch_status()

    assert result['days_since_update'] == 100
    assert any('90 days' in f for f in result['flags'])
    assert result['severity_score'] >= 3


def test_analyse_patch_status_auto_updates_off_adds_flag():
    with patch.object(lpa, 'detect_package_manager', return_value='apt'):
        with patch.object(lpa, 'get_available_updates', return_value=(0, 0, [])):
            with patch.object(lpa, 'get_last_update_time', return_value=(
                datetime.now(timezone.utc) - timedelta(days=5), 5
            )):
                with patch.object(lpa, 'check_auto_updates', return_value=(False, 'unattended-upgrades', 'not installed')):
                    with patch('socket.gethostname', return_value='testhost'):
                        result = lpa.analyse_patch_status()

    assert result['auto_updates_enabled'] is False
    assert any('Automatic updates' in f for f in result['flags'])
    assert any('unattended-upgrades' in r for r in result['remediations'])


def test_analyse_patch_status_positive_flags_last():
    with patch.object(lpa, 'detect_package_manager', return_value='dnf'):
        with patch.object(lpa, 'get_available_updates', return_value=(0, 0, [])):
            with patch.object(lpa, 'get_last_update_time', return_value=(
                datetime.now(timezone.utc) - timedelta(days=3), 3
            )):
                with patch.object(lpa, 'check_auto_updates', return_value=(True, 'dnf-automatic', 'active')):
                    with patch('socket.gethostname', return_value='testhost'):
                        result = lpa.analyse_patch_status()

    # All good: flags should be positive (✅) only
    positive = [f for f in result['flags'] if f.startswith('✅')]
    assert len(positive) == len(result['flags'])


# ── run() end-to-end mock ─────────────────────────────────────────────────────

def test_run_returns_report_with_required_keys(tmp_path):
    mock_result = {
        "hostname": "testhost",
        "kernel": "5.15.0",
        "package_manager": "apt",
        "total_updates": 2,
        "security_updates": 1,
        "pending_packages": ["curl"],
        "last_update": "2026-03-10T00:00:00+00:00",
        "days_since_update": 15,
        "auto_updates_enabled": True,
        "auto_update_agent": "unattended-upgrades",
        "risk_level": "MEDIUM",
        "severity_score": 3,
        "flags": ["ℹ️ 2 total update(s) available", "✅ Last update 15 days ago",
                  "✅ Automatic updates enabled (unattended-upgrades)"],
        "remediations": [],
    }

    prefix = str(tmp_path / 'patch_report')
    with patch.object(lpa, 'analyse_patch_status', return_value=mock_result):
        with patch('os.chmod'):
            report = lpa.run(output_prefix=prefix, fmt='stdout')

    assert isinstance(report, dict)
    assert 'generated_at' in report
    assert 'hostname' in report
    assert 'kernel' in report
    assert 'package_manager' in report
    assert 'summary' in report
    assert 'findings' in report
    assert 'pillar' in report
    assert 'risk_level' in report
    assert report['pillar'] == 'patch'
    assert report['summary']['overall_risk'] == 'MEDIUM'


# ── write_json / write_csv / write_html smoke tests ───────────────────────────

def test_write_json_calls_chmod(tmp_path):
    report = {
        'generated_at': '2026-01-01',
        'hostname': 'host',
        'findings': [],
        'summary': {},
    }
    path = str(tmp_path / 'test.json')
    with patch('os.chmod') as mock_chmod:
        lpa.write_json(report, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_json_produces_valid_json(tmp_path):
    report = {'generated_at': '2026-01-01', 'findings': [{'a': 1}], 'summary': {}}
    path = str(tmp_path / 'out.json')
    with patch('os.chmod'):
        lpa.write_json(report, path)
    with open(path) as f:
        data = json.load(f)
    assert data['findings'][0]['a'] == 1


def test_write_csv_calls_chmod(tmp_path):
    findings = [{'hostname': 'h', 'kernel': 'k', 'package_manager': 'apt',
                 'total_updates': 0, 'security_updates': 0, 'days_since_update': 5,
                 'auto_updates_enabled': True, 'auto_update_agent': 'uu',
                 'risk_level': 'LOW', 'severity_score': 0}]
    path = str(tmp_path / 'test.csv')
    with patch('os.chmod') as mock_chmod:
        lpa.write_csv(findings, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_csv_empty_findings_no_file(tmp_path):
    path = str(tmp_path / 'empty.csv')
    lpa.write_csv([], path)
    assert not os.path.exists(path)


def test_write_html_calls_chmod(tmp_path):
    mock_result = {
        "hostname": "testhost",
        "kernel": "5.15.0",
        "package_manager": "apt",
        "total_updates": 0,
        "security_updates": 0,
        "pending_packages": [],
        "last_update": None,
        "days_since_update": None,
        "auto_updates_enabled": True,
        "auto_update_agent": "unattended-upgrades",
        "risk_level": "LOW",
        "severity_score": 0,
        "flags": [],
        "remediations": [],
    }
    report = {
        'generated_at': '2026-01-01T00:00:00+00:00',
        'hostname': 'testhost',
        'kernel': '5.15.0',
        'package_manager': 'apt',
        'summary': {
            'total_updates': 0,
            'security_updates': 0,
            'days_since_update': None,
            'auto_updates_enabled': True,
            'overall_risk': 'LOW',
            'severity_score': 0,
        },
        'findings': [mock_result],
        'pillar': 'patch',
        'risk_level': 'LOW',
    }
    path = str(tmp_path / 'test.html')
    with patch('os.chmod') as mock_chmod:
        lpa.write_html(report, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_html_contains_title(tmp_path):
    mock_result = {
        "hostname": "myhost",
        "kernel": "5.15.0",
        "package_manager": "apt",
        "total_updates": 1,
        "security_updates": 0,
        "pending_packages": [],
        "last_update": None,
        "days_since_update": 5,
        "auto_updates_enabled": True,
        "auto_update_agent": "unattended-upgrades",
        "risk_level": "LOW",
        "severity_score": 1,
        "flags": ["ℹ️ 1 update available"],
        "remediations": [],
    }
    report = {
        'generated_at': '2026-01-01T00:00:00+00:00',
        'hostname': 'myhost',
        'kernel': '5.15.0',
        'package_manager': 'apt',
        'summary': {
            'total_updates': 1,
            'security_updates': 0,
            'days_since_update': 5,
            'auto_updates_enabled': True,
            'overall_risk': 'LOW',
            'severity_score': 1,
        },
        'findings': [mock_result],
        'pillar': 'patch',
        'risk_level': 'LOW',
    }
    path = str(tmp_path / 'out.html')
    with patch('os.chmod'):
        lpa.write_html(report, path)
    with open(path) as f:
        content = f.read()
    assert 'Linux Patch Auditor Report' in content
    assert 'myhost' in content


# ── Wrapper function smoke tests ──────────────────────────────────────────────

def test_read_file_returns_empty_on_missing():
    result = lpa.read_file('/nonexistent/path/that/does/not/exist')
    assert result == ''


def test_run_command_returns_tuple_on_error():
    stdout, rc = lpa.run_command(['false_nonexistent_command_xyz_abc'])
    assert isinstance(stdout, str)
    assert isinstance(rc, int)


def test_path_exists_returns_false_for_missing():
    assert lpa.path_exists('/nonexistent/path/xyz/abc/123') is False


def test_path_exists_returns_true_for_existing(tmp_path):
    f = tmp_path / 'exists.txt'
    f.write_text('hello')
    assert lpa.path_exists(str(f)) is True
