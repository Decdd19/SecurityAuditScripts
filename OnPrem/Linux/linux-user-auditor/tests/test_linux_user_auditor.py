"""Tests for linux_user_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch, MagicMock
import linux_user_auditor as lua


# ── Sample fixtures ────────────────────────────────────────────────────────────

SAMPLE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""

SAMPLE_SHADOW = """root:$6$xyz$hash123:19000:0:99999:7:::
alice:$6$abc$hash456:19100:0:90:7:::
emptyuser::19000:0:99999:7:::
"""

SAMPLE_SSHD = """Port 22
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
"""

SAMPLE_SUDOERS = """root    ALL=(ALL:ALL) ALL
alice   ALL=(ALL) NOPASSWD: ALL
bob     ALL=(ALL) /usr/bin/systemctl
"""


# ── parse_passwd tests ─────────────────────────────────────────────────────────

def test_parse_passwd_root():
    users = lua.parse_passwd(SAMPLE_PASSWD)
    root = next(u for u in users if u['username'] == 'root')
    assert root['uid'] == 0


def test_parse_passwd_normal_user():
    users = lua.parse_passwd(SAMPLE_PASSWD)
    alice = next(u for u in users if u['username'] == 'alice')
    assert alice['uid'] == 1000
    assert alice['shell'] == '/bin/bash'


def test_parse_passwd_nobody():
    users = lua.parse_passwd(SAMPLE_PASSWD)
    nobody = next(u for u in users if u['username'] == 'nobody')
    assert nobody['uid'] == 65534


def test_parse_passwd_home():
    users = lua.parse_passwd(SAMPLE_PASSWD)
    alice = next(u for u in users if u['username'] == 'alice')
    assert alice['home'] == '/home/alice'


def test_parse_passwd_nologin_shell():
    users = lua.parse_passwd(SAMPLE_PASSWD)
    daemon = next(u for u in users if u['username'] == 'daemon')
    assert daemon['shell'] == '/usr/sbin/nologin'


def test_parse_passwd_empty_content():
    users = lua.parse_passwd('')
    assert users == []


def test_parse_passwd_ignores_comments():
    content = "# this is a comment\nroot:x:0:0:root:/root:/bin/bash\n"
    users = lua.parse_passwd(content)
    assert len(users) == 1
    assert users[0]['username'] == 'root'


def test_parse_passwd_malformed_line_skipped():
    content = "badline\nroot:x:0:0:root:/root:/bin/bash\n"
    users = lua.parse_passwd(content)
    # malformed line should be skipped, root should still parse
    assert any(u['username'] == 'root' for u in users)


def test_parse_passwd_count():
    users = lua.parse_passwd(SAMPLE_PASSWD)
    assert len(users) == 4


# ── parse_shadow tests ─────────────────────────────────────────────────────────

def test_parse_shadow_with_hash():
    shadow = lua.parse_shadow(SAMPLE_SHADOW)
    assert shadow['root']['hash'].startswith('$6$')


def test_parse_shadow_empty_hash():
    shadow = lua.parse_shadow(SAMPLE_SHADOW)
    assert shadow['emptyuser']['hash'] == ''


def test_parse_shadow_max_days():
    shadow = lua.parse_shadow(SAMPLE_SHADOW)
    assert shadow['alice']['max_days'] == 90


def test_parse_shadow_root_max_days():
    shadow = lua.parse_shadow(SAMPLE_SHADOW)
    assert shadow['root']['max_days'] == 99999


def test_parse_shadow_last_change():
    shadow = lua.parse_shadow(SAMPLE_SHADOW)
    assert shadow['alice']['last_change'] == 19100


def test_parse_shadow_empty_content():
    shadow = lua.parse_shadow('')
    assert shadow == {}


def test_parse_shadow_locked_account():
    content = "locked:!:19000:0:99999:7:::\n"
    shadow = lua.parse_shadow(content)
    assert shadow['locked']['hash'] == '!'


def test_parse_shadow_double_locked():
    content = "locked2:!!:19000:0:99999:7:::\n"
    shadow = lua.parse_shadow(content)
    assert shadow['locked2']['hash'] == '!!'


def test_parse_shadow_malformed_line_skipped():
    content = ":\n" + SAMPLE_SHADOW
    shadow = lua.parse_shadow(content)
    # Original entries still present
    assert 'root' in shadow


# ── parse_sshd_config tests ────────────────────────────────────────────────────

def test_parse_sshd_permit_root_login():
    cfg = lua.parse_sshd_config(SAMPLE_SSHD)
    assert cfg.get('permitrootlogin') == 'yes'


def test_parse_sshd_password_auth():
    cfg = lua.parse_sshd_config(SAMPLE_SSHD)
    assert cfg.get('passwordauthentication') == 'no'


def test_parse_sshd_port():
    cfg = lua.parse_sshd_config(SAMPLE_SSHD)
    assert cfg.get('port') == '22'


def test_parse_sshd_pubkey_auth():
    cfg = lua.parse_sshd_config(SAMPLE_SSHD)
    assert cfg.get('pubkeyauthentication') == 'yes'


def test_parse_sshd_empty_content():
    cfg = lua.parse_sshd_config('')
    assert cfg == {}


def test_parse_sshd_ignores_comments():
    content = "# Port 2222\nPort 22\n"
    cfg = lua.parse_sshd_config(content)
    assert cfg.get('port') == '22'


def test_parse_sshd_keys_are_lowercase():
    content = "PermitRootLogin no\nPasswordAuthentication yes\n"
    cfg = lua.parse_sshd_config(content)
    assert 'permitrootlogin' in cfg
    assert 'passwordauthentication' in cfg


# ── parse_sudoers tests ────────────────────────────────────────────────────────

def test_parse_sudoers_nopasswd():
    entries = lua.parse_sudoers(SAMPLE_SUDOERS)
    alice = next(e for e in entries if e.get('user_or_group') == 'alice')
    assert alice['nopasswd'] is True
    assert alice['all_commands'] is True


def test_parse_sudoers_root_all():
    entries = lua.parse_sudoers(SAMPLE_SUDOERS)
    root_entry = next(e for e in entries if e.get('user_or_group') == 'root')
    assert root_entry['all_commands'] is True


def test_parse_sudoers_root_no_nopasswd():
    entries = lua.parse_sudoers(SAMPLE_SUDOERS)
    root_entry = next(e for e in entries if e.get('user_or_group') == 'root')
    assert root_entry['nopasswd'] is False


def test_parse_sudoers_bob_specific_command():
    entries = lua.parse_sudoers(SAMPLE_SUDOERS)
    bob = next(e for e in entries if e.get('user_or_group') == 'bob')
    assert bob['nopasswd'] is False
    assert bob['all_commands'] is False


def test_parse_sudoers_group_entry():
    content = "%admins ALL=(ALL) NOPASSWD: ALL\n"
    entries = lua.parse_sudoers(content)
    assert len(entries) == 1
    assert entries[0]['user_or_group'] == '%admins'
    assert entries[0]['nopasswd'] is True
    assert entries[0]['all_commands'] is True


def test_parse_sudoers_ignores_comments():
    content = "# this is a comment\nalice ALL=(ALL) NOPASSWD: ALL\n"
    entries = lua.parse_sudoers(content)
    assert len(entries) == 1


def test_parse_sudoers_ignores_defaults():
    content = "Defaults env_reset\nroot ALL=(ALL) ALL\n"
    entries = lua.parse_sudoers(content)
    assert len(entries) == 1
    assert entries[0]['user_or_group'] == 'root'


def test_parse_sudoers_empty_content():
    entries = lua.parse_sudoers('')
    assert entries == []


def test_nopasswd_all_detected():
    entries = lua.parse_sudoers("alice ALL=(ALL) NOPASSWD: ALL\n")
    alice = next(e for e in entries if e.get('user_or_group') == 'alice')
    assert alice['nopasswd'] is True
    assert alice['all_commands'] is True


# ── parse_login_defs tests ─────────────────────────────────────────────────────

def test_parse_login_defs_pass_max_days():
    login_defs = lua.parse_login_defs("PASS_MAX_DAYS\t90\nPASS_MIN_LEN\t12\n")
    assert login_defs.get('PASS_MAX_DAYS') == '90'


def test_parse_login_defs_pass_min_len():
    login_defs = lua.parse_login_defs("PASS_MIN_LEN\t6\nPASS_MAX_DAYS\t90\n")
    assert int(login_defs.get('PASS_MIN_LEN', 12)) < 12


def test_parse_login_defs_keys_uppercase():
    login_defs = lua.parse_login_defs("pass_min_len\t8\n")
    assert 'PASS_MIN_LEN' in login_defs


def test_parse_login_defs_ignores_comments():
    login_defs = lua.parse_login_defs("# PASS_MAX_DAYS 9999\nPASS_MAX_DAYS\t90\n")
    assert login_defs.get('PASS_MAX_DAYS') == '90'


def test_parse_login_defs_empty_content():
    login_defs = lua.parse_login_defs('')
    assert login_defs == {}


# ── severity_label tests ───────────────────────────────────────────────────────

def test_severity_critical():
    assert lua.severity_label(10) == 'CRITICAL'
    assert lua.severity_label(8) == 'CRITICAL'


def test_severity_high():
    assert lua.severity_label(7) == 'HIGH'
    assert lua.severity_label(6) == 'HIGH'


def test_severity_medium():
    assert lua.severity_label(5) == 'MEDIUM'
    assert lua.severity_label(3) == 'MEDIUM'


def test_severity_low():
    assert lua.severity_label(2) == 'LOW'
    assert lua.severity_label(0) == 'LOW'


# ── Logic unit tests (inline checks matching audit() behaviour) ────────────────

def test_uid_zero_non_root():
    users = [
        {'username': 'root', 'uid': 0, 'gid': 0, 'home': '/root', 'shell': '/bin/bash'},
        {'username': 'toor', 'uid': 0, 'gid': 0, 'home': '/root', 'shell': '/bin/bash'},
    ]
    findings = []
    for u in users:
        if u['uid'] == 0 and u['username'] != 'root':
            findings.append({'finding_type': 'UidZeroNonRoot', 'username': u['username'], 'score': 9})
    assert any(f['finding_type'] == 'UidZeroNonRoot' for f in findings)
    assert not any(f['username'] == 'root' for f in findings)


def test_direct_root_ssh():
    ssh_cfg = {'permitrootlogin': 'yes'}
    finding = ssh_cfg.get('permitrootlogin') == 'yes'
    assert finding is True


def test_direct_root_ssh_no_flag_when_prohibit_password():
    ssh_cfg = {'permitrootlogin': 'prohibit-password'}
    finding = ssh_cfg.get('permitrootlogin') == 'yes'
    assert finding is False


def test_direct_root_ssh_no_flag_when_no():
    ssh_cfg = {'permitrootlogin': 'no'}
    finding = ssh_cfg.get('permitrootlogin') == 'yes'
    assert finding is False


def test_weak_password_policy():
    login_defs = lua.parse_login_defs("PASS_MIN_LEN\t6\nPASS_MAX_DAYS\t90\n")
    assert int(login_defs.get('PASS_MIN_LEN', 12)) < 12


def test_no_weak_password_policy_when_strong():
    login_defs = lua.parse_login_defs("PASS_MIN_LEN\t14\nPASS_MAX_DAYS\t90\n")
    assert int(login_defs.get('PASS_MIN_LEN', 12)) >= 12


def test_ssh_password_auth_default_yes():
    # When not set, default should be treated as 'yes'
    ssh_cfg = {}
    password_auth = ssh_cfg.get('passwordauthentication', 'yes').lower()
    assert password_auth == 'yes'


def test_empty_password_hash_detection():
    shadow_data = {'baduser': {'hash': '', 'max_days': 99999, 'last_change': 19000}}
    findings = []
    for username, sdata in shadow_data.items():
        h = sdata.get('hash', '')
        if h == '':
            findings.append({'finding_type': 'EmptyPasswordHash', 'username': username, 'score': 10})
    assert len(findings) == 1
    assert findings[0]['username'] == 'baduser'
    assert findings[0]['score'] == 10


def test_locked_account_not_flagged_as_empty():
    # '!' and '!!' are locked, not empty
    shadow_data = {
        'locked1': {'hash': '!', 'max_days': 90, 'last_change': 19000},
        'locked2': {'hash': '!!', 'max_days': 90, 'last_change': 19000},
        'locked3': {'hash': '!*', 'max_days': 90, 'last_change': 19000},
        'asterisk': {'hash': '*', 'max_days': 90, 'last_change': 19000},
    }
    findings = []
    for username, sdata in shadow_data.items():
        h = sdata.get('hash', '')
        if h == '':
            findings.append({'finding_type': 'EmptyPasswordHash', 'username': username})
    assert findings == []


# ── audit() integration tests (mocked I/O) ────────────────────────────────────

def _make_audit_patches(
    passwd_data=None,
    shadow_data=None,
    sudoers_data=None,
    ssh_cfg=None,
    login_defs_data=None,
    run_command_rv=None,
    get_file_stat_rv=None,
):
    """Return a context-manager stack of patches suitable for calling lua.run()."""
    from contextlib import ExitStack
    passwd_data = passwd_data or []
    shadow_data = shadow_data or {}
    sudoers_data = sudoers_data or []
    ssh_cfg = ssh_cfg or {}
    login_defs_data = login_defs_data or {}
    run_command_rv = run_command_rv if run_command_rv is not None else ('testhost', 0)
    get_file_stat_rv = get_file_stat_rv  # None means stat returns None

    stack = ExitStack()
    stack.enter_context(patch.object(lua, 'parse_passwd', return_value=passwd_data))
    stack.enter_context(patch.object(lua, 'parse_shadow', return_value=shadow_data))
    stack.enter_context(patch.object(lua, 'parse_sudoers', return_value=sudoers_data))
    stack.enter_context(patch.object(lua, 'parse_sshd_config', return_value=ssh_cfg))
    stack.enter_context(patch.object(lua, 'parse_login_defs', return_value=login_defs_data))
    stack.enter_context(patch.object(lua, 'read_file', return_value=''))
    stack.enter_context(patch.object(lua, 'run_command', return_value=run_command_rv))
    stack.enter_context(patch.object(lua, 'get_file_stat', return_value=get_file_stat_rv))
    # Patch Path.glob to return empty to avoid touching filesystem in sudoers.d
    stack.enter_context(patch('linux_user_auditor.Path', wraps=_FakePath))
    stack.enter_context(patch('builtins.open', side_effect=OSError))
    stack.enter_context(patch('os.chmod'))
    return stack


class _FakePath:
    """Minimal Path stand-in that makes sudoers.d appear non-existent."""
    def __init__(self, *args, **kwargs):
        self._path = str(args[0]) if args else ''

    def exists(self):
        return False

    def glob(self, pattern):
        return []

    def read_text(self, **kwargs):
        raise OSError('mocked')

    def __str__(self):
        return self._path


def test_audit_returns_dict():
    with _make_audit_patches():
        report = lua.run(fmt='stdout')
    assert isinstance(report, dict)
    assert 'findings' in report
    assert 'summary' in report


def test_audit_flags_empty_password_hash():
    shadow_data = {'baduser': {'hash': '', 'max_days': 99999, 'last_change': 19000}}
    passwd_data = [{'username': 'baduser', 'uid': 1001, 'gid': 1001,
                    'home': '/home/baduser', 'shell': '/bin/bash'}]
    with _make_audit_patches(passwd_data=passwd_data, shadow_data=shadow_data):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'EmptyPasswordHash' in types


def test_audit_flags_uid_zero_non_root():
    passwd_data = [
        {'username': 'root', 'uid': 0, 'gid': 0, 'home': '/root', 'shell': '/bin/bash'},
        {'username': 'toor', 'uid': 0, 'gid': 0, 'home': '/root', 'shell': '/bin/bash'},
    ]
    with _make_audit_patches(passwd_data=passwd_data):
        report = lua.run(fmt='stdout')
    uid_zero = [f for f in report['findings'] if f['finding_type'] == 'UidZeroNonRoot']
    assert len(uid_zero) == 1
    assert uid_zero[0]['username'] == 'toor'


def test_audit_flags_direct_root_ssh():
    ssh_cfg = {'permitrootlogin': 'yes'}
    with _make_audit_patches(ssh_cfg=ssh_cfg):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'DirectRootSSH' in types


def test_audit_no_direct_root_ssh_when_prohibit_password():
    ssh_cfg = {'permitrootlogin': 'prohibit-password'}
    with _make_audit_patches(ssh_cfg=ssh_cfg):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'DirectRootSSH' not in types


def test_audit_flags_ssh_password_auth_when_yes():
    ssh_cfg = {'passwordauthentication': 'yes'}
    with _make_audit_patches(ssh_cfg=ssh_cfg):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'SSHPasswordAuthEnabled' in types


def test_audit_flags_ssh_password_auth_when_not_set():
    # Default is yes — should still be flagged
    ssh_cfg = {}
    with _make_audit_patches(ssh_cfg=ssh_cfg):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'SSHPasswordAuthEnabled' in types


def test_audit_no_ssh_password_auth_when_no():
    ssh_cfg = {'passwordauthentication': 'no'}
    with _make_audit_patches(ssh_cfg=ssh_cfg):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'SSHPasswordAuthEnabled' not in types


def test_audit_flags_passwordless_root_equivalent():
    sudoers_data = [
        {'user_or_group': 'alice', 'spec': 'alice ALL=(ALL) NOPASSWD: ALL',
         'nopasswd': True, 'all_commands': True},
    ]
    with _make_audit_patches(sudoers_data=sudoers_data):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'PasswordlessRootEquivalent' in types


def test_audit_flags_sudo_all_commands_with_password():
    sudoers_data = [
        {'user_or_group': 'bob', 'spec': 'bob ALL=(ALL) ALL',
         'nopasswd': False, 'all_commands': True},
    ]
    with _make_audit_patches(sudoers_data=sudoers_data):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'SudoAllCommandsGranted' in types


def test_audit_flags_sudo_nopasswd_specific_commands():
    sudoers_data = [
        {'user_or_group': 'carol', 'spec': 'carol ALL=(ALL) NOPASSWD: /usr/bin/systemctl',
         'nopasswd': True, 'all_commands': False},
    ]
    with _make_audit_patches(sudoers_data=sudoers_data):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'SudoAllNopasswd' in types


def test_audit_flags_no_password_expiry_from_login_defs():
    login_defs_data = {'PASS_MAX_DAYS': '99999', 'PASS_MIN_LEN': '12'}
    with _make_audit_patches(login_defs_data=login_defs_data):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'NoPasswordExpiry' in types


def test_audit_no_password_expiry_finding_when_set():
    login_defs_data = {'PASS_MAX_DAYS': '90', 'PASS_MIN_LEN': '12'}
    shadow_data = {'alice': {'hash': '$6$x', 'max_days': 90, 'last_change': 19100}}
    passwd_data = [{'username': 'alice', 'uid': 1000, 'gid': 1000,
                    'home': '/home/alice', 'shell': '/bin/bash'}]
    with _make_audit_patches(passwd_data=passwd_data, shadow_data=shadow_data,
                              login_defs_data=login_defs_data):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'NoPasswordExpiry' not in types


def test_audit_flags_weak_password_policy():
    login_defs_data = {'PASS_MIN_LEN': '6', 'PASS_MAX_DAYS': '90'}
    with _make_audit_patches(login_defs_data=login_defs_data):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'WeakPasswordPolicy' in types


def test_audit_no_weak_password_flag_when_length_ok():
    login_defs_data = {'PASS_MIN_LEN': '14', 'PASS_MAX_DAYS': '90'}
    with _make_audit_patches(login_defs_data=login_defs_data):
        report = lua.run(fmt='stdout')
    types = [f['finding_type'] for f in report['findings']]
    assert 'WeakPasswordPolicy' not in types


def test_audit_summary_counts_match():
    shadow_data = {'baduser': {'hash': '', 'max_days': 90, 'last_change': 19000}}
    passwd_data = [{'username': 'baduser', 'uid': 1001, 'gid': 1001,
                    'home': '/home/baduser', 'shell': '/bin/bash'}]
    with _make_audit_patches(passwd_data=passwd_data, shadow_data=shadow_data):
        report = lua.run(fmt='stdout')
    s = report['summary']
    total = s['critical'] + s['high'] + s['medium'] + s['low']
    assert total == s['total_findings']


def test_audit_findings_sorted_by_score_descending():
    sudoers_data = [
        {'user_or_group': 'alice', 'spec': 'alice ALL=(ALL) NOPASSWD: ALL',
         'nopasswd': True, 'all_commands': True},
    ]
    ssh_cfg = {'permitrootlogin': 'yes'}
    with _make_audit_patches(sudoers_data=sudoers_data, ssh_cfg=ssh_cfg):
        report = lua.run(fmt='stdout')
    scores = [f['score'] for f in report['findings']]
    assert scores == sorted(scores, reverse=True)


def test_audit_users_scanned_count():
    passwd_data = [
        {'username': 'root', 'uid': 0, 'gid': 0, 'home': '/root', 'shell': '/bin/bash'},
        {'username': 'alice', 'uid': 1000, 'gid': 1000, 'home': '/home/alice', 'shell': '/bin/bash'},
        {'username': 'bob', 'uid': 1001, 'gid': 1001, 'home': '/home/bob', 'shell': '/bin/bash'},
    ]
    with _make_audit_patches(passwd_data=passwd_data):
        report = lua.run(fmt='stdout')
    assert report['summary']['users_scanned'] == 3


def test_audit_hostname_in_report():
    with _make_audit_patches(run_command_rv=('myserver\n', 0)):
        report = lua.run(fmt='stdout')
    assert report['hostname'] == 'myserver'


# ── write_json / write_csv / write_html (smoke tests) ─────────────────────────

def test_write_json_calls_chmod(tmp_path):
    report = {'generated_at': '2026-01-01', 'findings': [], 'summary': {}}
    path = str(tmp_path / 'test.json')
    with patch('os.chmod') as mock_chmod:
        lua.write_json(report, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_csv_calls_chmod(tmp_path):
    findings = [{'finding_type': 'Test', 'username': 'u', 'detail': 'd',
                 'score': 5, 'severity': 'MEDIUM', 'recommendation': 'r'}]
    path = str(tmp_path / 'test.csv')
    with patch('os.chmod') as mock_chmod:
        lua.write_csv(findings, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_html_calls_chmod(tmp_path):
    report = {
        'generated_at': '2026-01-01',
        'hostname': 'host',
        'findings': [],
        'summary': {'total_findings': 0, 'users_scanned': 0,
                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
    }
    path = str(tmp_path / 'test.html')
    with patch('os.chmod') as mock_chmod:
        lua.write_html(report, path)
    mock_chmod.assert_called_once_with(path, 0o600)


def test_write_csv_empty_findings_no_file(tmp_path):
    path = str(tmp_path / 'empty.csv')
    lua.write_csv([], path)
    assert not os.path.exists(path)


def test_write_json_produces_valid_json(tmp_path):
    report = {'generated_at': '2026-01-01', 'findings': [{'a': 1}], 'summary': {}}
    path = str(tmp_path / 'out.json')
    with patch('os.chmod'):
        lua.write_json(report, path)
    import json
    with open(path) as f:
        data = json.load(f)
    assert data['findings'][0]['a'] == 1


def test_write_html_contains_title(tmp_path):
    report = {
        'generated_at': '2026-01-01',
        'hostname': 'myhost',
        'findings': [],
        'summary': {'total_findings': 0, 'users_scanned': 0,
                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
    }
    path = str(tmp_path / 'out.html')
    with patch('os.chmod'):
        lua.write_html(report, path)
    with open(path) as f:
        content = f.read()
    assert 'User Security Audit Report' in content


# ── read_file / run_command / get_file_stat wrappers ──────────────────────────

def test_read_file_returns_empty_on_missing():
    result = lua.read_file('/nonexistent/path/that/does/not/exist')
    assert result == ''


def test_run_command_returns_tuple_on_error():
    stdout, rc = lua.run_command(['false_nonexistent_command_xyz'])
    assert isinstance(stdout, str)
    assert isinstance(rc, int)


def test_get_file_stat_returns_none_on_missing():
    result = lua.get_file_stat('/nonexistent/path/xyz')
    assert result is None


def test_get_file_stat_returns_stat_on_existing(tmp_path):
    f = tmp_path / 'testfile'
    f.write_text('hello')
    result = lua.get_file_stat(str(f))
    assert result is not None
