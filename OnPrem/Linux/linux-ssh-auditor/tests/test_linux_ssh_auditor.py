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
