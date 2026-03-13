"""Tests for root_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../AWS/root-auditor"))

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
import root_auditor as ra


def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


# ── _mask_email ────────────────────────────────────────────────────────────────

def test_mask_email_normal():
    result = ra._mask_email("security@example.com")
    assert result == "se***@example.com"
    assert "security" not in result


def test_mask_email_short_local():
    result = ra._mask_email("a@example.com")
    assert "***" in result


def test_mask_email_no_at():
    result = ra._mask_email("notanemail")
    assert result == "Configured"


def test_mask_email_none():
    result = ra._mask_email(None)
    assert result == "Configured"


# ── check_mfa_devices ──────────────────────────────────────────────────────────

def test_check_mfa_virtual_found():
    iam = MagicMock()
    iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": [
        {"User": {"Arn": "arn:aws:iam::123456789012:root"}}
    ]}
    enabled, mfa_type = ra.check_mfa_devices(iam)
    assert enabled is True
    assert mfa_type == "Virtual MFA"


def test_check_mfa_hardware_via_account_summary():
    iam = MagicMock()
    iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": []}
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    enabled, mfa_type = ra.check_mfa_devices(iam)
    assert enabled is True
    assert "Hardware" in mfa_type


def test_check_mfa_none():
    iam = MagicMock()
    iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": []}
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
    enabled, mfa_type = ra.check_mfa_devices(iam)
    assert enabled is False
    assert mfa_type is None


def test_check_mfa_api_error_falls_through():
    iam = MagicMock()
    iam.list_virtual_mfa_devices.side_effect = _client_error("AccessDenied")
    iam.get_account_summary.side_effect = _client_error("AccessDenied")
    enabled, mfa_type = ra.check_mfa_devices(iam)
    assert enabled is False


# ── check_root_access_keys ─────────────────────────────────────────────────────

def test_check_root_keys_present():
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 1}}
    has_keys, count = ra.check_root_access_keys(iam)
    assert has_keys is True
    assert count == 1


def test_check_root_keys_absent():
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 0}}
    has_keys, count = ra.check_root_access_keys(iam)
    assert has_keys is False


# ── check_password_policy ──────────────────────────────────────────────────────

def test_password_policy_weak():
    iam = MagicMock()
    iam.get_account_password_policy.return_value = {"PasswordPolicy": {
        "MinimumPasswordLength": 6,
        "RequireUppercaseCharacters": False,
        "RequireLowercaseCharacters": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
        "MaxPasswordAge": 0,
        "PasswordReusePrevention": 0,
    }}
    policy, issues = ra.check_password_policy(iam)
    assert len(issues) > 0


def test_password_policy_no_policy():
    iam = MagicMock()
    iam.get_account_password_policy.side_effect = _client_error("NoSuchEntity")
    policy, issues = ra.check_password_policy(iam)
    assert policy is None
    assert any("No password policy" in i for i in issues)


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_no_mfa_critical():
    score, level = ra.calculate_score(True, False, False, False, False, False, 0)
    assert score >= 5


def test_score_root_keys_high():
    score, level = ra.calculate_score(False, True, False, False, False, False, 0)
    assert score >= 4


def test_score_all_clear():
    score, level = ra.calculate_score(False, False, False, False, False, False, 0)
    assert score == 0
    assert level == "LOW"
