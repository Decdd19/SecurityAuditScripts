"""Tests for root_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
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
    score, level = ra.calculate_score(True, False, False, False, False, False)
    assert score >= 5


def test_score_root_keys_high():
    score, level = ra.calculate_score(False, True, False, False, False, False)
    assert score >= 4


def test_score_all_clear():
    score, level = ra.calculate_score(False, False, False, False, False, False)
    assert score == 0
    assert level == "LOW"


# ── check_credential_report ────────────────────────────────────────────────────

def _make_credential_report_csv(password_last_used="no_information",
                                 access_key_1_last_used="N/A",
                                 mfa_active="false"):
    """Build a realistic IAM credential report CSV with a root account row."""
    headers = (
        "user,arn,user_creation_time,password_enabled,password_last_used,"
        "password_last_changed,password_next_rotation,mfa_active,"
        "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
        "access_key_1_last_used_region,access_key_1_last_used_service,"
        "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
        "access_key_2_last_used_region,access_key_2_last_used_service,"
        "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated"
    )
    root_row = (
        f"<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,"
        f"not_supported,{password_last_used},"
        f"not_supported,not_supported,{mfa_active},"
        f"false,N/A,{access_key_1_last_used},"
        f"N/A,N/A,"
        f"false,N/A,N/A,"
        f"N/A,N/A,"
        f"false,N/A,false,N/A"
    )
    return f"{headers}\n{root_row}".encode("utf-8")


def test_check_credential_report_no_root_login():
    iam = MagicMock()
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    now = datetime.now(timezone.utc)
    iam.get_credential_report.return_value = {
        "Content": _make_credential_report_csv(password_last_used="no_information"),
        "GeneratedTime": now,
        "ReportFormat": "text/csv",
    }
    root_line = ra.check_credential_report(iam)
    assert root_line is not None
    assert root_line["user"] == "<root_account>"
    # Caller logic: password_last_used "no_information" -> root_used_recently = False
    assert root_line["password_last_used"] == "no_information"


def test_check_credential_report_recent_root_login():
    iam = MagicMock()
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    five_days_ago = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    now = datetime.now(timezone.utc)
    iam.get_credential_report.return_value = {
        "Content": _make_credential_report_csv(password_last_used=five_days_ago),
        "GeneratedTime": now,
        "ReportFormat": "text/csv",
    }
    root_line = ra.check_credential_report(iam)
    assert root_line is not None
    pl = root_line["password_last_used"]
    assert pl not in ("no_information", "N/A")
    # Verify it's a parseable timestamp
    dt = datetime.fromisoformat(pl.replace("Z", "+00:00"))
    assert (datetime.now(timezone.utc) - dt).days < 10


def test_check_credential_report_stale_report():
    """A stale report (GeneratedTime older than 60 minutes) triggers a warning but still returns data."""
    iam = MagicMock()
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    stale_time = datetime.now(timezone.utc) - timedelta(hours=2)
    iam.get_credential_report.return_value = {
        "Content": _make_credential_report_csv(password_last_used="no_information"),
        "GeneratedTime": stale_time,
        "ReportFormat": "text/csv",
    }
    root_line = ra.check_credential_report(iam)
    # Despite stale report, processing continues and data is returned
    assert root_line is not None
    assert root_line["user"] == "<root_account>"


# ── check_alternate_contacts ───────────────────────────────────────────────────

def test_check_alternate_contacts_all_set():
    session = MagicMock()
    account_client = MagicMock()
    session.client.return_value = account_client
    account_client.get_alternate_contact.return_value = {
        "AlternateContact": {"EmailAddress": "admin@example.com"}
    }
    contacts = ra.check_alternate_contacts("123456789012", session)
    missing = [k for k, v in contacts.items() if v is None]
    assert missing == []
    assert set(contacts.keys()) == {"BILLING", "OPERATIONS", "SECURITY"}


def test_check_alternate_contacts_some_missing():
    session = MagicMock()
    account_client = MagicMock()
    session.client.return_value = account_client

    def get_alternate_contact(AlternateContactType):
        if AlternateContactType == "SECURITY":
            raise _client_error("ResourceNotFoundException")
        return {"AlternateContact": {"EmailAddress": "admin@example.com"}}

    account_client.get_alternate_contact.side_effect = get_alternate_contact
    contacts = ra.check_alternate_contacts("123456789012", session)
    missing = [k for k, v in contacts.items() if v is None]
    assert "SECURITY" in missing
    assert "BILLING" not in missing
    assert "OPERATIONS" not in missing


def test_check_alternate_contacts_api_unavailable():
    """AccessDeniedException is treated the same as ResourceNotFoundException
    (contact is set to None), so missing_contacts will contain those keys.
    The function does not distinguish denied from not-set — both result in None."""
    session = MagicMock()
    account_client = MagicMock()
    session.client.return_value = account_client
    account_client.get_alternate_contact.side_effect = _client_error("AccessDeniedException")
    contacts = ra.check_alternate_contacts("123456789012", session)
    # When access is denied, all contacts are set to None (cannot verify)
    # The function treats AccessDeniedException as "not found" (sets to None)
    # Callers may choose to handle this differently; here we verify no exception is raised
    assert isinstance(contacts, dict)
    assert set(contacts.keys()) == {"BILLING", "OPERATIONS", "SECURITY"}
    assert all(v is None for v in contacts.values())


# ── check_support_plan ─────────────────────────────────────────────────────────

def test_check_support_plan_business():
    session = MagicMock()
    support_client = MagicMock()
    session.client.return_value = support_client
    support_client.describe_severity_levels.return_value = {
        "severityLevels": [{"code": "critical", "name": "Critical"}]
    }
    result = ra.check_support_plan(session)
    assert "Business" in result or "higher" in result


def test_check_support_plan_basic():
    session = MagicMock()
    support_client = MagicMock()
    session.client.return_value = support_client
    support_client.describe_severity_levels.side_effect = _client_error("SubscriptionRequiredException")
    result = ra.check_support_plan(session)
    assert "Basic" in result


# ── audit_root integration tests ───────────────────────────────────────────────

def _make_clean_iam(recent_login=False, has_keys=False, mfa_enabled=True):
    """Build a fully mocked IAM client for audit_root."""
    iam = MagicMock()

    # MFA: virtual MFA assigned to root
    if mfa_enabled:
        iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": [
            {"User": {"Arn": "arn:aws:iam::123456789012:root"}}
        ]}
        iam.get_account_summary.return_value = {"SummaryMap": {
            "AccountMFAEnabled": 1,
            "AccountAccessKeysPresent": 1 if has_keys else 0,
        }}
    else:
        iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": []}
        iam.get_account_summary.return_value = {"SummaryMap": {
            "AccountMFAEnabled": 0,
            "AccountAccessKeysPresent": 1 if has_keys else 0,
        }}

    # Password policy — strong
    iam.get_account_password_policy.return_value = {"PasswordPolicy": {
        "MinimumPasswordLength": 14,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "RequireNumbers": True,
        "RequireSymbols": True,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 24,
    }}

    # Credential report
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    now = datetime.now(timezone.utc)
    if recent_login:
        password_last_used = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    else:
        password_last_used = "no_information"
    iam.get_credential_report.return_value = {
        "Content": _make_credential_report_csv(
            password_last_used=password_last_used,
            mfa_active="true" if mfa_enabled else "false",
        ),
        "GeneratedTime": now,
        "ReportFormat": "text/csv",
    }

    return iam


def _build_session_mock(iam, account_id="123456789012",
                         contacts_all_set=True, business_support=True,
                         is_org_master=False):
    """Build a session mock that returns the right client for each service."""
    session = MagicMock()

    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": account_id}

    account_client = MagicMock()
    if contacts_all_set:
        account_client.get_alternate_contact.return_value = {
            "AlternateContact": {"EmailAddress": "admin@example.com"}
        }
    else:
        def get_contact(AlternateContactType):
            raise _client_error("ResourceNotFoundException")
        account_client.get_alternate_contact.side_effect = get_contact

    org_client = MagicMock()
    if is_org_master:
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": account_id, "Id": "o-abc123", "Arn": "arn:aws:organizations::123456789012:organization/o-abc123"}
        }
    else:
        org_client.describe_organization.side_effect = _client_error("AWSOrganizationsNotInUseException")

    support_client = MagicMock()
    if business_support:
        support_client.describe_severity_levels.return_value = {"severityLevels": []}
    else:
        support_client.describe_severity_levels.side_effect = _client_error("SubscriptionRequiredException")

    def client_factory(service_name, **kwargs):
        mapping = {
            "iam": iam,
            "sts": sts,
            "account": account_client,
            "organizations": org_client,
            "support": support_client,
        }
        return mapping.get(service_name, MagicMock())

    session.client.side_effect = client_factory
    return session


def test_audit_root_critical_no_mfa_with_keys():
    """No MFA + root keys present should produce CRITICAL or HIGH risk."""
    iam = _make_clean_iam(mfa_enabled=False, has_keys=True, recent_login=True)
    session = _build_session_mock(iam, contacts_all_set=False, business_support=False)

    result = ra.audit_root(session)
    assert result["risk_level"] in ("CRITICAL", "HIGH")
    assert result["root_mfa_enabled"] is False
    assert result["root_access_keys_present"] is True


def test_audit_root_clean_account():
    """MFA enabled, no keys, no recent login, good policy, all contacts, Business support -> LOW."""
    iam = _make_clean_iam(mfa_enabled=True, has_keys=False, recent_login=False)
    session = _build_session_mock(
        iam,
        contacts_all_set=True,
        business_support=True,
        is_org_master=False,
    )

    result = ra.audit_root(session)
    assert result["risk_level"] == "LOW"
    assert result["root_mfa_enabled"] is True
    assert result["root_access_keys_present"] is False
    assert result["root_used_recently"] is False
    assert result["missing_alternate_contacts"] == []
    assert result["support_plan"] == "Business or higher"


# ── write_json / write_csv permissions ────────────────────────────────────────

def test_write_json_creates_file_with_600_perms(tmp_path):
    path = str(tmp_path / "root_report.json")
    report = {"generated_at": "2026-01-01", "account_id": "123456789012", "finding": {}}
    ra.write_json(report, path)
    assert os.path.exists(path)
    mode = oct(os.stat(path).st_mode)[-3:]
    assert mode == "600"


def test_write_csv_creates_file_with_600_perms(tmp_path):
    path = str(tmp_path / "root_report.csv")
    finding = {
        "account_id": "123456789012",
        "risk_level": "LOW",
        "severity_score": 0,
        "root_mfa_enabled": True,
        "root_mfa_type": "Virtual MFA",
        "root_access_keys_present": False,
        "root_access_key_count": 0,
        "root_last_console_login": None,
        "root_used_recently": False,
        "root_key_last_used": None,
        "password_policy_issues": [],
        "password_policy": {},
        "alternate_contacts": {},
        "missing_alternate_contacts": [],
        "is_org_management_account": False,
        "org_id": None,
        "support_plan": "Business or higher",
        "flags": [],
    }
    ra.write_csv(finding, path)
    assert os.path.exists(path)
    mode = oct(os.stat(path).st_mode)[-3:]
    assert mode == "600"
