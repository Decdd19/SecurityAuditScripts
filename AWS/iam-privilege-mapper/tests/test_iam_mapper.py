"""Tests for iam_mapper_v2.py — remediation hints in HTML output and JSON flags."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import iam_mapper_v2 as iam_mapper
from unittest.mock import MagicMock


def test_write_html_includes_remediation_for_mfa_warning(tmp_path):
    """write_html should include remediation text for MFA warning."""
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "scp_analysis": False,
        "summary": {
            "total_principals": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "users_without_mfa": 1,
            "stale_keys": 0,
            "cross_account_roles": 0,
            "admin_policy_holders": 0,
        },
        "findings": [{
            "type": "user",
            "name": "alice",
            "arn": "arn:aws:iam::123:user/alice",
            "risk_level": "CRITICAL",
            "severity_score": 8,
            "console_access": True,
            "password_last_used": None,
            "mfa_enabled": False,
            "mfa_warning": True,
            "groups": [],
            "has_admin_policy": False,
            "permission_boundary": None,
            "high_risk_actions": [],
            "privilege_escalation_paths": [],
            "access_key_issues": [],
            "access_keys": [],
            "total_actions_count": 5,
            "scp_restrictions_applied": False,
            "cross_account_trust": False,
        }],
    }
    path = str(tmp_path / "test.html")
    iam_mapper.write_html(report, path)
    content = open(path).read()
    assert "IAM Console" in content
    assert "MFA device" in content
    assert "rem-text" in content


def test_write_html_includes_remediation_for_admin_policy(tmp_path):
    """write_html should include remediation text for admin policy warning."""
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "scp_analysis": False,
        "summary": {
            "total_principals": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "users_without_mfa": 0,
            "stale_keys": 0,
            "cross_account_roles": 0,
            "admin_policy_holders": 1,
        },
        "findings": [{
            "type": "user",
            "name": "admin-user",
            "arn": "arn:aws:iam::123:user/admin-user",
            "risk_level": "CRITICAL",
            "severity_score": 9,
            "console_access": True,
            "password_last_used": None,
            "mfa_enabled": True,
            "mfa_warning": False,
            "groups": [],
            "has_admin_policy": True,
            "permission_boundary": None,
            "high_risk_actions": ["*"],
            "privilege_escalation_paths": [],
            "access_key_issues": [],
            "access_keys": [],
            "total_actions_count": 1,
            "scp_restrictions_applied": False,
            "cross_account_trust": False,
        }],
    }
    path = str(tmp_path / "test.html")
    iam_mapper.write_html(report, path)
    content = open(path).read()
    assert "AdministratorAccess" in content
    assert "least-privilege" in content


# ── _build_iam_flags ──────────────────────────────────────────────────────────

_BASE_FINDING = {
    "type": "user",
    "name": "test",
    "arn": "arn:aws:iam::123:user/test",
    "risk_level": "HIGH",
    "severity_score": 6,
    "mfa_warning": False,
    "has_admin_policy": False,
    "cross_account_trust": False,
    "privilege_escalation_paths": [],
    "high_risk_actions": [],
    "access_key_issues": [],
    "permission_boundary": None,
}


def test_build_iam_flags_mfa_warning():
    f = {**_BASE_FINDING, "mfa_warning": True}
    flags, rems = iam_mapper._build_iam_flags(f)
    assert any("No MFA" in fl for fl in flags)
    assert any("MFA device" in r for r in rems)
    assert len(flags) == len(rems)


def test_build_iam_flags_admin_policy():
    f = {**_BASE_FINDING, "has_admin_policy": True}
    flags, rems = iam_mapper._build_iam_flags(f)
    assert any("Admin Policy" in fl for fl in flags)
    assert any("least-privilege" in r for r in rems)


def test_build_iam_flags_high_risk_actions_uses_info_prefix():
    """ℹ️ prefix triggers quick_wins in exec_summary for HIGH/CRITICAL findings."""
    f = {**_BASE_FINDING, "high_risk_actions": ["iam:*", "ec2:*"]}
    flags, rems = iam_mapper._build_iam_flags(f)
    assert any(fl.startswith("ℹ️") for fl in flags)


def test_build_iam_flags_privesc():
    f = {**_BASE_FINDING, "privilege_escalation_paths": ["iam:PassRole → lambda:InvokeFunction"]}
    flags, rems = iam_mapper._build_iam_flags(f)
    assert any("Privilege Escalation" in fl for fl in flags)
    assert any("PassRole" in r for r in rems)


def test_build_iam_flags_boundary_is_positive():
    f = {**_BASE_FINDING, "permission_boundary": "arn:aws:iam::123:policy/boundary"}
    flags, rems = iam_mapper._build_iam_flags(f)
    assert any("✅" in fl for fl in flags)


def test_build_iam_flags_clean_finding_has_empty_lists():
    flags, rems = iam_mapper._build_iam_flags(_BASE_FINDING)
    assert flags == []
    assert rems == []


def test_build_iam_flags_parallel_lengths():
    """flags and remediations must always have equal length."""
    f = {
        **_BASE_FINDING,
        "mfa_warning": True,
        "has_admin_policy": True,
        "high_risk_actions": ["iam:*"],
        "access_key_issues": ["Key AKIA... is 120 days old"],
        "permission_boundary": "arn:aws:iam::123:policy/b",
    }
    flags, rems = iam_mapper._build_iam_flags(f)
    assert len(flags) == len(rems), "flags and remediations lists must be the same length"


# ── analyse_role cross-account detection ──────────────────────────────────────

def _make_iam_for_role():
    """Minimal IAM mock for analyse_role — returns empty policies and no boundary."""
    iam = MagicMock()
    iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    iam.list_role_policies.return_value = {"PolicyNames": []}
    iam.get_role_policy.return_value = {"PolicyDocument": {"Statement": []}}
    iam.get_role_policy.side_effect = None
    iam.list_role_tags.return_value = {"Tags": []}
    return iam


def _role_with_trust(principal_arn):
    return {
        "RoleName": "MyRole",
        "Arn": "arn:aws:iam::111111111111:role/MyRole",
        "AssumeRolePolicyDocument": {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "sts:AssumeRole",
            }]
        },
    }


def test_analyse_role_same_account_not_cross_account():
    """Role that trusts a principal in the SAME account must NOT be flagged cross-account."""
    iam = _make_iam_for_role()
    role = _role_with_trust("arn:aws:iam::111111111111:role/TrusterRole")
    result = iam_mapper.analyse_role(iam, role, set(), own_account="111111111111")
    assert result["cross_account_trust"] is False


def test_analyse_role_different_account_is_cross_account():
    """Role that trusts a principal in a DIFFERENT account must be flagged cross-account."""
    iam = _make_iam_for_role()
    role = _role_with_trust("arn:aws:iam::999999999999:role/ExternalRole")
    result = iam_mapper.analyse_role(iam, role, set(), own_account="111111111111")
    assert result["cross_account_trust"] is True


def test_analyse_role_own_account_none_falls_back_to_any_iam_arn():
    """When own_account is None (STS unavailable), any IAM ARN in trust = cross-account."""
    iam = _make_iam_for_role()
    role = _role_with_trust("arn:aws:iam::111111111111:role/SameAccountRole")
    result = iam_mapper.analyse_role(iam, role, set(), own_account=None)
    assert result["cross_account_trust"] is True
