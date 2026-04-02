"""Tests for backup_auditor.py"""
import sys
import os
import json
import stat
import tempfile
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import backup_auditor as ba


# -- Helpers -------------------------------------------------------------------

def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


def _make_backup_client(
    vaults=None,
    locked=False,
    recovery_points=None,
    policy=None,
    policy_error=None,
):
    """Return a mocked AWS Backup client."""
    client = MagicMock()

    if vaults is None:
        vaults = []
    client.list_backup_vaults.return_value = {"BackupVaultList": vaults}

    client.describe_backup_vault.return_value = {
        "BackupVaultName": "my-vault",
        "Locked": locked,
    }

    if recovery_points is None:
        recovery_points = []
    client.list_recovery_points_by_backup_vault.return_value = {
        "RecoveryPoints": recovery_points,
    }

    if policy_error:
        client.get_backup_vault_access_policy.side_effect = policy_error
    elif policy is not None:
        client.get_backup_vault_access_policy.return_value = {
            "Policy": json.dumps(policy),
        }
    else:
        # Default: no policy (ResourceNotFoundException)
        client.get_backup_vault_access_policy.side_effect = _client_error(
            "ResourceNotFoundException"
        )

    return client


def _vault_entry(name="my-vault"):
    return {
        "BackupVaultName": name,
        "BackupVaultArn": f"arn:aws:backup:us-east-1:123456789012:backup-vault:{name}",
    }


# -- Test 1: No vaults in region -> HIGH finding ------------------------------

def test_no_vaults_generates_high_finding():
    client = _make_backup_client(vaults=[])
    findings = ba.audit_region(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["check"] == "no_backup_vaults"
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["risk_level"] == "HIGH"


# -- Test 2: Vault present -> no "no vaults" finding --------------------------

def test_vault_present_no_missing_vault_finding():
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=True,
        recovery_points=[
            {"CreationDate": datetime.now(timezone.utc) - timedelta(days=1)}
        ],
    )
    findings = ba.audit_region(client, "us-east-1")
    no_vault_findings = [f for f in findings if f["check"] == "no_backup_vaults"]
    assert len(no_vault_findings) == 0


# -- Test 3: Vault not locked -> MEDIUM finding --------------------------------

def test_vault_not_locked_generates_medium_finding():
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=False,
        recovery_points=[
            {"CreationDate": datetime.now(timezone.utc) - timedelta(days=1)}
        ],
    )
    findings = ba.audit_region(client, "us-east-1")
    lock_findings = [f for f in findings if f["check"] == "vault_lock_not_configured"]
    assert len(lock_findings) == 1
    assert lock_findings[0]["severity"] == "MEDIUM"
    assert lock_findings[0]["status"] == "FAIL"


# -- Test 4: Vault locked -> no lock finding -----------------------------------

def test_vault_locked_no_lock_finding():
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=True,
        recovery_points=[
            {"CreationDate": datetime.now(timezone.utc) - timedelta(days=1)}
        ],
    )
    findings = ba.audit_region(client, "us-east-1")
    lock_findings = [f for f in findings if f["check"] == "vault_lock_not_configured"]
    assert len(lock_findings) == 0


# -- Test 5: No recovery points -> HIGH finding --------------------------------

def test_no_recovery_points_generates_high_finding():
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=True,
        recovery_points=[],
    )
    findings = ba.audit_region(client, "us-east-1")
    stale_findings = [f for f in findings if f["check"] == "no_recent_backups"]
    assert len(stale_findings) == 1
    assert stale_findings[0]["severity"] == "HIGH"
    assert stale_findings[0]["status"] == "FAIL"


# -- Test 6: Recent recovery point -> no staleness finding ---------------------

def test_recent_recovery_point_no_staleness_finding():
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=True,
        recovery_points=[
            {"CreationDate": datetime.now(timezone.utc) - timedelta(days=5)}
        ],
    )
    findings = ba.audit_region(client, "us-east-1")
    stale_findings = [f for f in findings if f["check"] == "no_recent_backups"]
    assert len(stale_findings) == 0


# -- Test 7: Stale recovery point (>30 days) -> HIGH finding -------------------

def test_stale_recovery_point_generates_high_finding():
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=True,
        recovery_points=[
            {"CreationDate": datetime.now(timezone.utc) - timedelta(days=60)}
        ],
    )
    findings = ba.audit_region(client, "us-east-1")
    stale_findings = [f for f in findings if f["check"] == "no_recent_backups"]
    assert len(stale_findings) == 1
    assert stale_findings[0]["severity"] == "HIGH"


# -- Test 8: Public vault policy -> CRITICAL finding ---------------------------

def test_public_vault_policy_generates_critical_finding():
    public_policy = {
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "backup:*"}
        ]
    }
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=True,
        recovery_points=[
            {"CreationDate": datetime.now(timezone.utc) - timedelta(days=1)}
        ],
        policy=public_policy,
    )
    findings = ba.audit_region(client, "us-east-1")
    policy_findings = [f for f in findings if f["check"] == "public_vault_policy"]
    assert len(policy_findings) == 1
    assert policy_findings[0]["severity"] == "CRITICAL"
    assert policy_findings[0]["severity_score"] == 10
    assert policy_findings[0]["status"] == "FAIL"


# -- Test 9: No vault policy (ResourceNotFoundException) -> no finding ---------

def test_no_vault_policy_resource_not_found_no_finding():
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=True,
        recovery_points=[
            {"CreationDate": datetime.now(timezone.utc) - timedelta(days=1)}
        ],
        policy_error=_client_error("ResourceNotFoundException"),
    )
    findings = ba.audit_region(client, "us-east-1")
    policy_findings = [f for f in findings if f["check"] == "public_vault_policy"]
    assert len(policy_findings) == 0


# -- Test 10: AccessDeniedException -> no crash, warning logged ----------------

def test_access_denied_no_crash(caplog):
    client = MagicMock()
    client.list_backup_vaults.side_effect = _client_error("AccessDeniedException")

    import logging
    with caplog.at_level(logging.WARNING):
        findings = ba.audit_region(client, "us-east-1")
    assert findings == []
    assert any("Access denied" in msg or "AccessDeniedException" in msg
               for msg in caplog.messages)


# -- Test 11: run() with fmt="stdout" returns without error --------------------

def test_run_stdout_returns_report():
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

    mock_backup = MagicMock()
    mock_backup.list_backup_vaults.return_value = {"BackupVaultList": []}

    def client_side_effect(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "backup":
            return mock_backup
        return MagicMock()

    mock_session.client.side_effect = client_side_effect

    with patch("boto3.Session", return_value=mock_session):
        report = ba.run(
            output_prefix="/dev/null",
            fmt="stdout",
            regions=["us-east-1"],
            profile=None,
        )

    assert "generated_at" in report
    assert "account_id" in report
    assert "summary" in report
    assert "findings" in report
    assert report["account_id"] == "123456789012"


# -- Test 12: Findings have cis_control field present --------------------------

def test_findings_have_cis_control():
    client = _make_backup_client(vaults=[])
    findings = ba.audit_region(client, "us-east-1")
    assert len(findings) >= 1
    for finding in findings:
        assert "cis_control" in finding
        assert finding["cis_control"] == "CIS 10.1"


# -- Test 13: Public policy with Condition -> NOT flagged ----------------------

def test_public_policy_with_condition_not_flagged():
    """A wildcard principal with a Condition block should not be flagged."""
    policy_with_condition = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "backup:CopyIntoBackupVault",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-12345"}},
            }
        ]
    }
    client = _make_backup_client(
        vaults=[_vault_entry()],
        locked=True,
        recovery_points=[
            {"CreationDate": datetime.now(timezone.utc) - timedelta(days=1)}
        ],
        policy=policy_with_condition,
    )
    findings = ba.audit_region(client, "us-east-1")
    policy_findings = [f for f in findings if f["check"] == "public_vault_policy"]
    assert len(policy_findings) == 0


# -- Test 14: Finding fields structure -----------------------------------------

def test_finding_has_all_required_fields():
    """Verify every finding from audit_region has the exact required fields."""
    client = _make_backup_client(vaults=[])
    findings = ba.audit_region(client, "us-east-1")
    required_fields = {
        "region", "resource", "check", "status", "severity",
        "risk_level", "severity_score", "description", "recommendation",
        "cis_control", "remediation", "flags", "remediations",
    }
    for finding in findings:
        assert required_fields.issubset(finding.keys()), (
            f"Missing fields: {required_fields - finding.keys()}"
        )
        assert isinstance(finding["flags"], list)
        assert isinstance(finding["remediations"], list)
        assert finding["severity"] == finding["risk_level"]
        assert finding["recommendation"] == finding["remediation"]
