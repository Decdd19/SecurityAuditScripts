"""Tests for kms_auditor.py"""
import sys
import os
import json
import stat
import tempfile
import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import kms_auditor as kma


# ── Helpers ───────────────────────────────────────────────────────────────────

def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


def _finding(**kwargs):
    defaults = {
        "key_id": "key-001",
        "key_arn": "arn:aws:kms:us-east-1:123456789012:key/key-001",
        "aliases": ["alias/my-key"],
        "key_state": "Enabled",
        "key_enabled": True,
        "key_spec": "SYMMETRIC_DEFAULT",
        "key_manager": "CUSTOMER",
        "multi_region": False,
        "rotation_enabled": True,
        "rotation_applicable": True,
        "public_policy": False,
        "creation_date": "2024-01-01T00:00:00+00:00",
        "region": "us-east-1",
    }
    defaults.update(kwargs)
    score, risk = kma.calculate_score(
        defaults["public_policy"],
        not defaults["rotation_enabled"] if defaults["rotation_enabled"] is not None else False,
        not defaults["key_enabled"],
    )
    defaults.update({"severity_score": score, "risk_level": risk})
    return defaults


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_public_policy_only():
    score, risk = kma.calculate_score(True, False, False)
    assert score == 5
    assert risk == "HIGH"


def test_score_no_rotation_only():
    score, risk = kma.calculate_score(False, True, False)
    assert score == 2
    assert risk == "MEDIUM"


def test_score_not_enabled_only():
    score, risk = kma.calculate_score(False, False, True)
    assert score == 3
    assert risk == "MEDIUM"


def test_score_public_policy_and_not_enabled():
    score, risk = kma.calculate_score(True, False, True)
    assert score == 8
    assert risk == "CRITICAL"


def test_score_all_issues():
    score, risk = kma.calculate_score(True, True, True)
    # 5 + 3 + 2 = 10, capped at 10
    assert score == 10
    assert risk == "CRITICAL"


def test_score_all_good_low():
    score, risk = kma.calculate_score(False, False, False)
    assert score == 0
    assert risk == "LOW"


def test_score_capped_at_10():
    # Even if weights exceed 10, cap enforced
    score, _ = kma.calculate_score(True, True, True)
    assert score <= 10


# ── _is_public_principal ──────────────────────────────────────────────────────

def test_public_principal_wildcard_string():
    assert kma._is_public_principal("*") is True


def test_public_principal_aws_wildcard_string():
    assert kma._is_public_principal({"AWS": "*"}) is True


def test_public_principal_aws_wildcard_in_list():
    assert kma._is_public_principal({"AWS": ["arn:aws:iam::123:root", "*"]}) is True


def test_public_principal_specific_arn_not_public():
    assert kma._is_public_principal({"AWS": "arn:aws:iam::123456789012:root"}) is False


def test_public_principal_service_not_public():
    assert kma._is_public_principal({"Service": "lambda.amazonaws.com"}) is False


def test_public_principal_aws_list_no_wildcard():
    assert kma._is_public_principal({"AWS": ["arn:aws:iam::111:role/A", "arn:aws:iam::222:role/B"]}) is False


# ── analyse_key ───────────────────────────────────────────────────────────────

def _make_kms_client(
    key_state="Enabled",
    key_spec="SYMMETRIC_DEFAULT",
    key_manager="CUSTOMER",
    rotation_enabled=True,
    aliases=None,
    policy_statements=None,
):
    """Return a mocked KMS client for a single key."""
    if aliases is None:
        aliases = [{"AliasName": "alias/test-key"}]
    if policy_statements is None:
        policy_statements = [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}, "Action": "kms:*"}
        ]

    kms = MagicMock()
    kms.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "key-001",
            "KeyArn": "arn:aws:kms:us-east-1:123:key/key-001",
            "KeyState": key_state,
            "KeySpec": key_spec,
            "KeyManager": key_manager,
            "MultiRegion": False,
            "CreationDate": __import__("datetime").datetime(2024, 1, 1, tzinfo=__import__("datetime").timezone.utc),
            "Description": "test key",
        }
    }
    kms.list_aliases.return_value = {"Aliases": aliases}
    kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": rotation_enabled}
    kms.get_key_policy.return_value = {
        "Policy": json.dumps({"Statement": policy_statements})
    }
    return kms


def test_analyse_key_symmetric_rotation_checked():
    kms = _make_kms_client(key_spec="SYMMETRIC_DEFAULT", rotation_enabled=True)
    result = kma.analyse_key(kms, "key-001", "arn:aws:kms:us-east-1:123:key/key-001", "us-east-1")
    assert result is not None
    assert result["rotation_enabled"] is True
    assert result["rotation_applicable"] is True


def test_analyse_key_symmetric_no_rotation_flagged():
    kms = _make_kms_client(key_spec="SYMMETRIC_DEFAULT", rotation_enabled=False)
    result = kma.analyse_key(kms, "key-001", "arn:aws:kms:us-east-1:123:key/key-001", "us-east-1")
    assert result["rotation_enabled"] is False
    assert result["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    warning_flags = [f for f in result["flags"] if "rotation" in f.lower() and "⚠️" in f]
    assert len(warning_flags) > 0


def test_analyse_key_asymmetric_rotation_not_applicable():
    kms = _make_kms_client(key_spec="RSA_2048", rotation_enabled=False)
    # get_key_rotation_status should not be called for asymmetric keys,
    # but even if it is, rotation_applicable should be False
    result = kma.analyse_key(kms, "key-001", "arn:aws:kms:us-east-1:123:key/key-001", "us-east-1")
    assert result["rotation_applicable"] is False
    assert result["rotation_enabled"] is None


def test_analyse_key_disabled_state_flagged():
    kms = _make_kms_client(key_state="Disabled")
    result = kma.analyse_key(kms, "key-001", "arn:aws:kms:us-east-1:123:key/key-001", "us-east-1")
    assert result["key_enabled"] is False
    assert result["key_state"] == "Disabled"
    not_enabled_flags = [f for f in result["flags"] if "state" in f.lower() and "⚠️" in f]
    assert len(not_enabled_flags) > 0


def test_analyse_key_public_policy_flagged():
    kms = _make_kms_client(
        policy_statements=[
            {"Effect": "Allow", "Principal": "*", "Action": "kms:*"}
        ]
    )
    result = kma.analyse_key(kms, "key-001", "arn:aws:kms:us-east-1:123:key/key-001", "us-east-1")
    assert result["public_policy"] is True
    assert result["risk_level"] in ("HIGH", "CRITICAL")


def test_analyse_key_no_alias_flagged():
    kms = _make_kms_client(aliases=[])
    result = kma.analyse_key(kms, "key-001", "arn:aws:kms:us-east-1:123:key/key-001", "us-east-1")
    assert result["aliases"] == []
    info_flags = [f for f in result["flags"] if "alias" in f.lower()]
    assert len(info_flags) > 0


def test_analyse_key_skips_aws_managed():
    kms = _make_kms_client(key_manager="AWS")
    result = kma.analyse_key(kms, "key-001", "arn:aws:kms:us-east-1:123:key/key-001", "us-east-1")
    assert result is None


# ── build_flags ───────────────────────────────────────────────────────────────

def test_build_flags_enabled_with_rotation_has_positive_flags_last():
    flags, remediations = kma.build_flags(
        key_enabled=True,
        key_state="Enabled",
        rotation_enabled=True,
        rotation_applicable=True,
        public_policy=False,
        aliases=["alias/my-key"],
    )
    # No warning/error flags
    warning_flags = [f for f in flags if f.startswith("⚠️") or f.startswith("❌")]
    assert warning_flags == []
    # Positive flags present
    positive_flags = [f for f in flags if f.startswith("✅")]
    assert len(positive_flags) >= 2
    # Positive flags come after all remediations (i.e., after index len(remediations)-1)
    for i, flag in enumerate(flags):
        if flag.startswith("✅"):
            assert i >= len(remediations)


def test_build_flags_disabled_key_has_warning():
    flags, remediations = kma.build_flags(
        key_enabled=False,
        key_state="Disabled",
        rotation_enabled=True,
        rotation_applicable=True,
        public_policy=False,
        aliases=["alias/my-key"],
    )
    warning_flags = [f for f in flags if "Disabled" in f and "⚠️" in f]
    assert len(warning_flags) > 0


def test_build_flags_public_policy_has_critical_flag():
    flags, remediations = kma.build_flags(
        key_enabled=True,
        key_state="Enabled",
        rotation_enabled=True,
        rotation_applicable=True,
        public_policy=True,
        aliases=["alias/my-key"],
    )
    critical_flags = [f for f in flags if f.startswith("❌") and "public" in f.lower()]
    assert len(critical_flags) > 0
    assert len(remediations) >= 1


def test_build_flags_asymmetric_has_na_info():
    flags, _ = kma.build_flags(
        key_enabled=True,
        key_state="Enabled",
        rotation_enabled=None,
        rotation_applicable=False,
        public_policy=False,
        aliases=["alias/rsa-key"],
    )
    na_flags = [f for f in flags if "not applicable" in f.lower() or "n/a" in f.lower()]
    assert len(na_flags) > 0


# ── write_json ────────────────────────────────────────────────────────────────

def test_write_json_creates_file_with_correct_permissions():
    f1 = _finding()
    report = {
        "generated_at": "2024-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "summary": {"total_keys": 1, "critical": 0, "high": 0, "medium": 0, "low": 1,
                    "no_rotation": 0, "public_policy": 0, "not_enabled": 0},
        "findings": [f1],
    }
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        path = tmp.name
    try:
        kma.write_json(report, path)
        assert os.path.exists(path)
        file_stat = os.stat(path)
        assert stat.S_IMODE(file_stat.st_mode) == 0o600
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["account_id"] == "123456789012"
        assert len(loaded["findings"]) == 1
    finally:
        os.unlink(path)


# ── write_csv ─────────────────────────────────────────────────────────────────

def test_write_csv_creates_file_with_correct_permissions():
    findings = [_finding(), _finding(key_id="key-002", rotation_enabled=False)]
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        path = tmp.name
    try:
        kma.write_csv(findings, path)
        assert os.path.exists(path)
        file_stat = os.stat(path)
        assert stat.S_IMODE(file_stat.st_mode) == 0o600
        with open(path) as f:
            content = f.read()
        assert "key_id" in content
        assert "key-001" in content
    finally:
        os.unlink(path)


def test_write_csv_empty_findings_does_not_create():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        path = tmp.name
    os.unlink(path)  # remove so we can check it's not created
    kma.write_csv([], path)
    assert not os.path.exists(path)


# ── run (integration) ─────────────────────────────────────────────────────────

def test_run_returns_report_with_correct_structure():
    """Mock boto3 entirely and verify the report structure from run()."""
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_kms = MagicMock()

    # Two customer-managed keys
    mock_kms.get_paginator.return_value.paginate.return_value = [
        {
            "Keys": [
                {"KeyId": "key-aaa", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-aaa"},
                {"KeyId": "key-bbb", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-bbb"},
            ]
        }
    ]

    from datetime import datetime, timezone as tz
    creation = datetime(2024, 1, 1, tzinfo=tz.utc)

    def describe_key_side_effect(KeyId):
        return {
            "KeyMetadata": {
                "KeyId": KeyId,
                "KeyArn": f"arn:aws:kms:us-east-1:123:key/{KeyId}",
                "KeyState": "Enabled",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "KeyManager": "CUSTOMER",
                "MultiRegion": False,
                "CreationDate": creation,
                "Description": "",
            }
        }

    mock_kms.describe_key.side_effect = describe_key_side_effect
    mock_kms.list_aliases.return_value = {"Aliases": [{"AliasName": "alias/test"}]}
    mock_kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    mock_kms.get_key_policy.return_value = {
        "Policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}, "Action": "kms:*"}
        ]})
    }

    def client_side_effect(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "kms":
            return mock_kms
        return MagicMock()

    mock_session.client.side_effect = client_side_effect

    with patch("boto3.Session", return_value=mock_session):
        report = kma.run(output_prefix="/dev/null", fmt="stdout", profile=None, regions=["us-east-1"])

    assert "generated_at" in report
    assert "account_id" in report
    assert "summary" in report
    assert "findings" in report
    summary = report["summary"]
    assert "total_keys" in summary
    assert "critical" in summary
    assert "high" in summary
    assert "medium" in summary
    assert "low" in summary
    assert "no_rotation" in summary
    assert "public_policy" in summary
    assert "not_enabled" in summary
    assert summary["total_keys"] == 2
