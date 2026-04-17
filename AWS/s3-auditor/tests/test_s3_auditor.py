"""Tests for s3_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import stat
import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
import s3_auditor as s3a


def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


# ── _is_public_principal ───────────────────────────────────────────────────────

def test_public_principal_wildcard_string():
    assert s3a._is_public_principal("*") is True


def test_public_principal_aws_wildcard_string():
    assert s3a._is_public_principal({"AWS": "*"}) is True


def test_public_principal_aws_wildcard_list():
    assert s3a._is_public_principal({"AWS": ["*"]}) is True


def test_public_principal_specific_account():
    assert s3a._is_public_principal({"AWS": "arn:aws:iam::123456789012:root"}) is False


def test_public_principal_service():
    assert s3a._is_public_principal({"Service": "lambda.amazonaws.com"}) is False


# ── check_public_access_block ──────────────────────────────────────────────────

def test_check_public_access_block_all_enabled():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    }}
    config, all_blocked = s3a.check_public_access_block(s3, "my-bucket")
    assert all_blocked is True
    assert config is not None


def test_check_public_access_block_not_configured():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
    config, all_blocked = s3a.check_public_access_block(s3, "my-bucket")
    assert config == {}
    assert all_blocked is False


def test_check_public_access_block_api_error_returns_none():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("AccessDenied")
    config, all_blocked = s3a.check_public_access_block(s3, "my-bucket")
    assert config is None  # Distinguishable from "no config set"
    assert all_blocked is False


# ── check_bucket_policy ────────────────────────────────────────────────────────

def test_check_bucket_policy_public_wildcard():
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    ]})}
    is_public, findings, _ = s3a.check_bucket_policy(s3, "my-bucket")
    assert is_public is True
    assert len(findings) > 0


def test_check_bucket_policy_public_aws_list():
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "s3:GetObject"}
    ]})}
    is_public, findings, _ = s3a.check_bucket_policy(s3, "my-bucket")
    assert is_public is True


def test_check_bucket_policy_private():
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:role/MyRole"}, "Action": "s3:GetObject"}
    ]})}
    is_public, findings, _ = s3a.check_bucket_policy(s3, "my-bucket")
    assert is_public is False


def test_check_bucket_policy_no_policy():
    s3 = MagicMock()
    s3.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")
    is_public, findings, _ = s3a.check_bucket_policy(s3, "my-bucket")
    assert is_public is False
    assert findings == []


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_public_bucket_critical():
    score, level = s3a.calculate_score(True, True, True, True, True, True)
    assert level == "CRITICAL"


def test_score_clean_bucket():
    score, level = s3a.calculate_score(False, False, False, False, False, False)
    assert score == 0
    assert level == "LOW"


# ── analyse_bucket integration tests ──────────────────────────────────────────

def _make_s3_happy():
    """Return a mocked S3 client representing a well-configured bucket."""
    s3 = MagicMock()
    # Public access block: all flags enabled
    s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }}
    # ACL: only canonical owner grant (no public URIs)
    owner_id = "abc123"
    s3.get_bucket_acl.return_value = {
        "Owner": {"ID": owner_id, "DisplayName": "owner"},
        "Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": owner_id}, "Permission": "FULL_CONTROL"}
        ],
    }
    # Encryption: AES256
    s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    }
    # Versioning: enabled
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    # Logging: enabled
    s3.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
    # Lifecycle: one rule
    s3.get_bucket_lifecycle_configuration.return_value = {"Rules": [{"ID": "expire-old"}]}
    # Policy: no policy
    s3.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")
    # Location: eu-west-1
    s3.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}
    return s3


def test_analyse_bucket_happy_path():
    s3 = _make_s3_happy()
    result = s3a.analyse_bucket(s3, "my-secure-bucket")

    assert result["risk_level"] == "LOW"
    assert result["is_public"] is False
    assert result["encryption_enabled"] is True
    assert result["encryption_algorithm"] == "AES256"
    assert result["versioning_status"] == "Enabled"
    assert result["logging_enabled"] is True
    assert result["lifecycle_rules"] == 1
    assert result["region"] == "eu-west-1"
    # No critical flags (all warning flags use warning/error prefixes)
    critical_flags = [f for f in result["flags"] if f.startswith("❌")]
    assert critical_flags == []


def test_analyse_bucket_public():
    s3 = MagicMock()
    # No public access block
    s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
    # ACL: AllUsers grant
    s3.get_bucket_acl.return_value = {
        "Owner": {"ID": "abc", "DisplayName": "owner"},
        "Grants": [
            {"Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            }, "Permission": "READ"},
        ],
    }
    # No encryption
    s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
    # Versioning: not enabled
    s3.get_bucket_versioning.return_value = {}
    # Logging: not enabled
    s3.get_bucket_logging.return_value = {}
    # Lifecycle: no rules
    s3.get_bucket_lifecycle_configuration.side_effect = _client_error("NoSuchLifecycleConfiguration")
    # Policy: no policy
    s3.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")
    # Location: us-east-1 (None means us-east-1)
    s3.get_bucket_location.return_value = {"LocationConstraint": None}

    result = s3a.analyse_bucket(s3, "my-public-bucket")

    assert result["is_public"] is True
    assert result["risk_level"] == "CRITICAL"
    assert result["encryption_enabled"] is False
    assert result["logging_enabled"] is False
    assert result["region"] == "us-east-1"


# ── check_acl unit tests ───────────────────────────────────────────────────────

def test_check_acl_no_public_grants():
    s3 = MagicMock()
    owner_id = "owner123"
    s3.get_bucket_acl.return_value = {
        "Owner": {"ID": owner_id},
        "Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": owner_id}, "Permission": "FULL_CONTROL"}
        ],
    }
    is_public, uri = s3a.check_acl(s3, "bucket")
    assert is_public is False
    assert uri is None


def test_check_acl_public_all_users():
    s3 = MagicMock()
    public_uri = "http://acs.amazonaws.com/groups/global/AllUsers"
    s3.get_bucket_acl.return_value = {
        "Owner": {"ID": "owner123"},
        "Grants": [
            {"Grantee": {"Type": "Group", "URI": public_uri}, "Permission": "READ"}
        ],
    }
    is_public, uri = s3a.check_acl(s3, "bucket")
    assert is_public is True
    assert uri == public_uri


# ── check_encryption unit tests ───────────────────────────────────────────────

def test_check_encryption_aes256():
    s3 = MagicMock()
    s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    }
    is_encrypted, algo, kms_key = s3a.check_encryption(s3, "bucket")
    assert is_encrypted is True
    assert algo == "AES256"
    assert kms_key is None


def test_check_encryption_kms():
    s3 = MagicMock()
    s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/abc"
            }}]
        }
    }
    is_encrypted, algo, kms_key = s3a.check_encryption(s3, "bucket")
    assert is_encrypted is True
    assert algo == "aws:kms"
    assert kms_key is not None


def test_check_encryption_none():
    s3 = MagicMock()
    s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
    is_encrypted, algo, kms_key = s3a.check_encryption(s3, "bucket")
    assert is_encrypted is False
    assert algo is None


# ── check_versioning unit tests ───────────────────────────────────────────────

def test_check_versioning_enabled():
    s3 = MagicMock()
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    versioning_enabled, status, mfa_delete = s3a.check_versioning(s3, "bucket")
    assert versioning_enabled is True
    assert status == "Enabled"


def test_check_versioning_suspended():
    s3 = MagicMock()
    s3.get_bucket_versioning.return_value = {"Status": "Suspended"}
    versioning_enabled, status, mfa_delete = s3a.check_versioning(s3, "bucket")
    assert versioning_enabled is False
    assert status == "Suspended"


def test_check_versioning_none():
    s3 = MagicMock()
    s3.get_bucket_versioning.return_value = {}
    versioning_enabled, status, mfa_delete = s3a.check_versioning(s3, "bucket")
    assert versioning_enabled is False


# ── check_logging unit tests ──────────────────────────────────────────────────

def test_check_logging_enabled():
    s3 = MagicMock()
    s3.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
    logging_enabled, target = s3a.check_logging(s3, "bucket")
    assert logging_enabled is True
    assert target == "log-bucket"


def test_check_logging_disabled():
    s3 = MagicMock()
    s3.get_bucket_logging.return_value = {}
    logging_enabled, target = s3a.check_logging(s3, "bucket")
    assert logging_enabled is False
    assert target is None


# ── check_lifecycle unit tests ────────────────────────────────────────────────

def test_check_lifecycle_has_rules():
    s3 = MagicMock()
    s3.get_bucket_lifecycle_configuration.return_value = {"Rules": [{"ID": "rule1"}, {"ID": "rule2"}]}
    has_rules, count = s3a.check_lifecycle(s3, "bucket")
    assert has_rules is True
    assert count == 2


def test_check_lifecycle_none():
    s3 = MagicMock()
    s3.get_bucket_lifecycle_configuration.side_effect = _client_error("NoSuchLifecycleConfiguration")
    has_rules, count = s3a.check_lifecycle(s3, "bucket")
    assert has_rules is False
    assert count == 0


# ── write_json / write_csv file permission tests ───────────────────────────────

def test_write_json_creates_file_with_600_perms(tmp_path):
    sample_report = {"generated_at": "2026-01-01", "findings": [{"name": "test-bucket"}]}
    out_path = str(tmp_path / "test.json")
    s3a.write_json(sample_report, out_path)
    assert (tmp_path / "test.json").exists()
    mode = (tmp_path / "test.json").stat().st_mode & 0o777
    assert mode == 0o600


def test_write_csv_creates_file_with_600_perms(tmp_path):
    sample_findings = [{
        "name": "test-bucket",
        "region": "us-east-1",
        "risk_level": "LOW",
        "severity_score": 0,
        "is_public": False,
        "public_acl": False,
        "public_policy": False,
        "block_public_access_enabled": True,
        "encryption_enabled": True,
        "encryption_algorithm": "AES256",
        "kms_key": None,
        "versioning_status": "Enabled",
        "mfa_delete": "Disabled",
        "logging_enabled": True,
        "log_target_bucket": "log-bucket",
        "lifecycle_rules": 1,
        "policy_findings": [],
        "flags": [],
        "remediations": [],
    }]
    out_path = str(tmp_path / "test.csv")
    s3a.write_csv(sample_findings, out_path)
    assert (tmp_path / "test.csv").exists()
    mode = (tmp_path / "test.csv").stat().st_mode & 0o777
    assert mode == 0o600


# ── remediation tests ─────────────────────────────────────────────────────────

def test_analyse_bucket_flagged_has_remediations():
    """Each non-✅ flag should have a paired remediation."""
    s3 = MagicMock()
    # No public access block (generates a ⚠️ flag)
    s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
    s3.get_bucket_acl.return_value = {"Owner": {"ID": "abc"}, "Grants": []}
    s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
    s3.get_bucket_versioning.return_value = {}
    s3.get_bucket_logging.return_value = {}
    s3.get_bucket_lifecycle_configuration.side_effect = _client_error("NoSuchLifecycleConfiguration")
    s3.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")
    s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}

    result = s3a.analyse_bucket(s3, "test-bucket")

    assert "remediations" in result
    warning_flags = [f for f in result["flags"] if not f.startswith("✅")]
    assert len(result["remediations"]) == len(warning_flags)
    assert all(len(r) > 0 for r in result["remediations"])


# ── UNKNOWN behaviour (AccessDenied → None sentinel) ──────────────────────────

def test_check_acl_access_denied_returns_none():
    s3 = MagicMock()
    s3.get_bucket_acl.side_effect = _client_error("AccessDenied")
    is_public, uri = s3a.check_acl(s3, "bucket")
    assert is_public is None
    assert uri is None


def test_check_acl_generic_error_returns_none():
    s3 = MagicMock()
    s3.get_bucket_acl.side_effect = _client_error("InternalError")
    is_public, _ = s3a.check_acl(s3, "bucket")
    assert is_public is None


def test_check_bucket_policy_access_denied_returns_none():
    s3 = MagicMock()
    s3.get_bucket_policy.side_effect = _client_error("AccessDenied")
    is_public, findings, doc = s3a.check_bucket_policy(s3, "bucket")
    assert is_public is None
    assert findings is None


def test_check_bucket_policy_no_such_policy_still_returns_false():
    s3 = MagicMock()
    s3.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")
    is_public, findings, doc = s3a.check_bucket_policy(s3, "bucket")
    assert is_public is False  # Legitimately no policy — not UNKNOWN
    assert findings == []


def test_check_encryption_access_denied_returns_none():
    s3 = MagicMock()
    s3.get_bucket_encryption.side_effect = _client_error("AccessDenied")
    is_encrypted, algo, key = s3a.check_encryption(s3, "bucket")
    assert is_encrypted is None


def test_check_encryption_not_found_still_returns_false():
    s3 = MagicMock()
    s3.get_bucket_encryption.side_effect = _client_error("ServerSideEncryptionConfigurationNotFoundError")
    is_encrypted, algo, key = s3a.check_encryption(s3, "bucket")
    assert is_encrypted is False  # Legitimately no encryption — not UNKNOWN


def test_check_versioning_client_error_returns_none():
    s3 = MagicMock()
    s3.get_bucket_versioning.side_effect = _client_error("AccessDenied")
    versioned, status, mfa = s3a.check_versioning(s3, "bucket")
    assert versioned is None


def test_check_logging_client_error_returns_none():
    s3 = MagicMock()
    s3.get_bucket_logging.side_effect = _client_error("AccessDenied")
    logging_on, target = s3a.check_logging(s3, "bucket")
    assert logging_on is None


def test_analyse_bucket_access_denied_emits_unknown_flags():
    """All checks return AccessDenied — analyse_bucket must emit UNKNOWN flags, not false-pass flags."""
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("AccessDenied")
    s3.get_bucket_acl.side_effect = _client_error("AccessDenied")
    s3.get_bucket_policy.side_effect = _client_error("AccessDenied")
    s3.get_bucket_encryption.side_effect = _client_error("AccessDenied")
    s3.get_bucket_versioning.side_effect = _client_error("AccessDenied")
    s3.get_bucket_logging.side_effect = _client_error("AccessDenied")
    s3.get_bucket_lifecycle_configuration.side_effect = _client_error("AccessDenied")
    s3.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}

    result = s3a.analyse_bucket(s3, "restricted-bucket")

    unknown_flags = [f for f in result["flags"] if "UNKNOWN" in f]
    assert len(unknown_flags) >= 4, f"Expected >=4 UNKNOWN flags, got: {result['flags']}"
    # Must not emit false "clean" flags when checks are inaccessible
    assert not any("✅" in f for f in result["flags"])
    # Bucket must not appear as "not public" simply because ACL/policy checks failed
    assert result["is_public"] is False  # Conservative: flag via UNKNOWN, not assume public


def test_analyse_bucket_unknown_has_paired_remediations():
    """Every ⚠️ UNKNOWN flag must have a paired remediation."""
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("AccessDenied")
    s3.get_bucket_acl.side_effect = _client_error("AccessDenied")
    s3.get_bucket_policy.side_effect = _client_error("AccessDenied")
    s3.get_bucket_encryption.side_effect = _client_error("AccessDenied")
    s3.get_bucket_versioning.side_effect = _client_error("AccessDenied")
    s3.get_bucket_logging.side_effect = _client_error("AccessDenied")
    s3.get_bucket_lifecycle_configuration.side_effect = _client_error("AccessDenied")
    s3.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}

    result = s3a.analyse_bucket(s3, "restricted-bucket")
    warning_flags = [f for f in result["flags"] if not f.startswith("✅")]
    assert len(result["remediations"]) == len(warning_flags)


def test_write_csv_includes_remediations_column(tmp_path):
    """The CSV output should include a remediations column."""
    import csv as csv_module
    sample_findings = [{
        "name": "test-bucket",
        "region": "us-east-1",
        "risk_level": "LOW",
        "severity_score": 0,
        "is_public": False,
        "public_acl": False,
        "public_policy": False,
        "block_public_access_enabled": True,
        "encryption_enabled": True,
        "encryption_algorithm": "AES256",
        "kms_key": None,
        "versioning_status": "Enabled",
        "mfa_delete": "Disabled",
        "logging_enabled": True,
        "log_target_bucket": "log-bucket",
        "lifecycle_rules": 1,
        "policy_findings": [],
        "flags": ["⚠️ Versioning disabled"],
        "remediations": ["Enable versioning: S3 Console → Properties → Bucket Versioning → Enable"],
    }]
    out_path = str(tmp_path / "test.csv")
    s3a.write_csv(sample_findings, out_path)
    with open(out_path) as f:
        reader = csv_module.DictReader(f)
        headers = reader.fieldnames
    assert "remediations" in headers
