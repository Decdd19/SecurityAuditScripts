"""Tests for s3_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../AWS/s3-auditor"))

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
    import json
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    ]})}
    is_public, findings, _ = s3a.check_bucket_policy(s3, "my-bucket")
    assert is_public is True
    assert len(findings) > 0


def test_check_bucket_policy_public_aws_list():
    import json
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "s3:GetObject"}
    ]})}
    is_public, findings, _ = s3a.check_bucket_policy(s3, "my-bucket")
    assert is_public is True


def test_check_bucket_policy_private():
    import json
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
