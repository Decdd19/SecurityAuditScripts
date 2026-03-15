"""Tests for cloudtrail_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
import cloudtrail_auditor as ct


def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_not_logging_is_critical():
    score, level = ct.calculate_score(True, False, False, False, False, False, False)
    assert score >= 5
    assert level in ("HIGH", "CRITICAL")


def test_score_s3_public_adds_points():
    score_without, _ = ct.calculate_score(False, False, False, False, False, False, False)
    score_with, _ = ct.calculate_score(False, False, False, False, False, False, True)
    assert score_with > score_without


def test_score_all_good():
    score, level = ct.calculate_score(False, False, False, False, False, False, False)
    assert score == 0
    assert level == "LOW"


# ── check_s3_bucket_public ─────────────────────────────────────────────────────

def test_check_s3_bucket_not_public():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }}
    assert ct.check_s3_bucket_public(s3, "my-bucket") is False


def test_check_s3_bucket_public_partial_block():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }}
    assert ct.check_s3_bucket_public(s3, "my-bucket") is True


def test_check_s3_bucket_api_error_returns_false():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("AccessDenied")
    assert ct.check_s3_bucket_public(s3, "my-bucket") is False


# ── check_event_selectors ──────────────────────────────────────────────────────

def test_check_event_selectors_basic():
    mock_ct = MagicMock()
    mock_ct.get_event_selectors.return_value = {
        "EventSelectors": [{"IncludeManagementEvents": True, "DataResources": [], "ReadWriteType": "All"}],
        "AdvancedEventSelectors": [],
    }
    has_mgmt, has_data, rw = ct.check_event_selectors(mock_ct, "arn:aws:cloudtrail:us-east-1:123:trail/test")
    assert has_mgmt is True
    assert has_data is False
    assert rw == "All"


def test_check_event_selectors_advanced():
    mock_ct = MagicMock()
    mock_ct.get_event_selectors.return_value = {
        "EventSelectors": [],
        "AdvancedEventSelectors": [
            {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}
        ],
    }
    has_mgmt, has_data, rw = ct.check_event_selectors(mock_ct, "arn:aws:cloudtrail:us-east-1:123:trail/test")
    assert has_mgmt is True


def test_check_event_selectors_error():
    mock_ct = MagicMock()
    mock_ct.get_event_selectors.side_effect = _client_error("TrailNotFoundException")
    has_mgmt, has_data, rw = ct.check_event_selectors(mock_ct, "bad-arn")
    assert has_mgmt is False
    assert rw == "Unknown"


# ── check_trail_logging ────────────────────────────────────────────────────────

def test_check_trail_logging_active():
    mock_ct = MagicMock()
    mock_ct.get_trail_status.return_value = {"IsLogging": True}
    is_logging, last_delivery, delivery_error = ct.check_trail_logging(mock_ct, "arn:aws:cloudtrail:us-east-1:123:trail/prod")
    assert is_logging is True


def test_check_trail_logging_stopped():
    mock_ct = MagicMock()
    mock_ct.get_trail_status.return_value = {"IsLogging": False}
    is_logging, last_delivery, delivery_error = ct.check_trail_logging(mock_ct, "arn:aws:cloudtrail:us-east-1:123:trail/prod")
    assert is_logging is False


def test_check_trail_logging_api_error():
    mock_ct = MagicMock()
    mock_ct.get_trail_status.side_effect = _client_error("TrailNotFoundException")
    is_logging, last_delivery, delivery_error = ct.check_trail_logging(mock_ct, "bad-arn")
    assert is_logging is False
    assert last_delivery is None
    assert delivery_error is None


# ── analyse_trail ──────────────────────────────────────────────────────────────

FULLY_CONFIGURED_TRAIL = {
    "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/prod",
    "Name": "prod",
    "HomeRegion": "us-east-1",
    "IsMultiRegionTrail": True,
    "IncludeGlobalServiceEvents": True,
    "LogFileValidationEnabled": True,
    "KMSKeyId": "arn:aws:kms:us-east-1:123:key/abc",
    "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123:log-group/ct",
    "S3BucketName": "my-logs-bucket",
    "HasCustomEventSelectors": True,
}


def _make_ct_client(is_logging=True, delivery_error=None):
    mock_ct = MagicMock()
    mock_ct.get_trail_status.return_value = {
        "IsLogging": is_logging,
        "LatestDeliveryError": delivery_error,
    }
    mock_ct.get_event_selectors.return_value = {
        "EventSelectors": [
            {"IncludeManagementEvents": True, "DataResources": [], "ReadWriteType": "All"}
        ],
        "AdvancedEventSelectors": [],
    }
    return mock_ct


def _make_s3_client(is_public=False):
    s3 = MagicMock()
    if is_public:
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }}
    else:
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }}
    return s3


def test_analyse_trail_fully_logging():
    mock_ct = _make_ct_client(is_logging=True)
    s3 = _make_s3_client(is_public=False)
    result = ct.analyse_trail(mock_ct, s3, FULLY_CONFIGURED_TRAIL)

    assert result["risk_level"] == "LOW"
    assert result["is_logging"] is True
    assert result["kms_encrypted"] is True
    assert result["cloudwatch_logs"] is True
    assert result["log_file_validation"] is True
    assert result["is_multi_region"] is True
    assert result["s3_bucket_public"] is False
    # No critical/warning flags about KMS or CloudWatch
    flags_text = " ".join(result["flags"])
    assert "Log files not KMS encrypted" not in flags_text
    assert "No CloudWatch Logs integration" not in flags_text


def test_analyse_trail_missing_kms_and_cloudwatch():
    trail = FULLY_CONFIGURED_TRAIL.copy()
    del trail["KMSKeyId"]
    del trail["CloudWatchLogsLogGroupArn"]

    mock_ct = _make_ct_client(is_logging=True)
    s3 = _make_s3_client(is_public=False)
    result = ct.analyse_trail(mock_ct, s3, trail)

    assert result["kms_encrypted"] is False
    assert result["cloudwatch_logs"] is False
    flags_text = " ".join(result["flags"])
    assert "Log files not KMS encrypted" in flags_text
    assert "No CloudWatch Logs integration" in flags_text


# ── check_region_coverage ──────────────────────────────────────────────────────

def test_check_region_coverage_region_with_trail():
    """A region where describe_trails returns a non-empty list should NOT be in uncovered."""
    session = MagicMock()
    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {"trailList": [{"Name": "prod"}]}
    session.client.return_value = mock_ct

    uncovered = ct.check_region_coverage(session)
    assert len(uncovered) == 0


def test_check_region_coverage_region_without_trail():
    """A region where describe_trails returns empty list should appear in uncovered."""
    session = MagicMock()
    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {"trailList": []}
    session.client.return_value = mock_ct

    uncovered = ct.check_region_coverage(session)
    # All regions return empty trailList, so all should be uncovered
    assert len(uncovered) == len(ct.ALL_REGIONS)
    assert "us-east-1" in uncovered


def test_check_region_coverage_api_error_not_uncovered():
    """A region where the API raises a ClientError should NOT be counted as uncovered.
    API errors (e.g. opt-in regions not enabled) should be skipped to avoid false positives."""
    session = MagicMock()
    mock_ct = MagicMock()
    mock_ct.describe_trails.side_effect = _client_error("AccessDenied")
    session.client.return_value = mock_ct

    # The function should skip regions with API errors rather than flagging them uncovered
    uncovered = ct.check_region_coverage(session)
    assert isinstance(uncovered, list)
    # All regions errored, so none should be in uncovered
    assert len(uncovered) == 0
    assert "us-east-1" not in uncovered


# ── write_json / write_csv permissions ────────────────────────────────────────

def test_write_json_creates_file_with_600_perms(tmp_path):
    path = str(tmp_path / "report.json")
    report = {"generated_at": "2026-01-01", "findings": []}
    ct.write_json(report, path)
    assert os.path.exists(path)
    mode = oct(os.stat(path).st_mode)[-3:]
    assert mode == "600"


def test_write_csv_creates_file_with_600_perms(tmp_path):
    path = str(tmp_path / "report.csv")
    findings = [{
        "name": "prod",
        "arn": "arn:aws:cloudtrail:us-east-1:123:trail/prod",
        "home_region": "us-east-1",
        "risk_level": "LOW",
        "severity_score": 0,
        "is_logging": True,
        "is_multi_region": True,
        "include_global_events": True,
        "log_file_validation": True,
        "kms_encrypted": True,
        "kms_key": "arn:aws:kms:us-east-1:123:key/abc",
        "cloudwatch_logs": True,
        "cloudwatch_group": "arn:aws:logs:us-east-1:123:log-group/ct",
        "s3_bucket": "my-logs-bucket",
        "s3_bucket_public": False,
        "sns_enabled": False,
        "management_events": True,
        "data_events": False,
        "read_write_type": "All",
        "last_delivery": "2026-01-01T00:00:00+00:00",
        "delivery_error": None,
        "flags": ["✅ Log file validation enabled"],
    }]
    ct.write_csv(findings, path)
    assert os.path.exists(path)
    mode = oct(os.stat(path).st_mode)[-3:]
    assert mode == "600"
