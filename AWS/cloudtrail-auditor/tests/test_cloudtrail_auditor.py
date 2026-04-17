"""Tests for cloudtrail_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import csv as csv_module
import json
import stat
import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
import cloudtrail_auditor as ct


def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


# ── Fixtures ──────────────────────────────────────────────────────────────────

FULLY_CONFIGURED_TRAIL = {
    "Name": "my-trail",
    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
    "HomeRegion": "us-east-1",
    "IsMultiRegionTrail": True,
    "IncludeGlobalServiceEvents": True,
    "LogFileValidationEnabled": True,
    "KMSKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc123",
    "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrailLogs",
    "S3BucketName": "my-logs-bucket",
    "SnsTopicARN": "arn:aws:sns:us-east-1:123456789012:my-topic",
}


def _make_ct_client(is_logging=True, delivery_error=None):
    mock = MagicMock()
    mock.get_trail_status.return_value = {
        "IsLogging": is_logging,
        "LatestDeliveryTime": None,
        "LatestDeliveryError": delivery_error,
    }
    mock.get_event_selectors.return_value = {
        "EventSelectors": [
            {
                "IncludeManagementEvents": True,
                "DataResources": [],
                "ReadWriteType": "All",
            }
        ],
        "AdvancedEventSelectors": [],
    }
    return mock


def _make_s3_client(is_public=False):
    mock = MagicMock()
    if is_public:
        mock.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }
    else:
        mock.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
    return mock


# ── check_trail_logging ────────────────────────────────────────────────────────

def test_check_trail_logging_returns_true_when_logging():
    mock_ct = _make_ct_client(is_logging=True)
    is_logging, last_delivery, delivery_error = ct.check_trail_logging(mock_ct, "arn:aws:cloudtrail:us-east-1:123:trail/test")
    assert is_logging is True
    assert delivery_error is None


def test_check_trail_logging_returns_false_on_client_error():
    mock_ct = MagicMock()
    mock_ct.get_trail_status.side_effect = _client_error("AccessDenied")
    is_logging, last_delivery, delivery_error = ct.check_trail_logging(mock_ct, "arn:aws:cloudtrail:us-east-1:123:trail/test")
    assert is_logging is False


# ── check_event_selectors ─────────────────────────────────────────────────────

def test_check_event_selectors_management_events():
    mock_ct = _make_ct_client()
    has_management, has_data, read_write = ct.check_event_selectors(mock_ct, "arn:aws:cloudtrail:us-east-1:123:trail/test")
    assert has_management is True
    assert read_write == "All"


def test_check_event_selectors_returns_false_on_error():
    mock_ct = MagicMock()
    mock_ct.get_event_selectors.side_effect = _client_error("AccessDenied")
    has_management, has_data, read_write = ct.check_event_selectors(mock_ct, "arn:aws:cloudtrail:us-east-1:123:trail/test")
    assert has_management is False
    assert has_data is False


# ── check_s3_bucket_public ────────────────────────────────────────────────────

def test_check_s3_bucket_not_public():
    s3 = _make_s3_client(is_public=False)
    assert ct.check_s3_bucket_public(s3, "my-bucket") is False


def test_check_s3_bucket_public():
    s3 = _make_s3_client(is_public=True)
    assert ct.check_s3_bucket_public(s3, "my-bucket") is True


def test_check_s3_bucket_public_client_error_returns_none():
    # AccessDenied / any unexpected error → UNKNOWN (None), not False (which implies "not public")
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("AccessDenied")
    assert ct.check_s3_bucket_public(s3, "my-bucket") is None


# ── analyse_trail ─────────────────────────────────────────────────────────────

def test_analyse_trail_fully_configured_low_risk():
    mock_ct = _make_ct_client(is_logging=True)
    s3 = _make_s3_client(is_public=False)
    result = ct.analyse_trail(mock_ct, s3, FULLY_CONFIGURED_TRAIL)
    assert result["risk_level"] == "LOW"
    assert result["is_logging"] is True
    assert result["kms_encrypted"] is True
    assert result["cloudwatch_logs"] is True
    assert result["log_file_validation"] is True
    assert result["is_multi_region"] is True


def test_analyse_trail_not_logging_raises_score():
    mock_ct = _make_ct_client(is_logging=False)
    s3 = _make_s3_client(is_public=False)
    result = ct.analyse_trail(mock_ct, s3, FULLY_CONFIGURED_TRAIL)
    assert result["is_logging"] is False
    assert result["severity_score"] >= 5
    assert any("NOT actively logging" in f for f in result["flags"])


def test_analyse_trail_s3_public_flags_correctly():
    mock_ct = _make_ct_client(is_logging=True)
    s3 = _make_s3_client(is_public=True)
    result = ct.analyse_trail(mock_ct, s3, FULLY_CONFIGURED_TRAIL)
    assert result["s3_bucket_public"] is True
    assert any("publicly accessible" in f for f in result["flags"])


def test_analyse_trail_returns_remediations_key():
    mock_ct = _make_ct_client(is_logging=True)
    s3 = _make_s3_client(is_public=False)
    result = ct.analyse_trail(mock_ct, s3, FULLY_CONFIGURED_TRAIL)
    assert "remediations" in result
    assert isinstance(result["remediations"], list)


# ── calculate_score ───────────────────────────────────────────────────────────

def test_calculate_score_all_good():
    score, level = ct.calculate_score(False, False, False, False, False, False, False)
    assert score == 0
    assert level == "LOW"


def test_calculate_score_not_logging_critical():
    score, level = ct.calculate_score(True, False, False, False, False, False, True)
    assert score >= 8
    assert level == "CRITICAL"


def test_calculate_score_capped_at_10():
    score, level = ct.calculate_score(True, True, True, True, True, True, True)
    assert score <= 10


# ── write_json ────────────────────────────────────────────────────────────────

def test_write_json_creates_file_with_600_perms(tmp_path):
    report = {"generated_at": "2026-01-01", "findings": []}
    out_path = str(tmp_path / "test.json")
    ct.write_json(report, out_path)
    assert (tmp_path / "test.json").exists()
    mode = (tmp_path / "test.json").stat().st_mode & 0o777
    assert mode == 0o600


# ── write_csv ─────────────────────────────────────────────────────────────────

def test_write_csv_creates_file_with_600_perms(tmp_path):
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
        "remediations": [],
    }]
    out_path = str(tmp_path / "test.csv")
    ct.write_csv(findings, out_path)
    assert (tmp_path / "test.csv").exists()
    mode = (tmp_path / "test.csv").stat().st_mode & 0o777
    assert mode == 0o600


def test_write_csv_empty_findings_no_file(tmp_path):
    out_path = str(tmp_path / "empty.csv")
    ct.write_csv([], out_path)
    assert not (tmp_path / "empty.csv").exists()


# ── write_html ────────────────────────────────────────────────────────────────

def test_write_html_creates_file_with_600_perms(tmp_path):
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "findings": [],
        "summary": {
            "total_trails": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "trails_not_logging": 0,
            "uncovered_regions": 0,
            "no_kms": 0,
            "no_cloudwatch": 0,
            "regions_checked": 18,
        },
        "uncovered_regions": [],
    }
    out_path = str(tmp_path / "test.html")
    ct.write_html(report, out_path)
    assert (tmp_path / "test.html").exists()
    mode = (tmp_path / "test.html").stat().st_mode & 0o777
    assert mode == 0o600


# ── Remediation tests ─────────────────────────────────────────────────────────

def test_analyse_trail_flagged_has_remediations():
    """Each non-✅ flag should have a paired remediation."""
    # A trail with missing KMS and CloudWatch will have ⚠️ flags
    trail = FULLY_CONFIGURED_TRAIL.copy()
    del trail["KMSKeyId"]
    del trail["CloudWatchLogsLogGroupArn"]

    mock_ct = _make_ct_client(is_logging=True)
    s3 = _make_s3_client(is_public=False)
    result = ct.analyse_trail(mock_ct, s3, trail)

    assert "remediations" in result
    warning_flags = [f for f in result["flags"] if not f.startswith("✅")]
    assert len(result["remediations"]) == len(warning_flags)
    assert all(len(r) > 0 for r in result["remediations"])


def test_write_csv_includes_remediations_column(tmp_path):
    """The CSV output should include a remediations column."""
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
        "remediations": [],
    }]
    path = str(tmp_path / "test.csv")
    ct.write_csv(findings, path)
    with open(path) as f:
        reader = csv_module.DictReader(f)
        headers = reader.fieldnames
    assert "remediations" in headers


# ── UNKNOWN behaviour (AccessDenied → None sentinel) ──────────────────────────

def test_check_s3_bucket_public_access_denied_returns_none():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("AccessDenied")
    assert ct.check_s3_bucket_public(s3, "trail-bucket") is None


def test_analyse_trail_s3_bucket_access_denied_emits_unknown_flag():
    """When S3 public check returns None (AccessDenied), trail analysis must emit UNKNOWN flag."""
    mock_ct = _make_ct_client(is_logging=True)
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("AccessDenied")

    result = ct.analyse_trail(mock_ct, s3, FULLY_CONFIGURED_TRAIL)

    unknown_flags = [f for f in result["flags"] if "UNKNOWN" in f]
    assert len(unknown_flags) >= 1
    # Must NOT claim the bucket is publicly accessible (false negative avoided separately)
    assert not any("publicly accessible!" in f for f in result["flags"])


def test_analyse_trail_s3_bucket_access_denied_has_remediation():
    """UNKNOWN flag for S3 bucket must include a paired remediation."""
    mock_ct = _make_ct_client(is_logging=True)
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("AccessDenied")

    result = ct.analyse_trail(mock_ct, s3, FULLY_CONFIGURED_TRAIL)
    warning_flags = [f for f in result["flags"] if not f.startswith("✅")]
    assert len(result["remediations"]) == len(warning_flags)
