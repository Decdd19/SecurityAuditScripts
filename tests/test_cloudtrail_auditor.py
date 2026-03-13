"""Tests for cloudtrail_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../AWS/cloudtrail-auditor"))

import pytest
from unittest.mock import MagicMock
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
