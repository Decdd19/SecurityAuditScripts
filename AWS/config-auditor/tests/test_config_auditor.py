"""Tests for config_auditor.py"""
import sys
import os
import json
import stat
import tempfile
import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config_auditor as ca


# -- Helpers -------------------------------------------------------------------

def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


def _make_config_client(
    recorders=None,
    channels=None,
    recorder_status=None,
    rules=None,
    non_compliant=None,
):
    """Return a mocked Config client with configurable responses."""
    client = MagicMock()

    if recorders is None:
        recorders = [{
            "name": "default",
            "recordingGroup": {"allSupported": True},
        }]
    client.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": recorders
    }

    if channels is None:
        channels = [{"name": "default", "s3BucketName": "my-bucket"}]
    client.describe_delivery_channels.return_value = {
        "DeliveryChannels": channels
    }

    if recorder_status is None:
        recorder_status = [{"name": "default", "recording": True, "lastStatus": "SUCCESS"}]
    client.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": recorder_status
    }

    if rules is None:
        rules = [{"ConfigRuleName": "s3-bucket-public-read-prohibited"}]
    client.describe_config_rules.return_value = {
        "ConfigRules": rules
    }

    if non_compliant is None:
        non_compliant = []
    client.describe_compliance_by_config_rule.return_value = {
        "ComplianceByConfigRules": non_compliant
    }

    return client


# -- Test 1: Recorder not present -> CRITICAL finding -------------------------

def test_recorder_not_present_critical_finding():
    client = _make_config_client(recorders=[])
    findings = ca.check_recorder(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["risk_level"] == "CRITICAL"
    assert "not enabled" in findings[0]["description"].lower()


# -- Test 2: Recorder present and enabled -> no recorder finding ---------------

def test_recorder_present_and_enabled_pass():
    client = _make_config_client(recorders=[{
        "name": "default",
        "recordingGroup": {"allSupported": True},
    }])
    findings = ca.check_recorder(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert findings[0]["severity"] == "LOW"


# -- Test 3: No delivery channel -> HIGH finding ------------------------------

def test_no_delivery_channel_high_finding():
    client = _make_config_client(channels=[])
    findings = ca.check_delivery_channel(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "HIGH"
    assert "delivery channel" in findings[0]["description"].lower()


# -- Test 4: Delivery channel present -> no channel finding --------------------

def test_delivery_channel_present_pass():
    client = _make_config_client(channels=[{"name": "default", "s3BucketName": "bucket"}])
    findings = ca.check_delivery_channel(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"


# -- Test 5: Recorder status failure -> HIGH finding ---------------------------

def test_recorder_status_failure_high_finding():
    client = _make_config_client(recorder_status=[{
        "name": "default",
        "recording": False,
        "lastStatus": "Failure",
    }])
    findings = ca.check_recorder_status(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "HIGH"


def test_recorder_status_not_recording_high_finding():
    client = _make_config_client(recorder_status=[{
        "name": "default",
        "recording": False,
        "lastStatus": "SUCCESS",
    }])
    findings = ca.check_recorder_status(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "HIGH"


# -- Test 6: No config rules -> HIGH finding ----------------------------------

def test_no_config_rules_high_finding():
    client = _make_config_client(rules=[])
    findings = ca.check_config_rules(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "HIGH"
    assert "no config rules" in findings[0]["description"].lower()


# -- Test 7: Config rules present -> no rules finding -------------------------

def test_config_rules_present_pass():
    client = _make_config_client(rules=[
        {"ConfigRuleName": "rule-1"},
        {"ConfigRuleName": "rule-2"},
    ])
    findings = ca.check_config_rules(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert "2" in findings[0]["description"]


# -- Test 8: Non-compliant rules present -> MEDIUM finding ---------------------

def test_non_compliant_rules_medium_finding():
    client = _make_config_client(non_compliant=[
        {"ConfigRuleName": "rule-1", "Compliance": {"ComplianceType": "NON_COMPLIANT"}},
        {"ConfigRuleName": "rule-2", "Compliance": {"ComplianceType": "NON_COMPLIANT"}},
    ])
    findings = ca.check_compliance(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "MEDIUM"
    assert "2" in findings[0]["description"]


# -- Test 9: All compliant -> no compliance finding ----------------------------

def test_all_compliant_pass():
    client = _make_config_client(non_compliant=[])
    findings = ca.check_compliance(client, "us-east-1")
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"
    assert "compliant" in findings[0]["description"].lower()


# -- Test 10: AccessDeniedException handled gracefully -------------------------

def test_access_denied_handled_gracefully():
    """AccessDeniedException in a region should skip that region without crashing."""
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

    mock_config = MagicMock()
    mock_config.describe_configuration_recorders.side_effect = _client_error("AccessDeniedException")

    def client_side_effect(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "config":
            return mock_config
        return MagicMock()

    mock_session.client.side_effect = client_side_effect

    with patch("boto3.Session", return_value=mock_session):
        report = ca.run(output_prefix="/dev/null", fmt="stdout", regions=["us-east-1"])

    # Should not crash and should return a valid report
    assert "findings" in report
    assert "summary" in report
    # Region was skipped so no findings
    assert len(report["findings"]) == 0


# -- Test 11: run() with fmt="stdout" returns without error --------------------

def test_run_stdout_returns_report():
    """Mock all boto3 calls and verify run() returns a valid report."""
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

    mock_config = _make_config_client()

    def client_side_effect(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "config":
            return mock_config
        return MagicMock()

    mock_session.client.side_effect = client_side_effect

    with patch("boto3.Session", return_value=mock_session):
        report = ca.run(output_prefix="/dev/null", fmt="stdout", regions=["us-east-1"])

    assert "generated_at" in report
    assert "account_id" in report
    assert "summary" in report
    assert "findings" in report
    assert report["account_id"] == "123456789012"
    assert report["summary"]["regions_scanned"] == 1
    assert report["summary"]["total_findings"] > 0


# -- Test 12: Findings have cis_control field present -------------------------

def test_findings_have_cis_control_field():
    """Every finding produced by every check function must include cis_control."""
    client = _make_config_client(
        recorders=[],
        channels=[],
        recorder_status=[{"name": "default", "recording": False, "lastStatus": "Failure"}],
        rules=[],
        non_compliant=[
            {"ConfigRuleName": "r1", "Compliance": {"ComplianceType": "NON_COMPLIANT"}},
        ],
    )
    all_findings = []
    all_findings.extend(ca.check_recorder(client, "us-east-1"))
    all_findings.extend(ca.check_delivery_channel(client, "us-east-1"))
    all_findings.extend(ca.check_recorder_status(client, "us-east-1"))
    all_findings.extend(ca.check_config_rules(client, "us-east-1"))
    all_findings.extend(ca.check_compliance(client, "us-east-1"))

    assert len(all_findings) >= 5
    for finding in all_findings:
        assert "cis_control" in finding, f"Finding missing cis_control: {finding['check']}"
        assert finding["cis_control"] == "CIS 3.5"


# -- Test 13: Finding dict has all required fields ----------------------------

def test_finding_has_all_required_fields():
    """Each finding dict must have all required fields from the spec."""
    required_fields = [
        "region", "resource", "check", "status", "severity",
        "risk_level", "severity_score", "description", "recommendation",
        "cis_control", "remediation", "flags", "remediations",
    ]
    client = _make_config_client(recorders=[])
    findings = ca.check_recorder(client, "us-east-1")
    assert len(findings) == 1
    for field in required_fields:
        assert field in findings[0], f"Missing required field: {field}"
    assert isinstance(findings[0]["flags"], list)
    assert isinstance(findings[0]["remediations"], list)


# -- Test 14: write_json creates file with correct permissions ----------------

def test_write_json_creates_file_with_correct_permissions():
    report = {
        "generated_at": "2024-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "summary": {"total_findings": 0, "regions_scanned": 1,
                     "critical": 0, "high": 0, "medium": 0, "low": 0,
                     "pass_count": 0, "fail_count": 0},
        "findings": [],
    }
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        path = tmp.name
    try:
        ca.write_json(report, path)
        assert os.path.exists(path)
        file_stat = os.stat(path)
        assert stat.S_IMODE(file_stat.st_mode) == 0o600
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["account_id"] == "123456789012"
    finally:
        os.unlink(path)


# -- Test 15: write_csv creates file with correct permissions -----------------

def test_write_csv_creates_file():
    client = _make_config_client(recorders=[])
    findings = ca.check_recorder(client, "us-east-1")
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        path = tmp.name
    try:
        ca.write_csv(findings, path)
        assert os.path.exists(path)
        file_stat = os.stat(path)
        assert stat.S_IMODE(file_stat.st_mode) == 0o600
        with open(path) as f:
            content = f.read()
        assert "region" in content
        assert "us-east-1" in content
    finally:
        os.unlink(path)


def test_write_csv_empty_findings_does_not_create():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        path = tmp.name
    os.unlink(path)
    ca.write_csv([], path)
    assert not os.path.exists(path)
