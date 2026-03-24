"""Tests for securityhub_auditor.py"""
import sys
import os
import json
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import securityhub_auditor as sh


# ── Helpers ───────────────────────────────────────────────────────────────────

def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": ""}}, "Op")


def _make_sh(enabled=True, critical=0, high=0, medium=0, low=0, standards=None):
    """Build a mock Security Hub client."""
    c = MagicMock()

    if enabled:
        c.describe_hub.return_value = {"HubArn": "arn:aws:securityhub:eu-west-1:123:hub/default"}
    else:
        c.describe_hub.side_effect = _client_error("InvalidAccessException")

    # Findings paginator
    findings_page = []
    for sev, count in [("CRITICAL", critical), ("HIGH", high),
                       ("MEDIUM", medium), ("LOW", low)]:
        for _ in range(count):
            findings_page.append({"Severity": {"Label": sev}})

    paginator_mock = MagicMock()
    paginator_mock.paginate.return_value = [{"Findings": findings_page}]

    standards_paginator = MagicMock()
    std_list = standards or []
    controls_pages = {}
    for s in std_list:
        controls = []
        for _ in range(s.get("passed", 0)):
            controls.append({"ControlStatus": "PASSED"})
        for _ in range(s.get("failed", 0)):
            controls.append({"ControlStatus": "FAILED"})
        controls_pages[s["arn"]] = [{"Controls": controls}]

    def _std_paginator(StandardsSubscriptionArn):
        mock = MagicMock()
        mock.__iter__ = lambda self: iter(controls_pages.get(StandardsSubscriptionArn, [{"Controls": []}]))
        mock.paginate.return_value = controls_pages.get(StandardsSubscriptionArn, [{"Controls": []}])
        return mock

    def _get_paginator(name):
        if name == "get_findings":
            return paginator_mock
        if name == "describe_standards_controls":
            return MagicMock(paginate=lambda **kw: controls_pages.get(
                kw.get("StandardsSubscriptionArn"), [{"Controls": []}]
            ))
        return MagicMock()

    c.get_paginator.side_effect = _get_paginator

    subs = [{"StandardsSubscriptionArn": s["arn"],
             "StandardsArn": f"arn:aws:securityhub:::ruleset/{s['name']}/v/1.0.0"}
            for s in (standards or [])]
    c.get_enabled_standards.return_value = {"StandardsSubscriptions": subs}

    return c


def _make_session(enabled=True, critical=0, high=0, standards=None):
    session = MagicMock()
    session.client.return_value = _make_sh(
        enabled=enabled, critical=critical, high=high, standards=standards
    )
    return session


# ── is_hub_enabled ────────────────────────────────────────────────────────────

def test_is_hub_enabled_true():
    c = MagicMock()
    c.describe_hub.return_value = {}
    assert sh.is_hub_enabled(c) is True


def test_is_hub_enabled_false_invalid_access():
    c = MagicMock()
    c.describe_hub.side_effect = _client_error("InvalidAccessException")
    assert sh.is_hub_enabled(c) is False


def test_is_hub_enabled_false_access_denied():
    c = MagicMock()
    c.describe_hub.side_effect = _client_error("AccessDeniedException")
    assert sh.is_hub_enabled(c) is False


# ── calculate_score ───────────────────────────────────────────────────────────

def test_score_not_enabled():
    score, risk = sh.calculate_score(False, 0, 0, False, 0)
    assert score == 9
    assert risk == "CRITICAL"


def test_score_enabled_no_issues():
    score, risk = sh.calculate_score(True, 0, 0, True, 0)
    assert score == 0
    assert risk == "LOW"


def test_score_critical_findings():
    score, risk = sh.calculate_score(True, 2, 0, True, 0)
    assert score >= 4
    assert risk in ("HIGH", "CRITICAL")


def test_score_no_standards():
    score, risk = sh.calculate_score(True, 0, 0, False, 0)
    assert score == 2
    assert risk == "MEDIUM"


def test_score_capped_at_10():
    score, _ = sh.calculate_score(True, 10, 10, False, 5)
    assert score == 10


# ── build_flags_and_remediations ──────────────────────────────────────────────

def test_flags_not_enabled():
    finding = {
        "enabled": False, "critical_findings": 0, "high_findings": 0,
        "standards_enabled": False, "standards_with_low_pass_rate": 0, "standards": [],
    }
    flags, rems = sh.build_flags_and_remediations(finding)
    assert any("not enabled" in f.lower() for f in flags)
    assert len(flags) == len(rems)


def test_flags_critical_findings():
    finding = {
        "enabled": True, "critical_findings": 3, "high_findings": 0,
        "standards_enabled": True, "standards_with_low_pass_rate": 0, "standards": [],
    }
    flags, rems = sh.build_flags_and_remediations(finding)
    assert any("CRITICAL" in f for f in flags)
    assert len(flags) == len(rems)


def test_flags_no_standards():
    finding = {
        "enabled": True, "critical_findings": 0, "high_findings": 0,
        "standards_enabled": False, "standards_with_low_pass_rate": 0, "standards": [],
    }
    flags, rems = sh.build_flags_and_remediations(finding)
    assert any("standard" in f.lower() for f in flags)
    assert len(flags) == len(rems)


def test_flags_low_pass_rate_uses_info_prefix():
    finding = {
        "enabled": True, "critical_findings": 0, "high_findings": 0,
        "standards_enabled": True, "standards_with_low_pass_rate": 1,
        "standards": [{"name": "cis-aws-foundations-benchmark", "pass_rate": 35.0, "passed": 35, "failed": 65}],
    }
    flags, rems = sh.build_flags_and_remediations(finding)
    assert any(f.startswith("ℹ️") and "pass rate" in f.lower() for f in flags)
    assert len(flags) == len(rems)


def test_flags_clean_has_positive_flag():
    finding = {
        "enabled": True, "critical_findings": 0, "high_findings": 0,
        "standards_enabled": True, "standards_with_low_pass_rate": 0, "standards": [],
    }
    flags, rems = sh.build_flags_and_remediations(finding)
    assert any("✅" in f for f in flags)
    assert len(flags) == len(rems)


# ── audit_region ──────────────────────────────────────────────────────────────

def test_audit_region_not_enabled_is_critical():
    c = _make_sh(enabled=False)
    session = MagicMock()
    session.client.return_value = c
    result = sh.audit_region(session, "eu-west-1")
    assert result["enabled"] is False
    assert result["risk_level"] == "CRITICAL"
    assert result["severity_score"] == 9


def test_audit_region_clean_is_low():
    # Enabled + at least one standard + no findings → LOW
    c = _make_sh(enabled=True, critical=0, high=0,
                 standards=[{"arn": "arn:aws:securityhub:::ruleset/cis/v/1.2.0",
                              "name": "cis", "passed": 80, "failed": 5}])
    session = MagicMock()
    session.client.return_value = c
    result = sh.audit_region(session, "eu-west-1")
    assert result["enabled"] is True
    assert result["risk_level"] == "LOW"


def test_audit_region_has_required_keys():
    c = _make_sh(enabled=True)
    session = MagicMock()
    session.client.return_value = c
    result = sh.audit_region(session, "us-east-1")
    for key in ["region", "enabled", "critical_findings", "high_findings",
                "risk_level", "severity_score", "flags", "remediations"]:
        assert key in result


def test_audit_region_flags_rems_same_length():
    c = _make_sh(enabled=True, critical=2, high=3)
    session = MagicMock()
    session.client.return_value = c
    result = sh.audit_region(session, "eu-west-1")
    assert len(result["flags"]) == len(result["remediations"])


# ── Output formatters ─────────────────────────────────────────────────────────

def _sample_report():
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "summary": {"total_regions": 1, "not_enabled": 0,
                    "critical": 0, "high": 0, "medium": 0, "low": 1},
        "findings": [{
            "region": "eu-west-1", "enabled": True,
            "critical_findings": 0, "high_findings": 0,
            "medium_findings": 0, "low_findings": 0,
            "standards_enabled": True, "standards_with_low_pass_rate": 0,
            "standards": [], "risk_level": "LOW", "severity_score": 0,
            "flags": ["✅ Security Hub enabled, no critical/high findings"],
            "remediations": [""],
        }],
    }


def test_write_json_creates_valid_json(tmp_path):
    path = str(tmp_path / "report.json")
    sh.write_json(_sample_report(), path)
    data = json.loads(open(path).read())
    assert data["findings"][0]["region"] == "eu-west-1"


def test_write_json_600_permissions(tmp_path):
    path = str(tmp_path / "report.json")
    sh.write_json(_sample_report(), path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_write_csv_creates_file(tmp_path):
    path = str(tmp_path / "report.csv")
    sh.write_csv(_sample_report()["findings"], path)
    assert "eu-west-1" in open(path).read()


def test_write_csv_600_permissions(tmp_path):
    path = str(tmp_path / "report.csv")
    sh.write_csv(_sample_report()["findings"], path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_write_html_creates_file(tmp_path):
    path = str(tmp_path / "report.html")
    sh.write_html(_sample_report(), path)
    content = open(path).read()
    assert "eu-west-1" in content
    assert "Security Hub" in content


def test_write_html_600_permissions(tmp_path):
    path = str(tmp_path / "report.html")
    sh.write_html(_sample_report(), path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"
